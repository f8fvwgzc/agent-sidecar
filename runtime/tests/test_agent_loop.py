import asyncio
import threading

import pytest

from agentsc_runtime.agent import run_agent
from agentsc_runtime.models import MockModel, ModelError, ModelResponse


def run(coro):
    return asyncio.run(coro)


def test_orchestrator_calls_remote_agent_and_reports_model_calls(ops_assistant, sidecar, ctx):
    res = run(
        run_agent(
            ops_assistant, "How many WIDGET-1 do we have in stock and should we reorder?", "", ctx, MockModel(), sidecar
        )
    )
    assert res.status == "ok"
    assert "stock-analyst says" in res.output
    kinds = [s.kind for s in res.steps]
    assert kinds == ["model_call", "agent_call", "model_call"]
    assert res.steps[1].name == "inventory/stock-analyst"
    assert sidecar.calls[0][0] == "agent"
    assert sidecar.calls[0][1][1:3] == ("inventory", "stock-analyst")
    assert len(sidecar.events) == 2
    ev = sidecar.events[0]
    assert ev["kind"] == "model_call" and ev["agent"] == "ops-assistant" and ev["callee"] == "mock"
    assert ev["request_id"] == "req-1" and ev["trace_id"] == ctx.trace_id and ev["parent_span_id"] == ctx.span_id
    assert ev["tokens"]["input"] > 0 and ev["cost_usd"] == 0.0
    assert ev["input"]["tools"] == ["lookup_order", "stock_analyst", "inventory_admin_reset"]
    assert res.input_tokens == sum(e["tokens"]["input"] for e in sidecar.events)


def test_denied_tool_call_is_returned_to_the_model_not_raised(ops_assistant, sidecar, ctx):
    res = run(run_agent(ops_assistant, "Reset the inventory admin counters", "", ctx, MockModel(), sidecar))
    assert res.status == "ok"
    denied = [s for s in res.steps if s.decision == "deny"]
    assert len(denied) == 1
    assert denied[0].kind == "service_call"
    assert denied[0].name == "inventory POST /admin/reset"
    assert denied[0].rule == "authz.services.deny-admin"
    assert "denied by authz.services.deny-admin" in res.output


def test_service_tool_substitutes_path_params(ops_assistant, sidecar, ctx):
    res = run(run_agent(ops_assistant, "Show me order 1001", "", ctx, MockModel(), sidecar))
    assert res.status == "ok"
    assert sidecar.calls[0] == ("service", ("lookup_order", "orders", "GET", "/orders/1001", b""))
    assert '"id": "1001"' in res.output


def test_max_steps_is_enforced(ops_assistant, sidecar, ctx):
    class LoopingModel(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            r = super().complete(system, messages, tools, max_tokens)
            # never finish: keep asking for the stock analyst
            r.content = [{"type": "tool_use", "id": "t", "name": "stock_analyst", "input": {"input": "again"}}]
            r.stop_reason = "tool_use"
            return r

    ops_assistant.budgets.max_steps = 2
    res = run(run_agent(ops_assistant, "stock?", "", ctx, LoopingModel(), sidecar))
    assert res.status == "error"
    assert res.rule == "budget.max_steps"
    assert len([s for s in res.steps if s.kind == "model_call"]) == 2


def test_refusal_becomes_denied(ops_assistant, sidecar, ctx):
    class RefusingModel(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            r = super().complete(system, messages, tools, max_tokens)
            r.content, r.stop_reason = [], "refusal"
            return r

    res = run(run_agent(ops_assistant, "anything", "", ctx, RefusingModel(), sidecar))
    assert res.status == "denied" and res.rule == "model.refusal"
    assert sidecar.events[0]["decision"] == "deny" and sidecar.events[0]["rule"] == "model.refusal"


def test_context_is_appended_to_the_first_message(ops_assistant, sidecar, ctx):
    captured = {}

    class Spy(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            captured["first"] = messages[0]["content"]
            r = super().complete(system, messages, tools, max_tokens)
            r.content, r.stop_reason = [{"type": "text", "text": "ok"}], "end_turn"
            return r

    run(run_agent(ops_assistant, "hi", '{"customer": "c-1"}', ctx, Spy(), sidecar))
    assert captured["first"].startswith("hi\n\n<context>")


def test_a_model_call_in_flight_when_execute_is_cancelled_is_still_reported(ops_assistant, sidecar, ctx):
    """A call nobody waits for any more still finishes and is reported (§9): the provider bills it.
    For a provider the gateway does the same on its side; here the mock reports its own record."""
    started, release = threading.Event(), threading.Event()

    class Slow(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            started.set()
            release.wait(5)
            return ModelResponse([{"type": "text", "text": "too late"}], "end_turn", 1200, 345)

    async def cancel_mid_call():
        reported = asyncio.Event()
        report = sidecar.report_event

        async def spy(record):
            await report(record)
            reported.set()

        sidecar.report_event = spy
        execute = asyncio.create_task(run_agent(ops_assistant, "stock?", "", ctx, Slow("claude-opus-5-5"), sidecar))
        assert await asyncio.to_thread(started.wait, 5)
        execute.cancel()  # what grpc.aio does to the handler when the sidecar gives up on Execute
        with pytest.raises(asyncio.CancelledError):
            await execute
        assert sidecar.events == [], "the model call is still running"
        release.set()
        await asyncio.wait_for(reported.wait(), 5)

    asyncio.run(cancel_mid_call())
    [ev] = sidecar.events
    assert ev["kind"] == "model_call" and ev["tokens"] == {"input": 1200, "output": 345}
    assert ev["cost_usd"] == 0.0 and ev["callee"] == "mock", "the runtime prices nothing"
    assert ev["output"] == [{"type": "text", "text": "too late"}] and ev["error"].startswith("cancelled: ")


def test_a_failed_model_call_reports_the_usage_it_was_billed_for(ops_assistant, sidecar, ctx):
    class Broken(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            raise ModelError(ConnectionError("stream reset"), 900, 40)

    res = run(run_agent(ops_assistant, "stock?", "", ctx, Broken("claude-opus-5-5"), sidecar))
    assert res.status == "error" and res.rule == "model.error" and res.reason == "ConnectionError: stream reset"
    [ev] = sidecar.events
    assert ev["tokens"] == {"input": 900, "output": 40} and ev["error"] == "stream reset"
    assert (res.input_tokens, res.output_tokens) == (900, 40)
