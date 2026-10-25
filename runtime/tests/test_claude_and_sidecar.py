"""The real-API path without the network, and the sidecar error mapping (CONTRACT.md §4.3, §9)."""

import asyncio
import time
from types import SimpleNamespace

import grpc
import pytest

from agentsc_runtime import models
from agentsc_runtime.agent import _now, run_agent
from agentsc_runtime.models import MockModel, ModelError, ModelResponse, supports_effort
from agentsc_runtime.pb.agentsc.v1alpha1 import common_pb2
from agentsc_runtime.sidecar import AGENT_TIMEOUT, SERVICE_TIMEOUT, GrpcSidecar
from agentsc_runtime.tools import HOP_MARGIN, CallContext, ToolDenied, ToolFailed, timeout_for


class FakeStream:
    def __init__(self, recorder, kwargs):
        self.recorder, self.kwargs = recorder, kwargs

    def __enter__(self):
        self.recorder.append(self.kwargs)
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        return iter(())

    def get_final_message(self):
        block = SimpleNamespace(model_dump=lambda exclude_none=True: {"type": "text", "text": "hi"})
        return SimpleNamespace(
            content=[block], stop_reason="end_turn", usage=SimpleNamespace(input_tokens=10, output_tokens=2)
        )


def test_anthropic_model_streams_and_sends_effort_only_where_supported(monkeypatch):
    calls = []
    m = models.AnthropicModel.__new__(models.AnthropicModel)
    m.name = "claude-opus-5-5"
    m._client = SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: FakeStream(calls, kw)))
    resp = m.complete("sys", [{"role": "user", "content": "x"}], [], 64000)
    assert resp.text() == "hi" and resp.input_tokens == 10
    assert calls[0]["max_tokens"] == 64000 and calls[0]["output_config"] == {"effort": "low"}
    assert "timeout" not in calls[0], "no deadline: the SDK's own timeout"
    m.name = "claude-haiku-4-5"
    m.complete("sys", [{"role": "user", "content": "x"}], [], 512)
    assert "output_config" not in calls[1]
    assert supports_effort("claude-sonnet-5-5") and supports_effort("claude-fable-5-1")
    assert not supports_effort("claude-sonnet-4-5")


def test_anthropic_model_reports_the_usage_of_a_stream_that_broke():
    class Broken(FakeStream):
        current_message_snapshot = SimpleNamespace(usage=SimpleNamespace(input_tokens=900, output_tokens=1))

        def get_final_message(self):
            raise ConnectionError("stream reset")

    class Refused(FakeStream):
        def __enter__(self):
            raise ConnectionError("overloaded")

    calls = []
    m = models.AnthropicModel.__new__(models.AnthropicModel)
    m.name = "claude-opus-5-5"
    m._client = SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: Broken(calls, kw)))
    with pytest.raises(ModelError) as info:
        m.complete("sys", [{"role": "user", "content": "x"}], [], 512, timeout=12.5)
    assert calls[0]["timeout"] == 12.5
    assert isinstance(info.value.cause, ConnectionError) and str(info.value) == "stream reset"
    assert (info.value.input_tokens, info.value.output_tokens) == (900, 1), "billed from message_start on"
    m._client = SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: Refused(calls, kw)))
    with pytest.raises(ModelError) as info:
        m.complete("sys", [{"role": "user", "content": "x"}], [], 512)
    assert (info.value.input_tokens, info.value.output_tokens) == (0, 0), "no message_start: nothing billed"


def test_max_tokens_without_text_is_an_error_not_an_empty_answer(ops_assistant, sidecar, ctx):
    class Truncating(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            return ModelResponse([{"type": "thinking", "thinking": "", "signature": "s"}], "max_tokens", 50, max_tokens)

    res = asyncio.run(run_agent(ops_assistant, "stock?", "", ctx, Truncating(), sidecar))
    assert res.status == "error" and res.rule == "budget.max_tokens_per_call"

    class TruncatedToolCall(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            return ModelResponse(
                [{"type": "tool_use", "id": "t", "name": "stock_analyst", "input": {}}], "max_tokens", 5, 5
            )

    res = asyncio.run(run_agent(ops_assistant, "stock?", "", ctx, TruncatedToolCall(), sidecar))
    assert res.status == "error" and sidecar.calls == [], "a cut-off tool call must not run"

    class TruncatedText(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            return ModelResponse([{"type": "text", "text": "partial answ"}], "max_tokens", 5, 5)

    res = asyncio.run(run_agent(ops_assistant, "stock?", "", ctx, TruncatedText(), sidecar))
    assert res.status == "ok" and res.output == "partial answ"


def test_timestamp_format():
    ts = _now()
    assert len(ts) == 24 and ts.endswith("Z") and ts[19] == "."


def rpc_error(code, rule=None, details="x"):
    md = grpc.aio.Metadata(("x-agentsc-rule", rule)) if rule else grpc.aio.Metadata()
    return grpc.aio.AioRpcError(code, grpc.aio.Metadata(), md, details=details)


@pytest.mark.parametrize(
    "code,rule,expected",
    [
        (grpc.StatusCode.PERMISSION_DENIED, "authz.services.deny-admin", ToolDenied),
        (grpc.StatusCode.RESOURCE_EXHAUSTED, "budget.max_calls_per_minute", ToolDenied),
        (grpc.StatusCode.RESOURCE_EXHAUSTED, None, ToolFailed),  # gRPC message-size limit, not policy
        (grpc.StatusCode.UNAVAILABLE, "mesh.unavailable", ToolFailed),
        (grpc.StatusCode.NOT_FOUND, "agent.unknown", ToolFailed),
    ],
)
def test_sidecar_status_mapping(code, rule, expected):
    sc = GrpcSidecar.__new__(GrpcSidecar)

    async def fail():
        raise rpc_error(code, rule)

    with pytest.raises(expected) as info:
        asyncio.run(sc._call(fail()))
    if expected is ToolDenied:
        assert info.value.rule == rule


def test_tool_calls_fit_inside_the_execute_deadline(ops_assistant, sidecar, ctx):
    """A tool call never outlives the Execute it belongs to (CONTRACT.md §4.3)."""
    seen = {}

    class Stub:
        def InvokeAgent(self, req, timeout):
            seen["timeout"] = timeout

            async def ok():
                return common_pb2.InvokeAgentResponse(status="ok", output="fine")

            return ok()

    sc = GrpcSidecar.__new__(GrpcSidecar)
    sc._stub = Stub()
    call = CallContext("r", "t", "s", "ops-assistant", 0)
    assert asyncio.run(sc.invoke_agent(call, "stock_analyst", "inventory", "stock-analyst", "hi")) == "fine"
    assert seen["timeout"] == AGENT_TIMEOUT, "no deadline: the static bound"
    call.deadline = time.monotonic() + 10
    asyncio.run(sc.invoke_agent(call, "stock_analyst", "inventory", "stock-analyst", "hi"))
    assert 9 < seen["timeout"] <= 10 - HOP_MARGIN
    call.deadline = time.monotonic() - 1
    assert timeout_for(call, SERVICE_TIMEOUT) == 0.0

    # the agent loop hands the deadline to every tool call it makes
    deadlines = []
    invoke_agent = sidecar.invoke_agent

    async def spy(c, *args):
        deadlines.append(c.deadline)
        return await invoke_agent(c, *args)

    sidecar.invoke_agent = spy
    ctx.deadline = time.monotonic() + 60
    res = asyncio.run(
        run_agent(ops_assistant, "WIDGET-1 stock levels and reorder advice?", "", ctx, MockModel(), sidecar)
    )
    assert res.status == "ok" and deadlines == [ctx.deadline]


def test_model_calls_fit_inside_the_execute_deadline(ops_assistant, sidecar, ctx):
    """A model call gets what is left of the deadline, and none starts once it is (nearly) up."""
    timeouts = []

    class Timed(MockModel):
        def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
            timeouts.append(timeout)
            return super().complete(system, messages, tools, max_tokens)

    ctx.deadline = time.monotonic() + 60
    res = asyncio.run(run_agent(ops_assistant, "WIDGET-1 stock levels?", "", ctx, Timed(), sidecar))
    assert res.status == "ok" and len(timeouts) == 2
    assert all(55 < t <= 60 - HOP_MARGIN for t in timeouts)

    ctx.deadline = time.monotonic() + HOP_MARGIN / 2
    sidecar.events.clear()
    res = asyncio.run(run_agent(ops_assistant, "WIDGET-1 stock levels?", "", ctx, Timed(), sidecar))
    assert res.status == "error" and res.rule == "deadline.exceeded"
    assert len(timeouts) == 2 and res.steps == [] and sidecar.events == [], "no model call was started"
