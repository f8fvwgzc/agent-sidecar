"""The runtime's gRPC server against a fake SidecarTools server, over real gRPC on loopback: the
Execute deadline, tool span ids, the rule on ReportEvent's answer, a sidecar that keeps to design
§6.5, and ProposeLesson on the wire."""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

import grpc
import pytest

from agentsc_runtime.learning import Learner
from agentsc_runtime.models import MockModel
from agentsc_runtime.pb.agentsc.v1alpha1 import common_pb2, runtime_pb2, runtime_pb2_grpc
from agentsc_runtime.prompts import REFLECTION_MARKER
from agentsc_runtime.server import RuntimeServicer
from agentsc_runtime.sidecar import GrpcSidecar
from agentsc_runtime.spec import AgentSpec
from agentsc_runtime.tools import RULE_COST_BUDGET, RULE_REPORT_REJECTED


class FakeTools(runtime_pb2_grpc.SidecarToolsServicer):
    """`report_rule` is named on every ReportEvent answer, the way `report_via` says: `headers` (what
    tonic sends for `Response::metadata`), `trailers`, or an error `status` (RESOURCE_EXHAUSTED)."""

    def __init__(self, report_rule: str | None = None, report_via: str = "headers") -> None:
        self.report_rule, self.report_via = report_rule, report_via
        self.events: list[dict[str, Any]] = []
        self.agent_calls: list[Any] = []
        self.lessons: list[Any] = []
        # Set: ReportEvent keeps to design §6.5 and refuses records of an Execute not in this set.
        self.in_flight: set[str] | None = None
        self.rejected: list[dict[str, Any]] = []

    async def ReportEvent(self, request, context):
        record = json.loads(request.json)
        if self.in_flight is not None and record["request_id"] not in self.in_flight:
            self.rejected.append(record)
            context.set_trailing_metadata((("x-agentsc-rule", RULE_REPORT_REJECTED),))
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"no Execute in flight for {record['request_id']}")
        self.events.append(record)
        if self.report_rule and self.report_via == "headers":
            await context.send_initial_metadata((("x-agentsc-rule", self.report_rule),))
        elif self.report_rule and self.report_via == "trailers":
            context.set_trailing_metadata((("x-agentsc-rule", self.report_rule),))
        elif self.report_rule:
            context.set_trailing_metadata((("x-agentsc-rule", self.report_rule),))
            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "daily cost budget spent")
        return common_pb2.Empty()

    async def InvokeAgent(self, request, context):
        self.agent_calls.append(request)
        return common_pb2.InvokeAgentResponse(status="ok", output="42 on hand")

    async def ProposeLesson(self, request, context):
        self.lessons.append(request)
        return runtime_pb2.LessonResponse(decision="allow", rule="learning.proposed", reason="")


class Held(MockModel):
    """A mock whose reflections wait for `release`, so they start only once the test says the
    Execute has returned (as a real reflection, seconds long, would)."""

    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()

    def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
        if system.startswith(REFLECTION_MARKER):
            assert self.release.wait(5)
        return super().complete(system, messages, tools, max_tokens, timeout)


def request(spec: AgentSpec, request_id: str) -> runtime_pb2.ExecuteRequest:
    return runtime_pb2.ExecuteRequest(
        request_id=request_id,
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_id="00f067aa0ba902b7",
        agent_spec_json=spec.model_dump_json(),
        input="How many WIDGET-1 in stock?",
        caller="local",
    )


async def execute(
    spec: AgentSpec, tools: FakeTools, timeout: float, runs: int = 1, model: MockModel | None = None
) -> tuple[list[Any], Learner]:
    """`runs` Executes, one after the other, each with its reflection (if any) done before the next.
    With `tools.in_flight` set, each request id is in flight exactly while its Execute runs."""
    sidecar_server = grpc.aio.server()
    runtime_pb2_grpc.add_SidecarToolsServicer_to_server(tools, sidecar_server)
    sidecar_port = sidecar_server.add_insecure_port("127.0.0.1:0")
    await sidecar_server.start()
    learner = Learner()
    models = (lambda name: model) if model is not None else (lambda name: MockModel())
    runtime_server = grpc.aio.server()
    runtime_pb2_grpc.add_RuntimeServicer_to_server(
        RuntimeServicer(GrpcSidecar(f"127.0.0.1:{sidecar_port}"), learner=learner, models=models), runtime_server
    )
    runtime_port = runtime_server.add_insecure_port("127.0.0.1:0")
    await runtime_server.start()
    responses = []
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{runtime_port}") as channel:
            for n in range(1, runs + 1):
                request_id = f"req-{n}"
                if tools.in_flight is not None:
                    tools.in_flight.add(request_id)
                resp = await runtime_pb2_grpc.RuntimeStub(channel).Execute(request(spec, request_id), timeout=timeout)
                if tools.in_flight is not None:
                    tools.in_flight.discard(request_id)
                if isinstance(model, Held):
                    model.release.set()
                responses.append(resp)
                await learner.drain()
        return responses, learner
    finally:
        await runtime_server.stop(None)
        await sidecar_server.stop(None)


@pytest.fixture
def spec(ops_assistant) -> AgentSpec:
    ops_assistant.learning.enabled = True
    return ops_assistant


def test_execute_over_grpc_reflects_and_proposes(spec):
    tools = FakeTools()
    [resp], learner = asyncio.run(execute(spec, tools, timeout=20))
    assert resp.status == "ok" and resp.output == "Based on stock_analyst: 42 on hand"
    [call] = tools.agent_calls
    assert call.ctx.span_id == "00f067aa0ba902b7" and call.ctx.tool == "stock_analyst"
    assert [e["kind"] for e in tools.events] == ["model_call", "model_call", "model_call"]
    assert tools.events[-1]["input"]["system"].startswith(REFLECTION_MARKER)
    [lesson] = tools.lessons
    assert lesson.ctx.agent == "ops-assistant" and lesson.ctx.span_id == "00f067aa0ba902b7"
    assert lesson.run_request_id == "req-1" and lesson.note.startswith("Use stock_analyst for requests like")
    assert learner.dropped == 0 and learner.halted is None


@pytest.mark.parametrize("via", ["headers", "trailers", "status"])
def test_the_budget_rule_on_reportevent_stops_the_reflection(spec, via):
    tools = FakeTools(report_rule=RULE_COST_BUDGET, report_via=via)
    [resp], _ = asyncio.run(execute(spec, tools, timeout=20))
    assert resp.status == "ok" and len(tools.events) == 2
    assert all(not e["input"]["system"].startswith(REFLECTION_MARKER) for e in tools.events)
    assert tools.lessons == []


def test_a_sidecar_keeping_to_6_5_refuses_the_reflection_and_learning_stops(spec):
    """§6.5 takes ReportEvent records only for an Execute in flight; the reflection comes after (§12)."""
    tools = FakeTools()
    tools.in_flight = set()
    responses, learner = asyncio.run(execute(spec, tools, timeout=20, runs=2, model=Held()))
    assert [r.status for r in responses] == ["ok", "ok"]
    assert [(e["request_id"], e["kind"]) for e in tools.events] == [("req-1", "model_call")] * 2 + [
        ("req-2", "model_call")
    ] * 2, "the runs' own records arrive while their Execute is in flight"
    [refused] = tools.rejected
    assert refused["request_id"] == "req-1" and refused["input"]["system"].startswith(REFLECTION_MARKER)
    assert tools.lessons == [], "a reflection whose cost the sidecar did not count proposes nothing"
    assert learner.halted == RULE_REPORT_REJECTED, "and no reflection is paid for after that (req-2)"


def test_the_execute_deadline_reaches_the_model_and_tool_calls(spec):
    seen: dict[str, float] = {}

    class Timing(FakeTools):
        async def InvokeAgent(self, request, context):
            seen["tool"] = context.time_remaining()
            return await super().InvokeAgent(request, context)

    spec.learning.enabled = False
    [resp], _ = asyncio.run(execute(spec, Timing(), timeout=4))
    assert resp.status == "ok"
    # At most 4 s − 0.5 s, give or take gRPC rounding the timeout it sends up to three significant figures
    # (at most 10 ms here), once on Execute and once on the tool call.
    assert 2.5 < seen["tool"] <= 3.5 + 0.1, "the tool RPC got what was left of Execute's deadline, less 500 ms"
