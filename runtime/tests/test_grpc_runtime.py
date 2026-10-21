"""The runtime's gRPC server against a fake SidecarTools server, over real gRPC on loopback: the
Execute deadline, tool span ids, ReportEvent's trailing rule and ProposeLesson on the wire."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import grpc
import pytest

from attache_runtime.learning import Learner
from attache_runtime.pb.attache.v1alpha1 import common_pb2, runtime_pb2, runtime_pb2_grpc
from attache_runtime.prompts import REFLECTION_MARKER
from attache_runtime.server import RuntimeServicer
from attache_runtime.sidecar import GrpcSidecar
from attache_runtime.spec import AgentSpec
from attache_runtime.tools import RULE_COST_BUDGET


class FakeTools(runtime_pb2_grpc.SidecarToolsServicer):
    def __init__(self, report_rule: str | None = None) -> None:
        self.report_rule = report_rule
        self.events: list[dict[str, Any]] = []
        self.agent_calls: list[Any] = []
        self.lessons: list[Any] = []

    async def ReportEvent(self, request, context):
        self.events.append(json.loads(request.json))
        if self.report_rule:
            context.set_trailing_metadata((("x-attache-rule", self.report_rule),))
        return common_pb2.Empty()

    async def InvokeAgent(self, request, context):
        self.agent_calls.append(request)
        return common_pb2.InvokeAgentResponse(status="ok", output="42 on hand")

    async def ProposeLesson(self, request, context):
        self.lessons.append(request)
        return runtime_pb2.LessonResponse(decision="allow", rule="learning.proposed", reason="")


async def execute(spec: AgentSpec, tools: FakeTools, timeout: float) -> tuple[Any, Learner]:
    sidecar_server = grpc.aio.server()
    runtime_pb2_grpc.add_SidecarToolsServicer_to_server(tools, sidecar_server)
    sidecar_port = sidecar_server.add_insecure_port("127.0.0.1:0")
    await sidecar_server.start()
    learner = Learner()
    runtime_server = grpc.aio.server()
    runtime_pb2_grpc.add_RuntimeServicer_to_server(
        RuntimeServicer(GrpcSidecar(f"127.0.0.1:{sidecar_port}"), learner=learner), runtime_server
    )
    runtime_port = runtime_server.add_insecure_port("127.0.0.1:0")
    await runtime_server.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{runtime_port}") as channel:
            resp = await runtime_pb2_grpc.RuntimeStub(channel).Execute(
                runtime_pb2.ExecuteRequest(
                    request_id="req-1",
                    trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
                    span_id="00f067aa0ba902b7",
                    agent_spec_json=spec.model_dump_json(),
                    input="How many WIDGET-1 in stock?",
                    caller="local",
                ),
                timeout=timeout,
            )
        await learner.drain()
        return resp, learner
    finally:
        await runtime_server.stop(None)
        await sidecar_server.stop(None)


@pytest.fixture
def spec(ops_assistant) -> AgentSpec:
    ops_assistant.learning.enabled = True
    return ops_assistant


def test_execute_over_grpc_reflects_and_proposes(spec):
    tools = FakeTools()
    resp, learner = asyncio.run(execute(spec, tools, timeout=20))
    assert resp.status == "ok" and resp.output == "Based on stock_analyst: 42 on hand"
    [call] = tools.agent_calls
    assert call.ctx.span_id == "00f067aa0ba902b7" and call.ctx.tool == "stock_analyst"
    assert [e["kind"] for e in tools.events] == ["model_call", "model_call", "model_call"]
    assert tools.events[-1]["input"]["system"].startswith(REFLECTION_MARKER)
    [lesson] = tools.lessons
    assert lesson.ctx.agent == "ops-assistant" and lesson.ctx.span_id == "00f067aa0ba902b7"
    assert lesson.run_request_id == "req-1" and lesson.note.startswith("Use stock_analyst for requests like")
    assert learner.dropped == 0


def test_the_budget_rule_on_reportevent_stops_the_reflection(spec):
    tools = FakeTools(report_rule=RULE_COST_BUDGET)
    resp, _ = asyncio.run(execute(spec, tools, timeout=20))
    assert resp.status == "ok"
    assert all(not e["input"]["system"].startswith(REFLECTION_MARKER) for e in tools.events)
    assert tools.lessons == []


def test_the_execute_deadline_reaches_the_model_and_tool_calls(spec):
    seen: dict[str, float] = {}

    class Timing(FakeTools):
        async def InvokeAgent(self, request, context):
            seen["tool"] = context.time_remaining()
            return await super().InvokeAgent(request, context)

    spec.learning.enabled = False
    resp, _ = asyncio.run(execute(spec, Timing(), timeout=4))
    assert resp.status == "ok"
    assert 2.5 < seen["tool"] <= 3.5, "the tool RPC got what was left of Execute's deadline, less 500 ms"
