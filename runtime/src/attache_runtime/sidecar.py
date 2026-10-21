"""gRPC client for the sidecar's SidecarTools service over a unix socket (CONTRACT.md §4.3)."""

from __future__ import annotations

import json
import time
from typing import Any

import grpc

from .pb.attache.v1alpha1 import runtime_pb2, runtime_pb2_grpc
from .tools import CallContext, ToolDenied, ToolFailed

# Tool responses up to this size reach the agent (it truncates what it shows the model).
MAX_MESSAGE = 32 * 1024 * 1024
# Upper bounds per tool RPC, in seconds. An agent call may take as long as a whole run (the sidecar's
# RUN_TIMEOUT); every call is further held inside the Execute deadline (CONTRACT.md §4.3).
SERVICE_TIMEOUT = 120.0
AGENT_TIMEOUT = 300.0
# Left of the Execute deadline after a tool call gives up, so this run can still answer.
HOP_MARGIN = 0.5


def timeout_for(ctx: CallContext, cap: float) -> float:
    if ctx.deadline is None:
        return cap
    return max(0.0, min(cap, ctx.deadline - time.monotonic() - HOP_MARGIN))


def _rule_of(err: grpc.aio.AioRpcError) -> str:
    md = err.trailing_metadata() or ()
    for key, value in md:
        if key == "x-attache-rule":
            return value if isinstance(value, str) else value.decode()
    return "sidecar.error"


def _ctx(ctx: CallContext, tool: str) -> runtime_pb2.ToolContext:
    return runtime_pb2.ToolContext(
        request_id=ctx.request_id,
        trace_id=ctx.trace_id,
        span_id=ctx.span_id,
        agent=ctx.agent,
        tool=tool,
        depth=ctx.depth,
    )


class GrpcSidecar:
    def __init__(self, address: str) -> None:
        # grpc-python sends the percent-encoded socket path as :authority on unix: targets, which hyper
        # (tonic) rejects with an HTTP/2 PROTOCOL_ERROR. A plain authority avoids that.
        self._channel = grpc.aio.insecure_channel(
            address,
            options=[
                ("grpc.default_authority", "localhost"),
                ("grpc.max_receive_message_length", MAX_MESSAGE),
                ("grpc.max_send_message_length", MAX_MESSAGE),
            ],
        )
        self._stub = runtime_pb2_grpc.SidecarToolsStub(self._channel)

    async def _call(self, coro):
        try:
            return await coro
        except grpc.aio.AioRpcError as e:
            rule = _rule_of(e)
            # A denial is a policy decision the sidecar made and named. Anything else — including
            # RESOURCE_EXHAUSTED from gRPC's own message-size limit, which carries no rule — failed.
            if e.code() == grpc.StatusCode.PERMISSION_DENIED or (
                e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED and rule.startswith("budget.")
            ):
                raise ToolDenied(rule, e.details() or "denied") from None
            raise ToolFailed(f"{rule}: {e.code().name}: {e.details()}") from None

    async def invoke_service(
        self, ctx: CallContext, tool: str, service: str, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, bytes]:
        req = runtime_pb2.ToolServiceRequest(
            ctx=_ctx(ctx, tool), service=service, method=method, path=path, headers=headers, body=body
        )
        resp = await self._call(self._stub.InvokeService(req, timeout=timeout_for(ctx, SERVICE_TIMEOUT)))
        return resp.status, resp.body

    async def invoke_agent(
        self, ctx: CallContext, tool: str, target_service: str, target_agent: str, input: str
    ) -> str:
        req = runtime_pb2.ToolAgentRequest(
            ctx=_ctx(ctx, tool), target_service=target_service, target_agent=target_agent, input=input
        )
        resp = await self._call(self._stub.InvokeAgent(req, timeout=timeout_for(ctx, AGENT_TIMEOUT)))
        if resp.status == "denied":  # older sidecars answered with an envelope
            raise ToolDenied(resp.rule or "agent.denied", resp.reason or f"agent {target_agent} denied the call")
        if resp.status != "ok":
            raise ToolFailed(f"{resp.rule}: {resp.reason}")
        return resp.output

    async def invoke_http(
        self, ctx: CallContext, tool: str, method: str, url: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, bytes]:
        req = runtime_pb2.ToolHttpRequest(ctx=_ctx(ctx, tool), method=method, url=url, headers=headers, body=body)
        resp = await self._call(self._stub.InvokeHttp(req, timeout=timeout_for(ctx, SERVICE_TIMEOUT)))
        return resp.status, resp.body

    async def report_event(self, record: dict[str, Any]) -> None:
        try:
            await self._stub.ReportEvent(runtime_pb2.AuditEvent(json=json.dumps(record)), timeout=10)
        except grpc.aio.AioRpcError as e:  # the audit sink is the sidecar's job; never fail the agent on it
            import sys

            print(f"report_event failed: {e.code().name} {e.details()}", file=sys.stderr)
