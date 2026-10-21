"""gRPC client for the sidecar's SidecarTools service over a unix socket (CONTRACT.md §4.3)."""

from __future__ import annotations

import json
import logging
from typing import Any

import grpc

from .pb.agentsc.v1alpha1 import runtime_pb2, runtime_pb2_grpc
from .tools import (
    RULE_REPORT_REJECTED,
    CallContext,
    LessonOutcome,
    ReportOutcome,
    ToolDenied,
    ToolFailed,
    timeout_for,
)

log = logging.getLogger("agentsc-runtime")

# Tool responses up to this size reach the agent (it truncates what it shows the model).
MAX_MESSAGE = 32 * 1024 * 1024
# Upper bounds per tool RPC, in seconds. An agent call may take as long as a whole run (the sidecar's
# RUN_TIMEOUT); every call is further held inside the Execute deadline (CONTRACT.md §4.3).
SERVICE_TIMEOUT = 120.0
AGENT_TIMEOUT = 300.0
# ReportEvent and ProposeLesson are local bookkeeping: they answer at once or not at all.
REPORT_TIMEOUT = 10.0


def _named_rule(md: Any) -> str | None:
    """The `x-agentsc-rule` in one set of a call's metadata, if any."""
    for key, value in md or ():
        if key == "x-agentsc-rule":
            return value if isinstance(value, str) else value.decode("utf-8", "replace")
    return None


def _error_rule(err: grpc.aio.AioRpcError) -> str | None:
    """The rule of a failed call. tonic sends an error status with its metadata as trailers, or as the
    headers of a trailers-only response, which grpc-python may hand over as either."""
    return _named_rule(err.trailing_metadata()) or _named_rule(err.initial_metadata())


def _rule_of(err: grpc.aio.AioRpcError) -> str:
    return _error_rule(err) or "sidecar.error"


async def _answer_rule(call: Any) -> str | None:
    """The rule on a successful call's answer: in its response headers (what tonic sends for
    `Response::metadata`, since a successful unary reply cannot carry custom trailers), else its trailers."""
    for read in ("initial_metadata", "trailing_metadata"):
        try:
            rule = _named_rule(await getattr(call, read)())
        except (grpc.aio.AioRpcError, AttributeError, TypeError):
            continue
        if rule:
            return rule
    return None


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

    async def report_event(self, record: dict[str, Any]) -> ReportOutcome:
        """Send one record. The answer carries the rule the sidecar named in `x-agentsc-rule` — e.g.
        `budget.max_cost_usd_per_day` once the agent's daily cost budget is spent — on a successful
        reply (headers or trailers) or on an error status; and whether the sidecar refused the record
        (design §6.5: INVALID_ARGUMENT, rule `runtime.report_rejected`). Never raises: the audit sink is
        the sidecar's job, and the agent does not fail on it."""
        call = self._stub.ReportEvent(runtime_pb2.AuditEvent(json=json.dumps(record)), timeout=REPORT_TIMEOUT)
        try:
            await call
        except grpc.aio.AioRpcError as e:
            rule = _error_rule(e)
            rejected = e.code() == grpc.StatusCode.INVALID_ARGUMENT or rule == RULE_REPORT_REJECTED
            log.warning(
                "report_event %s: %s %s (rule %s, request %s)",
                "rejected" if rejected else "failed",
                e.code().name,
                e.details(),
                rule,
                record.get("request_id"),
            )
            return ReportOutcome(rule, rejected)
        return ReportOutcome(await _answer_rule(call))

    async def propose_lesson(self, ctx: CallContext, note: str, rationale: str, run_request_id: str) -> LessonOutcome:
        """Hand a lesson to the sidecar, which checks, scrubs, audits and forwards it (design §6.5)."""
        req = runtime_pb2.LessonRequest(
            ctx=_ctx(ctx, ""), note=note, rationale=rationale, run_request_id=run_request_id
        )
        try:
            resp = await self._stub.ProposeLesson(req, timeout=REPORT_TIMEOUT)
        except grpc.aio.AioRpcError as e:
            log.warning("propose_lesson failed: %s %s", e.code().name, e.details())
            return LessonOutcome("error", _rule_of(e), f"{e.code().name}: {e.details()}")
        return LessonOutcome(resp.decision, resp.rule, resp.reason)
