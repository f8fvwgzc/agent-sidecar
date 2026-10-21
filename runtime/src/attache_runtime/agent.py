"""The agentic loop (CONTRACT.md §9): system + input → model → tools via the sidecar → … → answer."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import pricing
from .models import Model, ModelError, ModelResponse
from .spec import AgentSpec
from .tools import HOP_MARGIN, CallContext, SidecarClient, run_tool, timeout_for

# Upper bound per model request, in seconds (the Anthropic SDK's own default); held inside the deadline.
MODEL_TIMEOUT = 600.0
# The `error` of a model_call whose Execute was cancelled while it ran (cf. audit.rs CANCELLED).
CANCELLED = "cancelled: the caller went away or its deadline passed before this output was used"
# Model calls in flight. The event loop holds tasks only weakly, and one whose Execute was cancelled
# has no one else awaiting it until it has reported its usage.
_in_flight: set[asyncio.Task[Any]] = set()


@dataclass
class Step:
    kind: str
    name: str
    decision: str = "allow"
    rule: str = ""
    latency_ms: int = 0
    summary: str = ""


@dataclass
class ExecuteResult:
    status: str  # ok | denied | error
    output: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    steps: list[Step] = field(default_factory=list)
    rule: str = ""
    reason: str = ""


def _now() -> str:
    now = datetime.now(UTC)  # read the clock once: two reads can straddle a second boundary
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def new_span_id() -> str:
    return secrets.token_hex(8)


def model_call_record(
    spec: AgentSpec,
    ctx: CallContext,
    caller: str,
    caller_agent: str,
    model: Model,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    content: list[dict[str, Any]] | None,
    stop_reason: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    error: str | None = None,
) -> dict[str, Any]:
    callee = model.name if model.provider == "mock" else f"{model.provider}:{model.name}"
    denied = stop_reason == "refusal"
    return {
        "ts": _now(),
        "kind": "model_call",
        "request_id": ctx.request_id,
        "trace_id": ctx.trace_id,
        "span_id": new_span_id(),
        "parent_span_id": ctx.span_id or None,
        "service": "",
        "namespace": "",
        "agent": spec.name,
        "caller": caller or "local",
        "caller_agent": caller_agent or None,
        "callee": callee,
        "direction": "outbound",
        "input": {"system": system, "messages": messages, "tools": [t["name"] for t in tools]},
        "output": content,
        "input_sha256": None,
        "output_sha256": None,
        "tokens": {"input": input_tokens, "output": output_tokens},
        "cost_usd": pricing.cost_usd(model.name, input_tokens, output_tokens),
        "latency_ms": latency_ms,
        "decision": "deny" if denied else "allow",
        "rule": "model.refusal" if denied else None,
        "reason": "the model refused the request" if denied else None,
        "error": error,
    }


@dataclass
class _Turn:
    """A finished model call: its response, or the error it failed with, and the usage to account."""

    resp: ModelResponse | None
    error: Exception | None
    input_tokens: int
    output_tokens: int
    latency_ms: int


async def _model_turn(
    spec: AgentSpec,
    ctx: CallContext,
    caller: str,
    caller_agent: str,
    model: Model,
    sidecar: SidecarClient,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    max_tokens: int,
    timeout: float,
    abandoned: asyncio.Event,
) -> _Turn:
    """One model call and its ReportEvent. The provider bills the call whether or not anyone still waits
    for it, so this runs to the end even when the Execute that started it is cancelled."""
    started = time.monotonic()
    try:
        resp = await asyncio.to_thread(model.complete, spec.system, messages, tools, max_tokens, timeout)
    except Exception as e:  # noqa: BLE001 — surfaced to the sidecar as an error envelope
        cause = e.cause if isinstance(e, ModelError) else e
        used = (e.input_tokens, e.output_tokens) if isinstance(e, ModelError) else (0, 0)
        turn = _Turn(None, cause, *used, _ms(started))
        content, stop_reason, error = None, "error", str(cause)
    else:
        turn = _Turn(resp, None, resp.input_tokens, resp.output_tokens, _ms(started))
        content, stop_reason = resp.content, resp.stop_reason
        error = CANCELLED if abandoned.is_set() else None
    await sidecar.report_event(
        model_call_record(
            spec,
            ctx,
            caller,
            caller_agent,
            model,
            spec.system,
            messages,
            tools,
            content,
            stop_reason,
            turn.input_tokens,
            turn.output_tokens,
            turn.latency_ms,
            error=error,
        )
    )
    return turn


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


async def run_agent(
    spec: AgentSpec,
    user_input: str,
    context_json: str,
    ctx: CallContext,
    model: Model,
    sidecar: SidecarClient,
    caller: str = "local",
    caller_agent: str = "",
) -> ExecuteResult:
    tools = [t.anthropic_tool() for t in spec.tools]
    first = user_input
    if context_json.strip():
        first = f"{user_input}\n\n<context>\n{context_json.strip()}\n</context>"
    messages: list[dict[str, Any]] = [{"role": "user", "content": first}]
    result = ExecuteResult(status="ok")
    max_tokens = max(1, spec.budgets.max_tokens_per_call)
    abandoned = asyncio.Event()

    for step in range(spec.budgets.max_steps):
        timeout = timeout_for(ctx, MODEL_TIMEOUT)
        if timeout <= 0:
            # The sidecar is about to give up on this Execute: a model call started now would be billed
            # and its answer never used.
            result.status, result.rule = "error", "deadline.exceeded"
            result.reason = (
                f"agent {spec.name} stopped before step {step + 1}: "
                f"less than {HOP_MARGIN}s left of its caller's deadline"
            )
            return result
        call = asyncio.create_task(
            _model_turn(
                spec, ctx, caller, caller_agent, model, sidecar, messages, tools, max_tokens, timeout, abandoned
            )
        )
        _in_flight.add(call)
        call.add_done_callback(_in_flight.discard)
        try:
            turn = await asyncio.shield(call)
        except asyncio.CancelledError:
            # Execute was cancelled (the caller went away, or its deadline passed). The model call goes
            # on in its thread and is billed, so the task finishes it and reports its usage.
            abandoned.set()
            raise
        result.input_tokens += turn.input_tokens
        result.output_tokens += turn.output_tokens
        result.cost_usd = round(
            result.cost_usd + pricing.cost_usd(model.name, turn.input_tokens, turn.output_tokens), 6
        )
        if turn.error is not None:
            e = turn.error
            result.status, result.rule, result.reason = "error", "model.error", f"{type(e).__name__}: {e}"
            result.steps.append(
                Step("model_call", model.name, "allow", "", turn.latency_ms, f"error: {type(e).__name__}")
            )
            return result
        resp = turn.resp
        result.steps.append(Step("model_call", model.name, "allow", "", turn.latency_ms, f"stop={resp.stop_reason}"))

        if resp.stop_reason == "refusal":
            result.status, result.rule, result.reason = "denied", "model.refusal", "the model refused the request"
            result.steps[-1].decision, result.steps[-1].rule = "deny", "model.refusal"
            return result

        messages.append({"role": "assistant", "content": resp.content})
        tool_uses = resp.tool_uses()
        if resp.stop_reason == "pause_turn":
            continue
        if resp.stop_reason == "max_tokens":
            # The budget cut the turn short. A half-written tool call must not run, and an answer
            # with no text (thinking used the whole budget) is a failure, not an empty success.
            text = resp.text()
            if tool_uses or not text.strip():
                result.status, result.rule = "error", "budget.max_tokens_per_call"
                result.reason = (
                    f"agent {spec.name} hit max_tokens_per_call={spec.budgets.max_tokens_per_call} "
                    "before finishing; raise the budget in the charter"
                )
                result.steps[-1].summary = "stop=max_tokens (no complete answer)"
                return result
            result.output = text
            result.steps[-1].summary = "stop=max_tokens (output truncated by budgets.max_tokens_per_call)"
            return result
        if not tool_uses or resp.stop_reason in {"end_turn", "stop_sequence"}:
            result.output = resp.text()
            return result

        tool_results: list[dict[str, Any]] = []
        for use in tool_uses:
            tool = spec.tool(use["name"])
            args = use.get("input") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"input": args}
            if tool is None:
                content, is_error = f"unknown tool {use['name']}", True
                result.steps.append(
                    Step("tool_call", use["name"], "deny", "guardrail.allowed_tools", 0, "not declared")
                )
            else:
                call_ctx = CallContext(ctx.request_id, ctx.trace_id, new_span_id(), spec.name, ctx.depth, ctx.deadline)
                outcome = await run_tool(tool, args, call_ctx, sidecar)
                content, is_error = outcome.content, outcome.is_error
                result.steps.append(
                    Step(outcome.kind, outcome.callee, outcome.decision, outcome.rule, outcome.latency_ms)
                )
            tool_results.append(
                {"type": "tool_result", "tool_use_id": use["id"], "content": content[:20_000], "is_error": is_error}
            )
        messages.append({"role": "user", "content": tool_results})

    result.status, result.rule = "error", "budget.max_steps"
    result.reason = f"agent {spec.name} did not finish within max_steps={spec.budgets.max_steps}"
    return result
