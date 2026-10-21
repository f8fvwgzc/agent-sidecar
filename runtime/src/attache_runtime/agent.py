"""The agentic loop (CONTRACT.md §9, design §12): system + input → model → tools via the sidecar → … → answer.

Every model call goes through the harness: the agent's model with up to `harness.max_retries`
retries of retryable failures, then one attempt with `harness.fallback_model`. All of that is one
step of `budgets.max_steps`; each attempt is its own `model_call` record and `steps[]` entry.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import pricing
from .harness import RETRY_AFTER_CAP_NO_DEADLINE, is_retryable, retry_delay
from .models import Model, ModelError, ModelResponse
from .prompts import load_skill_tool, notes_block, system_prompt
from .spec import LOAD_SKILL_TOOL, AgentSpec
from .tools import HOP_MARGIN, RULE_COST_BUDGET, CallContext, ReportOutcome, SidecarClient, run_tool, timeout_for

log = logging.getLogger("attache-runtime")

# The `error` of a model_call whose Execute was cancelled while it ran (cf. audit.rs CANCELLED).
CANCELLED = "cancelled: the caller went away or its deadline passed before this output was used"
# Model calls in flight. The event loop holds tasks only weakly, and one whose Execute was cancelled
# has no one else awaiting it until it has reported its usage.
_in_flight: set[asyncio.Task[Any]] = set()
# The wait between attempts (tests replace it to keep time still).
_sleep = asyncio.sleep


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
    # What the reflection after the run needs (design §12); none of it goes back to the sidecar.
    user_text: str = ""  # the input, with its context block, as the model got it (without memory notes)
    messages: list[dict[str, Any]] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)  # tools other than load_skill the model called
    cost_budget_exhausted: bool = False  # the sidecar said the agent's daily cost budget is spent


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
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """`meta` adds fields to `input`: `attempt` (1-based) and `fallback` for harness attempts, or
    `purpose: "reflection"` for the learning reflection (design §6.5, §11.1, §12)."""
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
        "input": {"system": system, "messages": messages, "tools": [t["name"] for t in tools], **(meta or {})},
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


def load_skill_record(
    spec: AgentSpec,
    ctx: CallContext,
    caller: str,
    caller_agent: str,
    skill: str,
    instructions: str,
    latency_ms: int,
) -> dict[str, Any]:
    """The `tool_call` record of a `load_skill` call: its own span under the invocation (design §12)."""
    return {
        "ts": _now(),
        "kind": "tool_call",
        "request_id": ctx.request_id,
        "trace_id": ctx.trace_id,
        "span_id": new_span_id(),
        "parent_span_id": ctx.span_id or None,
        "service": "",
        "namespace": "",
        "agent": spec.name,
        "caller": caller or "local",
        "caller_agent": caller_agent or None,
        "callee": f"{LOAD_SKILL_TOOL}:{skill}",
        "direction": "internal",
        "input": {"name": skill},
        "output": instructions,
        "input_sha256": None,
        "output_sha256": None,
        "tokens": None,
        "cost_usd": None,
        "latency_ms": latency_ms,
        "decision": "allow",
        "rule": None,
        "reason": None,
        "error": None,
    }


def cut_tool_result(content: str, limit: int) -> tuple[str, str]:
    """A tool result held to `limit` characters, with a note telling the model it was cut; and the
    step summary saying so ("" when it fit)."""
    if len(content) <= limit:
        return content, ""
    note = f"\n[the runtime cut this tool result to its first {limit} of {len(content)} characters]"
    return content[:limit] + note, f"result cut to {limit} of {len(content)} chars"


@dataclass
class _Turn:
    """A finished model call: its response, or the error it failed with, and the usage to account."""

    resp: ModelResponse | None
    error: Exception | None
    input_tokens: int
    output_tokens: int
    latency_ms: int
    sidecar_rule: str | None = None  # the rule the sidecar named when it took the record
    label: str = ""  # "attempt n/N" or "fallback"


async def _model_turn(
    spec: AgentSpec,
    ctx: CallContext,
    caller: str,
    caller_agent: str,
    model: Model,
    sidecar: SidecarClient,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    max_tokens: int,
    timeout: float,
    abandoned: asyncio.Event,
    meta: dict[str, Any] | None = None,
) -> _Turn:
    """One model call and its ReportEvent. The provider bills the call whether or not anyone still waits
    for it, so this runs to the end even when the Execute that started it is cancelled."""
    started = time.monotonic()
    try:
        resp = await asyncio.to_thread(model.complete, system, messages, tools, max_tokens, timeout)
    except Exception as e:  # noqa: BLE001 — surfaced to the sidecar as an error envelope
        cause = e.cause if isinstance(e, ModelError) else e
        used = (e.input_tokens, e.output_tokens) if isinstance(e, ModelError) else (0, 0)
        turn = _Turn(None, cause, *used, _ms(started))
        content, stop_reason, error = None, "error", str(cause)
    else:
        turn = _Turn(resp, None, resp.input_tokens, resp.output_tokens, _ms(started))
        content, stop_reason = resp.content, resp.stop_reason
        error = CANCELLED if abandoned.is_set() else None
    record = model_call_record(
        spec,
        ctx,
        caller,
        caller_agent,
        model,
        system,
        messages,
        tools,
        content,
        stop_reason,
        turn.input_tokens,
        turn.output_tokens,
        turn.latency_ms,
        error=error,
        meta=meta,
    )
    outcome = await sidecar.report_event(record)
    turn.sidecar_rule = outcome.rule if isinstance(outcome, ReportOutcome) else None
    if isinstance(outcome, ReportOutcome) and outcome.rejected:
        warn_unreported(record, outcome)
    return turn


def _attempt_meta(label: str) -> dict[str, Any]:
    """`attempt n/N` -> {attempt: n, fallback: False}; `fallback` -> {attempt: <none>, fallback: True}."""
    if label == "fallback":
        return {"fallback": True}
    try:
        n = int(label.split()[1].split("/")[0])
    except (IndexError, ValueError):
        n = 1
    return {"attempt": n, "fallback": False}


def warn_unreported(record: dict[str, Any], outcome: ReportOutcome) -> None:
    """Log a model call the sidecar refused to record: the provider bills it, but the agent's budgets
    never see it. A sidecar that keeps to design §6.5 refuses records of an Execute no longer in flight,
    e.g. a call that finished after its Execute was cancelled."""
    log.warning(
        "the sidecar refused the model_call record of agent=%s request=%s (rule %s): %s input and %s output "
        "tokens, $%s, are not counted in the agent's budgets",
        record.get("agent"),
        record.get("request_id"),
        outcome.rule,
        (record.get("tokens") or {}).get("input"),
        (record.get("tokens") or {}).get("output"),
        record.get("cost_usd"),
    )


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


class _Run:
    """One Execute: the conversation, the harness around each model call, and the tool calls."""

    def __init__(
        self,
        spec: AgentSpec,
        ctx: CallContext,
        model: Model,
        fallback: Model | None,
        sidecar: SidecarClient,
        caller: str,
        caller_agent: str,
    ) -> None:
        self.spec, self.ctx, self.model, self.fallback, self.sidecar = spec, ctx, model, fallback, sidecar
        self.caller, self.caller_agent = caller, caller_agent
        self.system = system_prompt(spec.system, spec.inline_skills())
        self.loadable = spec.loadable_skills()
        self.tools = [t.anthropic_tool() for t in spec.tools]
        if self.loadable:
            self.tools.append(load_skill_tool(self.loadable))
        self.max_tokens = max(1, spec.budgets.max_tokens_per_call)
        # Tool calls carry the Execute's span, so the sidecar's tool spans nest under the invocation.
        self.tool_ctx = CallContext(ctx.request_id, ctx.trace_id, ctx.span_id, spec.name, ctx.depth, ctx.deadline)
        self.abandoned = asyncio.Event()
        self.result = ExecuteResult(status="ok")

    async def _attempt(self, model: Model, label: str, messages: list[dict[str, Any]], timeout: float) -> _Turn:
        call = asyncio.create_task(
            _model_turn(
                self.spec,
                self.ctx,
                self.caller,
                self.caller_agent,
                model,
                self.sidecar,
                self.system,
                list(messages),  # this attempt's view: the record must not see later turns
                self.tools,
                self.max_tokens,
                timeout,
                self.abandoned,
                _attempt_meta(label),
            )
        )
        _in_flight.add(call)
        call.add_done_callback(_in_flight.discard)
        try:
            turn = await asyncio.shield(call)
        except asyncio.CancelledError:
            # Execute was cancelled (the caller went away, or its deadline passed). The model call goes
            # on in its thread and is billed, so the task finishes it and reports its usage.
            self.abandoned.set()
            raise
        turn.label = label
        r = self.result
        r.input_tokens += turn.input_tokens
        r.output_tokens += turn.output_tokens
        r.cost_usd = round(r.cost_usd + pricing.cost_usd(model.name, turn.input_tokens, turn.output_tokens), 6)
        if turn.sidecar_rule == RULE_COST_BUDGET:
            r.cost_budget_exhausted = True
        if turn.error is not None:
            summary = f"{label}: error {type(turn.error).__name__}"
        else:
            summary = f"{label}: stop={turn.resp.stop_reason if turn.resp else ''}"
        r.steps.append(Step("model_call", model.name, "allow", "", turn.latency_ms, summary))
        return turn

    def _wait(self, n: int, err: BaseException) -> float | None:
        """Seconds to wait before retry n, or None when the wait and a retry no longer fit the deadline."""
        wait = retry_delay(n, err)
        if self.ctx.deadline is None:
            return min(wait, RETRY_AFTER_CAP_NO_DEADLINE)
        if time.monotonic() + wait >= self.ctx.deadline - HOP_MARGIN:
            return None
        return wait

    async def _model_step(self, messages: list[dict[str, Any]]) -> _Turn | None:
        """One step's model call under the harness. Returns the turn that answered or the last failure;
        None when not even the first attempt fits the deadline."""
        h = self.spec.harness
        total = max(0, h.max_retries) + 1
        per_attempt = float(max(1, h.request_timeout_seconds))
        turn: _Turn | None = None
        for n in range(1, total + 1):
            timeout = timeout_for(self.ctx, per_attempt)
            if timeout <= 0:
                return turn
            turn = await self._attempt(self.model, f"attempt {n}/{total}", messages, timeout)
            if turn.error is None or not is_retryable(turn.error):
                return turn
            if n == total:
                break
            wait = self._wait(n - 1, turn.error)
            if wait is None:
                break
            await _sleep(wait)
        if self.fallback is None:
            return turn
        timeout = timeout_for(self.ctx, per_attempt)
        if timeout <= 0:
            return turn
        return await self._attempt(self.fallback, "fallback", messages, timeout)

    async def _load_skill(self, args: Any) -> tuple[str, bool]:
        started = time.monotonic()
        name = args.get("name") if isinstance(args, dict) else None
        skill = self.spec.skill(name) if isinstance(name, str) else None
        if skill is None:
            self.result.steps.append(Step("tool_call", LOAD_SKILL_TOOL, "allow", "", 0, "error: unknown skill"))
            return f"unknown skill; load one of: {', '.join(s.name for s in self.loadable)}", True
        latency = _ms(started)
        await self.sidecar.report_event(
            load_skill_record(
                self.spec, self.ctx, self.caller, self.caller_agent, skill.name, skill.instructions, latency
            )
        )
        self.result.steps.append(
            Step("tool_call", f"{LOAD_SKILL_TOOL}:{skill.name}", "allow", "", latency, "skill loaded")
        )
        return skill.instructions, False

    async def _use_tool(self, use: dict[str, Any]) -> tuple[str, bool]:
        name = str(use.get("name", ""))
        args = use.get("input") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"input": args}
        if name == LOAD_SKILL_TOOL and self.loadable:
            return await self._load_skill(args)
        if name not in self.result.tools_used:
            self.result.tools_used.append(name)
        tool = self.spec.tool(name)
        if tool is None:
            self.result.steps.append(Step("tool_call", name, "deny", "guardrail.allowed_tools", 0, "not declared"))
            return f"unknown tool {name}", True
        outcome = await run_tool(tool, args if isinstance(args, dict) else {"input": args}, self.tool_ctx, self.sidecar)
        content, summary = cut_tool_result(outcome.content, self.spec.harness.tool_result_max_chars)
        self.result.steps.append(
            Step(outcome.kind, outcome.callee, outcome.decision, outcome.rule, outcome.latency_ms, summary)
        )
        return content, outcome.is_error

    async def run(self, user_input: str, context_json: str) -> ExecuteResult:
        spec, result = self.spec, self.result
        first = user_input
        if context_json.strip():
            first = f"{user_input}\n\n<context>\n{context_json.strip()}\n</context>"
        result.user_text = first
        opening: str | list[dict[str, Any]] = first
        if spec.memory:
            # Notes are data in the user turn, never part of the system prompt (design §12).
            notes = notes_block([n.text for n in spec.memory])
            opening = [{"type": "text", "text": notes}, {"type": "text", "text": first}]
        messages: list[dict[str, Any]] = [{"role": "user", "content": opening}]
        result.messages = messages

        for step in range(spec.budgets.max_steps):
            turn = await self._model_step(messages)
            if turn is None:
                # The sidecar is about to give up on this Execute: a model call started now would be billed
                # and its answer never used.
                result.status, result.rule = "error", "deadline.exceeded"
                result.reason = (
                    f"agent {spec.name} stopped before step {step + 1}: "
                    f"less than {HOP_MARGIN}s left of its caller's deadline"
                )
                return result
            if turn.error is not None or turn.resp is None:
                e = turn.error
                result.status, result.rule, result.reason = "error", "model.error", f"{type(e).__name__}: {e}"
                return result
            resp = turn.resp

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
                    result.steps[-1].summary = f"{turn.label}: stop=max_tokens (no complete answer)"
                    return result
                result.output = text
                result.steps[
                    -1
                ].summary = f"{turn.label}: stop=max_tokens (output truncated by budgets.max_tokens_per_call)"
                return result
            if not tool_uses or resp.stop_reason in {"end_turn", "stop_sequence"}:
                result.output = resp.text()
                return result

            tool_results: list[dict[str, Any]] = []
            for use in tool_uses:
                content, is_error = await self._use_tool(use)
                tool_results.append(
                    {"type": "tool_result", "tool_use_id": use.get("id", ""), "content": content, "is_error": is_error}
                )
            messages.append({"role": "user", "content": tool_results})

        result.status, result.rule = "error", "budget.max_steps"
        result.reason = f"agent {spec.name} did not finish within max_steps={spec.budgets.max_steps}"
        return result


async def run_agent(
    spec: AgentSpec,
    user_input: str,
    context_json: str,
    ctx: CallContext,
    model: Model,
    sidecar: SidecarClient,
    caller: str = "local",
    caller_agent: str = "",
    *,
    fallback: Model | None = None,
) -> ExecuteResult:
    """Run one Execute. `fallback` is the model for `harness.fallback_model` (None: no fallback)."""
    return await _Run(spec, ctx, model, fallback, sidecar, caller, caller_agent).run(user_input, context_json)
