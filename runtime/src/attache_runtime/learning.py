"""Governed learning, runtime side (design §12).

After an Execute has returned its response, a run that used a tool (other than `load_skill`) or
ended `denied`/`error` gets one reflection model call, if the agent has learning enabled. The
answer is `NONE` or one note; a note goes to the sidecar with `SidecarTools.ProposeLesson`, which
checks, scrubs, audits and forwards it — the runtime never writes memory itself. Reflections run in
the background, at most two at a time per process; a run that finds both slots busy is not reflected on.

The reflection's `model_call` record is what counts its cost in the agent's budgets. It carries the
run's request id but reaches the sidecar after that Execute has returned, and design §6.5 has the
sidecar accept ReportEvent records only for an Execute still in flight. A sidecar that refuses the
record has not counted the cost, so the note is not proposed and this process reflects no more:
every further reflection would be spend outside the budgets (and a `runtime.report_rejected` denial).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from .agent import ExecuteResult, model_call_record, warn_unreported
from .models import Model, ModelError
from .prompts import NONE, TRANSCRIPT_CLOSE, TRANSCRIPT_OPEN, reflection_system
from .spec import LOAD_SKILL_TOOL, AgentSpec
from .tools import RULE_REPORT_REJECTED, CallContext, ReportOutcome, SidecarClient

log = logging.getLogger("attache-runtime")

# Reflections running at once in this process; one more is dropped, not queued.
MAX_CONCURRENT = 2
# Each input and output in the reflection transcript is cut to this many bytes.
TRANSCRIPT_ITEM_BYTES = 8 * 1024
_TRANSCRIPT_TAG = re.compile(r"<(\s*/?\s*transcript\b)", re.IGNORECASE)


def should_reflect(spec: AgentSpec, result: ExecuteResult, caller: str) -> bool:
    """Whether a finished run is reflected on: learning on, the run used a tool other than
    `load_skill` or ended denied/error, the caller is one the agent learns from (`local`, or a peer
    with `from_peers`), and the sidecar has not said the daily cost budget is spent."""
    if not spec.learning.enabled or result.cost_budget_exhausted:
        return False
    if (caller or "local") != "local" and not spec.learning.from_peers:
        return False  # the sidecar would refuse the lesson (design §6.5): do not pay for it
    return bool(result.tools_used) or result.status in {"denied", "error"}


def cut(text: str, limit: int = TRANSCRIPT_ITEM_BYTES) -> str:
    """`text` held to `limit` UTF-8 bytes (never splitting a character), with a marker when cut."""
    data = text.encode("utf-8", "replace")  # a lone surrogate from decoded JSON must not raise
    if len(data) <= limit:
        return text
    return data[:limit].decode("utf-8", "ignore") + f"…(truncated, {len(data)} bytes)"


def _item(text: str) -> str:
    """One transcript entry: cut, and unable to close the transcript block early."""
    return _TRANSCRIPT_TAG.sub(r"&lt;\1", cut(text))


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(b.get("text", "")) for b in content if isinstance(b, dict))
    return json.dumps(content, ensure_ascii=False, default=str)


def transcript(spec: AgentSpec, result: ExecuteResult, caller: str) -> str:
    """The run as the reflection sees it, one entry per line group. Memory notes and skill
    instructions are left out: they are not what the run did."""
    lines = [
        TRANSCRIPT_OPEN,
        f"agent: {spec.name}",
        f"caller: {caller or 'local'}",
        f"input: {_item(result.user_text)}",
    ]
    names: dict[str, str] = {}
    for m in result.messages[1:]:
        content = m.get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            if not isinstance(b, dict):
                continue
            kind = b.get("type")
            if m.get("role") == "assistant" and kind == "text" and str(b.get("text", "")).strip():
                lines.append(f"assistant: {_item(str(b['text']))}")
            elif m.get("role") == "assistant" and kind == "tool_use":
                name = str(b.get("name", ""))
                names[str(b.get("id", ""))] = name
                args = json.dumps(b.get("input"), ensure_ascii=False, default=str)
                lines.append(f"call {name}: {_item(args)}")
            elif m.get("role") == "user" and kind == "tool_result":
                name = names.get(str(b.get("tool_use_id", "")), "tool")
                flag = " (error)" if b.get("is_error") else ""
                if name == LOAD_SKILL_TOOL and not b.get("is_error"):
                    text = "(skill instructions)"
                else:
                    text = _item(_result_text(b.get("content")))
                lines.append(f"result {name}{flag}: {text}")
    outcome = result.status + (f" ({result.rule})" if result.rule else "")
    if result.reason:
        outcome += f": {_item(result.reason)}"
    lines += [f"outcome: {outcome}", TRANSCRIPT_CLOSE]
    return "\n".join(lines)


def parse_note(answer: str, max_note_chars: int) -> str | None:
    """The note in a reflection answer: None for NONE, an empty answer, or a note over the limit
    (a cut note could say something the model did not)."""
    note = " ".join(answer.split())
    if not note or re.match(rf"{NONE}\b", note):
        return None
    if len(note) > max_note_chars:
        return None
    return note


def rationale(result: ExecuteResult) -> str:
    ended = result.status + (f" ({result.rule})" if result.rule else "")
    used = ", ".join(result.tools_used) if result.tools_used else "no tools"
    return f"Reflection on a run that ended {ended} and used {used}."


@dataclass
class Reflection:
    """A finished run to reflect on. `ctx` is the run's: its request, trace and invocation span."""

    spec: AgentSpec
    ctx: CallContext
    caller: str
    caller_agent: str
    model: Model
    sidecar: SidecarClient
    result: ExecuteResult


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


class ReflectionRefused(Exception):
    """The sidecar refused the reflection's `model_call` record, so its cost is not in the budgets."""

    def __init__(self, rule: str | None) -> None:
        super().__init__(f"the sidecar refused the reflection's model_call record (rule {rule})")
        self.rule = rule


async def _report(
    job: Reflection,
    system: str,
    messages: list[dict[str, Any]],
    content: list[dict[str, Any]] | None,
    stop_reason: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    error: str | None = None,
) -> None:
    """Report the reflection's `model_call` record: the run's request and trace, parent = the
    invocation span. Raises ReflectionRefused when the sidecar refuses it."""
    record = model_call_record(
        job.spec,
        job.ctx,
        job.caller,
        job.caller_agent,
        job.model,
        system,
        messages,
        [],
        content,
        stop_reason,
        input_tokens,
        output_tokens,
        latency_ms,
        error=error,
        meta={"purpose": "reflection"},
    )
    outcome = await job.sidecar.report_event(record)
    if isinstance(outcome, ReportOutcome) and outcome.rejected:
        warn_unreported(record, outcome)
        raise ReflectionRefused(outcome.rule)


async def reflect(job: Reflection) -> str | None:
    """One reflection: the model call (reported as a `model_call` under the invocation span, so it
    counts toward the budgets) and, for a note, ProposeLesson. Returns the note proposed, if any.
    Raises ReflectionRefused, before any ProposeLesson, when the sidecar refuses the model_call record."""
    spec, ctx = job.spec, job.ctx
    system = reflection_system(spec.learning.max_note_chars)
    messages = [{"role": "user", "content": transcript(spec, job.result, job.caller)}]
    max_tokens = max(1, spec.budgets.max_tokens_per_call)
    timeout = float(max(1, spec.harness.request_timeout_seconds))  # one attempt, no retries: the run is over
    started = time.monotonic()
    try:
        resp = await asyncio.to_thread(job.model.complete, system, messages, [], max_tokens, timeout)
    except Exception as e:  # noqa: BLE001 — reported like any failed model call, then given up
        cause = e.cause if isinstance(e, ModelError) else e
        used = (e.input_tokens, e.output_tokens) if isinstance(e, ModelError) else (0, 0)
        await _report(job, system, messages, None, "error", *used, _ms(started), error=str(cause))
        log.warning("reflection failed agent=%s request=%s: %s", spec.name, ctx.request_id, cause)
        return None
    await _report(
        job, system, messages, resp.content, resp.stop_reason, resp.input_tokens, resp.output_tokens, _ms(started)
    )
    if resp.stop_reason in {"refusal", "max_tokens"}:
        return None  # no answer, or one cut short
    note = parse_note(resp.text(), spec.learning.max_note_chars)
    if note is None:
        return None
    outcome = await job.sidecar.propose_lesson(ctx, note, rationale(job.result), ctx.request_id)
    log.info(
        "lesson proposed agent=%s request=%s decision=%s rule=%s",
        spec.name,
        ctx.request_id,
        outcome.decision,
        outcome.rule,
    )
    return note


class Learner:
    """Starts reflections in the background, at most `max_concurrent` at once; more are dropped."""

    def __init__(self, max_concurrent: int = MAX_CONCURRENT) -> None:
        self.max_concurrent = max_concurrent
        self.dropped = 0
        # Set once the sidecar refuses a reflection's model_call record; no reflection starts after that.
        self.halted: str | None = None
        self._tasks: set[asyncio.Task[Any]] = set()

    @property
    def active(self) -> int:
        return len(self._tasks)

    def after_run(self, job: Reflection) -> bool:
        """Start the reflection on a finished run if it qualifies, the sidecar has not refused a
        reflection's record, and a slot is free. Never waits."""
        if self.halted is not None or not should_reflect(job.spec, job.result, job.caller):
            return False
        return self.submit(job)

    def submit(self, job: Reflection) -> bool:
        if len(self._tasks) >= self.max_concurrent:
            self.dropped += 1
            log.info(
                "reflection dropped agent=%s request=%s: %d already running",
                job.spec.name,
                job.ctx.request_id,
                len(self._tasks),
            )
            return False
        task = asyncio.get_running_loop().create_task(self._run(job))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return True

    async def _run(self, job: Reflection) -> None:
        try:
            await reflect(job)
        except ReflectionRefused as e:
            if self.halted is None:
                log.error(
                    "reflections stopped for this process: %s for agent=%s request=%s, so its cost is not "
                    "counted in the budgets and its note was not proposed. The sidecar accepts ReportEvent "
                    "records only while their Execute is in flight (design §6.5), and a reflection runs "
                    "after it has returned (§12).",
                    e,
                    job.spec.name,
                    job.ctx.request_id,
                )
            self.halted = e.rule or RULE_REPORT_REJECTED
        except Exception:  # a reflection never takes the runtime down
            log.exception("reflection crashed agent=%s request=%s", job.spec.name, job.ctx.request_id)

    async def drain(self) -> None:
        """Wait for the reflections running now (tests, shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)


# The process-wide learner the gRPC server uses.
LEARNER = Learner()
