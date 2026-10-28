"""Governed learning, runtime side (design §12, agent-practices design "Learning").

After an Execute has returned its response, a run that used a tool (other than `load_skill` and
`ask_caller`) or ended `denied`/`error` gets one reflection model call, if the agent has learning
enabled. The reflection sees the run as a transcript whose entries after the input are numbered `s1`
to `sN` (the outcome included) and, with `learning.contrast_runs` above 0, digests of the agent's
earlier runs in this process. A call that got no result shows as `(not run)`, and a tool name the
charter does not declare as `undeclared`. A digest holds no input, output, argument or result, so
nothing of one caller's run reaches the reflection on another's.

The answer is `NONE` or four lines, SCOPE, TARGET, EVIDENCE and NOTE, and code checks it: the model
does not get the last word. Only the note goes to the sidecar with `SidecarTools.ProposeLesson`,
which checks, scrubs, audits and forwards it — the runtime never writes memory itself. The rationale
sent with it carries scope, target, evidence and contrast, as step ids, kinds and tool names with no
payloads. Reflections run in the background, at most two at a time per process; a run that finds
both slots busy is not reflected on.

A provider's reflection goes through the sidecar's model gateway like any model call: the gateway
lets one through per run in the run window after its Execute returned, records it and counts its
cost. For the mock, the runtime reports the reflection's `model_call` record itself. It carries the
run's request id but reaches the sidecar after that Execute has returned; a sidecar that refuses the
record (design §6.5) gets no proposal, and this process reflects no more.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import deque
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any

from .agent import ExecuteResult, gateway_headers, model_call_record, warn_unreported
from .models import Model, ModelError
from .prompts import (
    NONE,
    TRANSCRIPT_CLOSE,
    TRANSCRIPT_OPEN,
    earlier_runs_block,
    escape_reflection_tags,
    reflection_system,
)
from .spec import ASK_CALLER_TOOL, LOAD_SKILL_TOOL, AgentSpec
from .tools import RULE_REPORT_REJECTED, CallContext, ReportOutcome, SidecarClient

log = logging.getLogger("agentsc-runtime")

# Reflections running at once in this process; one more is dropped, not queued.
MAX_CONCURRENT = 2
# Each input and output in the reflection transcript is cut to this many bytes.
TRANSCRIPT_ITEM_BYTES = 8 * 1024
# Digests kept per agent: as many as `learning.contrast_runs` may ask for (CONTRACT.md §3.2).
MAX_DIGESTS = 20
# What the transcript, a digest or the rationale shows for a tool name the charter does not declare.
UNDECLARED = "undeclared"
# The tools the runtime offers itself. Calling them is not a tool use for learning.
_RUNTIME_TOOLS = frozenset({LOAD_SKILL_TOOL, ASK_CALLER_TOOL})


def should_reflect(spec: AgentSpec, result: ExecuteResult, caller: str) -> bool:
    """Whether a finished run is reflected on: learning on, the run used a tool other than
    `load_skill` and `ask_caller` or ended denied/error, the caller is one the agent learns from
    (`local`, or a peer with `from_peers`), and the sidecar has not said the daily cost budget is spent."""
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
    """One transcript entry on one line: whitespace collapsed, so no payload can start a line that reads
    as a numbered step; cut; and unable to close the transcript block (or open an earlier-runs one)."""
    return escape_reflection_tags(cut(" ".join(text.split())))


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(b.get("text", "")) for b in content if isinstance(b, dict))
    return json.dumps(content, ensure_ascii=False, default=str)


@dataclass(frozen=True)
class Entry:
    """One numbered transcript entry: its id (`s1`…), its kind (`assistant`, `call`, `result` or
    `outcome`), the tool a call or result names, whether a result is an error, its text (the payload),
    and whether a call ran."""

    id: str
    kind: str
    tool: str = ""
    error: bool = False
    text: str = ""
    ran: bool = True

    def head(self, tool: str | None = None) -> str:
        """`<id> <kind>[ <tool>][ (error)][ (not run)]`: the entry without its payload. `tool` replaces
        the tool name."""
        name = self.tool if tool is None else tool
        head = f"{self.id} {self.kind}" + (f" {name}" if name else "") + (" (error)" if self.error else "")
        return head + ("" if self.ran else " (not run)")


def _answered(result: ExecuteResult) -> set[str]:
    """The ids of the tool_use blocks that got a tool_result. No call cut off by max_tokens, and no call
    of the turn that asked, got one."""
    return {
        str(b.get("tool_use_id", ""))
        for m in result.messages
        if m.get("role") == "user" and isinstance(m.get("content"), list)
        for b in m["content"]
        if isinstance(b, dict) and b.get("type") == "tool_result"
    }


def entries(result: ExecuteResult) -> list[Entry]:
    """The run after its input, as numbered entries `s1` to `sN`, the outcome last. A call that got no
    result is `(not run)`, but for the `ask_caller` call that ended the run. Memory notes and skill
    instructions are left out: they are not what the run did."""
    found: list[Entry] = []

    def add(kind: str, tool: str = "", error: bool = False, text: str = "", ran: bool = True) -> None:
        found.append(Entry(f"s{len(found) + 1}", kind, tool, error, text, ran))

    names: dict[str, str] = {}
    answered = _answered(result) | ({result.ask_call_id} if result.ask_call_id else set())
    for m in result.messages[1:]:
        content = m.get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            if not isinstance(b, dict):
                continue
            kind = b.get("type")
            if m.get("role") == "assistant" and kind == "text" and str(b.get("text", "")).strip():
                add("assistant", text=_item(str(b["text"])))
            elif m.get("role") == "assistant" and kind == "tool_use":
                name, id_ = str(b.get("name", "")), str(b.get("id", ""))
                names[id_] = name
                args = json.dumps(b.get("input"), ensure_ascii=False, default=str)
                add("call", name, text=_item(args), ran=id_ in answered)
            elif m.get("role") == "user" and kind == "tool_result":
                name = names.get(str(b.get("tool_use_id", "")), "tool")
                error = bool(b.get("is_error"))
                if name == LOAD_SKILL_TOOL and not error:
                    text = "(skill instructions)"
                else:
                    text = _item(_result_text(b.get("content")))
                add("result", name, error, text)
    outcome = result.status + (f" ({result.rule})" if result.rule else "")
    if result.reason:
        outcome += f": {_item(result.reason)}"
    add("outcome", text=outcome)
    return found


def _declared(spec: AgentSpec, name: str) -> str:
    """A tool name as the transcript, a digest or the rationale shows it: the charter's name, else
    `undeclared`."""
    return name if spec.tool(name) is not None else UNDECLARED


def _head(spec: AgentSpec, e: Entry) -> str:
    """An entry's head as the transcript and the rationale show it: a tool name the charter does not
    declare is `undeclared` (load_skill and ask_caller keep theirs), so a name the model made up
    reaches neither the reflection nor the reviewer."""
    return e.head(e.tool if not e.tool or e.tool in _RUNTIME_TOOLS else _declared(spec, e.tool))


def transcript(spec: AgentSpec, result: ExecuteResult, caller: str, numbered: list[Entry] | None = None) -> str:
    """The run as the reflection sees it, one line per entry, those after the input numbered."""
    lines = [
        TRANSCRIPT_OPEN,
        f"agent: {spec.name}",
        f"caller: {caller or 'local'}",
        f"input: {_item(result.user_text)}",
    ]
    lines += [f"{_head(spec, e)}: {e.text}" for e in (entries(result) if numbered is None else numbered)]
    lines.append(TRANSCRIPT_CLOSE)
    return "\n".join(lines)


# --- digests of earlier runs --------------------------------------------------------------------


def _called(result: ExecuteResult) -> list[str]:
    """The tools the run called, in order: tool_use blocks that got a result (a call cut off by
    max_tokens, or in the turn that asked, never ran), without load_skill and ask_caller."""
    answered = _answered(result)
    called: list[str] = []
    for m in result.messages:
        if m.get("role") != "assistant" or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            if not isinstance(b, dict) or b.get("type") != "tool_use" or str(b.get("id", "")) not in answered:
                continue
            if (name := str(b.get("name", ""))) not in _RUNTIME_TOOLS:
                called.append(name)
    return called


@dataclass(frozen=True)
class RunDigest:
    """What a reflection on a later run may know of a finished one: its status, rule, number of steps
    (its transcript entries, the outcome included) and the declared tools it called, in order. No
    input, output, argument or result."""

    status: str
    rule: str
    steps: int
    tools: tuple[str, ...]

    def line(self, k: int) -> str:
        """The digest as line `r<k>` of the earlier-runs block."""
        ended = self.status + (f" ({self.rule})" if self.rule else "")
        steps = f"{self.steps} step{'' if self.steps == 1 else 's'}"
        return f"r{k} {ended}; {steps}; tools: {', '.join(self.tools) or 'none'}"


def digest(spec: AgentSpec, result: ExecuteResult) -> RunDigest:
    """The digest of a finished run, for the reflections on the agent's later runs. It counts the
    run's transcript entries, `s1` to `sN`, and keeps none of them."""
    tools = tuple(_declared(spec, name) for name in _called(result))
    return RunDigest(result.status, result.rule, len(entries(result)), tools)


# --- the answer ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Lesson:
    """A reflection answer that passed every check. Only `note` becomes memory."""

    scope: str
    target: str
    evidence: tuple[str, ...]
    note: str


_FIELD = re.compile(r"(SCOPE|TARGET|EVIDENCE|NOTE):(.*)")
# A NOTE that says there is no lesson, compared once tidied (`_value`) and lower-cased.
_NO_NOTE = frozenset({NONE.lower(), "n/a"})


def _value(text: str | None) -> str:
    """A field's value without surrounding whitespace, a final full stop or code quotes."""
    return (text or "").strip().rstrip(".").strip().strip("`").strip()


def _evidence(text: str | None, ids: Collection[str]) -> tuple[str, ...] | None:
    """The step ids an answer cites, in order and each once; () for none; None when one of them is not
    an id of the transcript (the evidence is made up)."""
    value = _value(text).lower()
    if value in {"", "none"}:
        return ()
    cited: list[str] = []
    for token in re.split(r"[\s,;]+", value):
        token = token.strip(".")
        if not token:
            continue
        if token not in ids:
            return None
        if token not in cited:
            cited.append(token)
    return tuple(cited)


def _target(text: str | None, spec: AgentSpec) -> str:
    """`notes`, `system`, `skill:<a skill of the agent>` or `tool:<a tool of the agent>`; anything else
    becomes `notes`. The target is advice for the reviewer: nothing edits `system` or a skill on its own."""
    value = _value(text)
    if value.lower() in {"notes", "system"}:
        return value.lower()
    if m := re.fullmatch(r"(skill|tool)\s*:\s*(\S+)", value, re.IGNORECASE):
        kind, name = m.group(1).lower(), m.group(2)
        if (spec.skill(name) if kind == "skill" else spec.tool(name)) is not None:
            return f"{kind}:{name}"
    return "notes"


def parse_lesson(answer: str, spec: AgentSpec, ids: Collection[str]) -> Lesson | None:
    """The lesson in a reflection answer, or None when a check fails (agent-practices design, "The
    answer"): NONE, an empty answer, no NOTE line or a field given twice; a note that is empty, says
    NONE or N/A, or is over `max_note_chars` once whitespace is collapsed (a cut note could say
    something the model did not); a SCOPE not in `learning.scopes`; an EVIDENCE id that is not in `ids`,
    or none with `require_evidence`. A line that is not a field continues the NOTE when it follows the
    NOTE line and is ignored anywhere else; a code fence line is always ignored."""
    text = answer.strip()
    if not text or re.match(rf"{NONE}\b", text):
        return None
    fields: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        if line.strip().startswith("```"):
            continue  # the answer in a code block: the fences are not part of any field
        if m := _FIELD.fullmatch(line.strip()):
            current = m.group(1)
            if current in fields:
                return None  # which of the two the model meant would be a guess
            fields[current] = [m.group(2)]
        elif current == "NOTE":
            fields[current].append(line)
    if "NOTE" not in fields:
        return None
    learning = spec.learning
    note = " ".join(" ".join(fields["NOTE"]).split())
    if not note or len(note) > learning.max_note_chars or _value(note).lower() in _NO_NOTE:
        return None
    scope = _value(" ".join(fields.get("SCOPE", []))).lower()
    if scope not in learning.scopes:
        return None
    evidence = _evidence(" ".join(fields.get("EVIDENCE", [])), ids)
    if evidence is None or (learning.require_evidence and not evidence):
        return None
    return Lesson(scope, _target(" ".join(fields.get("TARGET", [])), spec), evidence, note)


def rationale(spec: AgentSpec, result: ExecuteResult, lesson: Lesson, numbered: list[Entry], earlier: int) -> str:
    """What the reflection found besides the note, for the reviewer, as one line: how the run ended,
    the tools it used, the lesson's scope, target and evidence, and how many earlier runs it was
    contrasted with (left out when it saw none). Step ids, kinds and tool names only, never a payload;
    a name the charter does not declare is `undeclared` (agent-practices design, "Learning")."""
    ended = result.status + (f" ({result.rule})" if result.rule else "")
    used = list(dict.fromkeys(_declared(spec, name) for name in result.tools_used))
    by_id = {e.id: e for e in numbered}

    cited = "; ".join(_head(spec, by_id[i]) for i in lesson.evidence if i in by_id) or "none"
    sentences = [
        f"Reflection on a run that ended {ended} and used {', '.join(used) or 'no tools'}.",
        f"Scope: {lesson.scope}.",
        f"Target: {lesson.target}.",
        f"Evidence: {cited}.",
    ]
    if earlier:
        sentences.append(f"Compared with {earlier} earlier run{'' if earlier == 1 else 's'}.")
    return " ".join(sentences)


@dataclass
class Reflection:
    """A finished run to reflect on. `ctx` is the run's: its request, trace and invocation span.
    `earlier`: digests of the agent's runs before this one, newest first (Learner.after_run fills it)."""

    spec: AgentSpec
    ctx: CallContext
    caller: str
    caller_agent: str
    model: Model
    sidecar: SidecarClient
    result: ExecuteResult
    earlier: list[RunDigest] = field(default_factory=list)


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
    """Report the mock reflection's `model_call` record: the run's request and trace, parent = the
    invocation span. Raises ReflectionRefused when the sidecar refuses it. A provider's reflection
    is recorded by the gateway: nothing to send."""
    if job.model.provider != "mock":
        return
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
    counts toward the budgets) and, for a lesson that passes the checks, ProposeLesson with its note.
    Returns the note proposed, if any. Raises ReflectionRefused, before any ProposeLesson, when the
    sidecar refuses the model_call record. Its prompt is the reflection prompt alone: no practices
    sections, since a lesson is persisted text and stays plain prose."""
    spec, ctx, learning = job.spec, job.ctx, job.spec.learning
    system = reflection_system(learning.max_note_chars, list(learning.scopes), learning.require_evidence)
    numbered = entries(job.result)
    earlier = job.earlier[: max(0, learning.contrast_runs)]
    content = transcript(spec, job.result, job.caller, numbered)
    if block := earlier_runs_block([d.line(k) for k, d in enumerate(earlier, 1)]):
        content = f"{content}\n\n{block}"
    messages = [{"role": "user", "content": content}]
    max_tokens = max(1, spec.budgets.max_tokens_per_call)
    timeout = float(max(1, spec.harness.request_timeout_seconds))  # one attempt, no retries: the run is over
    started = time.monotonic()
    headers = gateway_headers(ctx, spec.name, {"purpose": "reflection"})
    try:
        resp = await asyncio.to_thread(job.model.complete, system, messages, [], max_tokens, timeout, headers)
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
    lesson = parse_lesson(resp.text(), spec, {e.id for e in numbered})
    if lesson is None:
        return None
    why = rationale(spec, job.result, lesson, numbered, len(earlier))
    outcome = await job.sidecar.propose_lesson(ctx, lesson.note, why, ctx.request_id)
    log.info(
        "lesson proposed agent=%s request=%s scope=%s target=%s decision=%s rule=%s",
        spec.name,
        ctx.request_id,
        lesson.scope,
        lesson.target,
        outcome.decision,
        outcome.rule,
    )
    return lesson.note


class Learner:
    """Starts reflections in the background, at most `max_concurrent` at once; more are dropped. Keeps
    the digests of each agent's finished runs, at most MAX_DIGESTS per agent, in memory only."""

    def __init__(self, max_concurrent: int = MAX_CONCURRENT) -> None:
        self.max_concurrent = max_concurrent
        self.dropped = 0
        # Set once the sidecar refuses a reflection's model_call record; no reflection starts after that.
        self.halted: str | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        # Per agent, the digests of its finished runs in this process, oldest first.
        self.recent: dict[str, deque[RunDigest]] = {}

    @property
    def active(self) -> int:
        return len(self._tasks)

    def earlier(self, spec: AgentSpec) -> list[RunDigest]:
        """The newest `contrast_runs` digests of the agent's runs so far, newest first."""
        if spec.learning.contrast_runs <= 0:
            return []
        return list(reversed(self.recent.get(spec.name, ())))[: spec.learning.contrast_runs]

    def record(self, spec: AgentSpec, result: ExecuteResult) -> None:
        """Keep the digest of a finished run; the oldest goes once the agent has MAX_DIGESTS."""
        self.recent.setdefault(spec.name, deque(maxlen=MAX_DIGESTS)).append(digest(spec, result))

    def after_run(self, job: Reflection) -> bool:
        """Keep the run's digest if the agent learns with contrast_runs above 0, then start the
        reflection on it if it qualifies, the sidecar has not refused a reflection's record, and a slot
        is free. Never waits."""
        learning = job.spec.learning
        if learning.enabled and learning.contrast_runs > 0:
            # The reflection contrasts with the runs before this one: take them before this one goes in.
            job.earlier = self.earlier(job.spec)
            self.record(job.spec, job.result)
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
