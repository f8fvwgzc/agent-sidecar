"""Tool dispatch: every call goes to the sidecar's SidecarTools service (CONTRACT.md §4.3)."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote

from .spec import ToolSpec


@dataclass
class CallContext:
    request_id: str
    trace_id: str
    span_id: str
    agent: str
    depth: int = 0
    # time.monotonic() at which the sidecar stops waiting for this Execute (None: no deadline).
    deadline: float | None = None


# Left of the Execute deadline after a call made inside it gives up, so this run can still answer.
HOP_MARGIN = 0.5


def timeout_for(ctx: CallContext, cap: float) -> float:
    """Seconds a call made on this Execute's behalf may take: `cap`, held inside the deadline."""
    if ctx.deadline is None:
        return cap
    return max(0.0, min(cap, ctx.deadline - time.monotonic() - HOP_MARGIN))


@dataclass
class ToolOutcome:
    content: str
    is_error: bool
    decision: str  # allow | deny
    rule: str
    kind: str  # service_call | agent_call | http_call
    callee: str
    latency_ms: int


class SidecarClient(Protocol):
    async def invoke_service(
        self, ctx: CallContext, tool: str, service: str, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, bytes]: ...

    async def invoke_agent(
        self, ctx: CallContext, tool: str, target_service: str, target_agent: str, input: str
    ) -> str: ...

    async def invoke_http(
        self, ctx: CallContext, tool: str, method: str, url: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, bytes]: ...

    # The sidecar's answer: the rule it named (gRPC `x-agentsc-rule`), if any — `budget.max_cost_usd_per_day`
    # once a reported cost exhausts the agent's daily budget — and whether it refused the record (§6.5).
    async def report_event(self, record: dict[str, Any]) -> ReportOutcome: ...

    async def propose_lesson(
        self, ctx: CallContext, note: str, rationale: str, run_request_id: str
    ) -> LessonOutcome: ...


# The rule a sidecar names when an agent's daily cost budget is used up.
RULE_COST_BUDGET = "budget.max_cost_usd_per_day"
# The rule of a ReportEvent record the sidecar refuses (design §6.5: INVALID_ARGUMENT).
RULE_REPORT_REJECTED = "runtime.report_rejected"


@dataclass(frozen=True)
class ReportOutcome:
    """The sidecar's answer to ReportEvent."""

    rule: str | None = None  # the rule it named in `x-agentsc-rule`, if any
    # It refused the record (INVALID_ARGUMENT, or rule `runtime.report_rejected`): the record was not
    # written, and a model call's cost was not counted in the agent's budgets.
    rejected: bool = False


@dataclass
class LessonOutcome:
    """The sidecar's answer to ProposeLesson; decision `error` when the call itself failed."""

    decision: str
    rule: str
    reason: str


class ToolDenied(Exception):
    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule
        self.reason = reason


class ToolFailed(Exception):
    pass


RULE_TOOL_SPEC = "guardrail.tool_spec"
_PARAM = re.compile(r"\{([a-zA-Z0-9_]+)(\?)?\}")


def fill_path(template: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Substitute `{param}`s in a service path or http URL; return it and the arguments not used.

    A path value is percent-encoded, so it is exactly one segment: "../admin" arrives as
    "..%2Fadmin", which the sidecar refuses (CONTRACT.md §3.1, §5.1). A missing or empty value, or
    one of only dots, would drop or climb a segment and retarget the call (DELETE /orders/{id}
    becoming DELETE /orders), so it raises ToolDenied instead — except for an optional last
    segment `{param?}`, which is then left out together with its `/`.
    """
    used: set[str] = set()
    origin, path, query = _split_template(template)

    if m := re.search(r"/\{([a-zA-Z0-9_]+)\?\}$", path):
        used.add(m.group(1))
        if _blank(args.get(m.group(1))):
            path = path[: m.start()] or "/"

    def sub_path(m: re.Match[str]) -> str:
        name = m.group(1)
        used.add(name)
        value = args.get(name)
        if _blank(value) or not str(value).strip("."):
            raise ToolDenied(
                RULE_TOOL_SPEC,
                f"path parameter {name!r} needs a non-empty value other than '.' or '..', got {value!r}",
            )
        return quote(str(value), safe="")

    def sub_query(m: re.Match[str]) -> str:
        used.add(m.group(1))
        value = args.get(m.group(1))
        return "" if value is None else quote(str(value), safe="")

    path = _PARAM.sub(sub_path, path)
    query = _PARAM.sub(sub_query, query)
    rest = {k: v for k, v in args.items() if k not in used}
    return f"{origin}{path}{query}", rest


def _blank(value: Any) -> bool:
    return value is None or str(value) == ""


def _split_template(template: str) -> tuple[str, str, str]:
    """`scheme://authority`, path and `?query` of a template; the `?` of `{param?}` is not a query."""
    origin = ""
    if "://" in template:
        scheme, _, tail = template.partition("://")
        cut = min((i for i in (tail.find("/"), tail.find("?")) if i >= 0), default=len(tail))
        origin, template = f"{scheme}://{tail[:cut]}", tail[cut:]
    q = re.search(r"\?(?![^{]*\})", template)
    if q is None:
        return origin, template, ""
    return origin, template[: q.start()], template[q.start() :]


def with_query(path: str, args: dict[str, Any]) -> str:
    """Append `args` as query parameters, after any query the template already has."""
    from urllib.parse import urlencode

    query = urlencode({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in args.items()})
    if "?" not in path:
        return f"{path}?{query}"
    return f"{path}{'' if path.endswith(('?', '&')) else '&'}{query}"


async def run_tool(tool: ToolSpec, args: dict[str, Any], ctx: CallContext, sidecar: SidecarClient) -> ToolOutcome:
    started = time.monotonic()
    kind = {"service": "service_call", "agent": "agent_call", "http": "http_call"}[tool.type]
    callee = tool.name
    try:
        if tool.type == "service":
            method = (tool.method or "GET").upper()
            path, rest = fill_path(tool.path or "/", args)
            headers = {"accept": "application/json"}
            body = b""
            if rest and method in {"GET", "DELETE", "HEAD"}:
                path = with_query(path, rest)
            elif rest or method in {"POST", "PUT", "PATCH"}:
                body = json.dumps(rest).encode()
                headers["content-type"] = "application/json"
            callee = f"{tool.service} {method} {path}"
            status, data = await sidecar.invoke_service(ctx, tool.name, tool.service or "", method, path, headers, body)
            text = data.decode("utf-8", "replace")
            return ToolOutcome(text or f"HTTP {status}", status >= 400, "allow", "", kind, callee, _ms(started))
        if tool.type == "agent":
            target_service = tool.service or ""
            callee = f"{target_service}/{tool.agent}" if target_service else str(tool.agent)
            question = args.get("input") if isinstance(args.get("input"), str) else json.dumps(args)
            output = await sidecar.invoke_agent(ctx, tool.name, target_service, tool.agent or "", question or "")
            return ToolOutcome(output, False, "allow", "", kind, callee, _ms(started))
        method = (tool.method or "GET").upper()
        url, rest = fill_path(tool.url or "", args)
        headers = {"accept": "application/json"}
        body = b""
        if rest and method in {"GET", "DELETE", "HEAD"}:
            url = with_query(url, rest)
        elif rest:
            body = json.dumps(rest).encode()
            headers["content-type"] = "application/json"
        callee = f"{method} {url}"
        status, data = await sidecar.invoke_http(ctx, tool.name, method, url, headers, body)
        text = data.decode("utf-8", "replace")
        return ToolOutcome(text or f"HTTP {status}", status >= 400, "allow", "", kind, callee, _ms(started))
    except ToolDenied as d:
        return ToolOutcome(f"denied by {d.rule}: {d.reason}", True, "deny", d.rule, kind, callee, _ms(started))
    except ToolFailed as f:
        return ToolOutcome(f"tool failed: {f}", True, "allow", "", kind, callee, _ms(started))


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
