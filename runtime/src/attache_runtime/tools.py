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

    async def report_event(self, record: dict[str, Any]) -> None: ...


class ToolDenied(Exception):
    def __init__(self, rule: str, reason: str) -> None:
        super().__init__(reason)
        self.rule = rule
        self.reason = reason


class ToolFailed(Exception):
    pass


def fill_path(template: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Substitute `{param}` segments; return the path and the arguments that were not used."""
    rest = dict(args)

    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key in rest:
            # Encoded, so a value can never add path segments: "../admin" arrives as "..%2Fadmin",
            # which the sidecar refuses (CONTRACT.md §5.1).
            return quote(str(rest.pop(key)), safe="")
        return ""

    path = re.sub(r"\{([a-zA-Z0-9_]+)\}", sub, template)
    scheme, sep, tail = path.partition("://")
    if not sep:
        scheme, tail = "", path
    tail = re.sub(r"/{2,}", "/", tail)
    if len(tail) > 1 and tail.endswith("/"):
        tail = tail[:-1]
    return f"{scheme}{sep}{tail}", rest


def _encode_query(args: dict[str, Any]) -> str:
    from urllib.parse import urlencode

    return urlencode({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in args.items()})


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
                path = f"{path}?{_encode_query(rest)}"
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
            url = f"{url}?{_encode_query(rest)}"
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
