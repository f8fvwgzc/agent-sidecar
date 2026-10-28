from __future__ import annotations

import json
from typing import Any

import pytest

from agentsc_runtime.spec import AgentSpec
from agentsc_runtime.tools import RULE_REPORT_REJECTED, CallContext, LessonOutcome, ReportOutcome, ToolDenied

STOCK = {"sku": "WIDGET-1", "on_hand": 42, "reorder_point": 50, "warehouse_contact": "ops-lead@example.com"}


class FakeSidecar:
    """Stands in for agentscd: records every call, denies /admin like the inventory charter does."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.contexts: list[CallContext] = []  # the ToolContext of every tool call
        self.lessons: list[tuple[CallContext, str, str, str]] = []
        self.report_rule: str | None = None  # what ReportEvent answers with (x-agentsc-rule)
        # Set: ReportEvent keeps to design §6.5 and refuses records of an Execute not in this set.
        self.in_flight: set[str] | None = None
        self.rejected: list[dict[str, Any]] = []
        self.lesson_outcome = LessonOutcome("allow", "learning.proposed", "")

    async def invoke_service(self, ctx: CallContext, tool: str, service: str, method: str, path: str, headers, body):
        self.contexts.append(ctx)
        self.calls.append(("service", (tool, service, method, path, body)))
        if path.startswith("/admin"):
            raise ToolDenied("authz.services.deny-admin", f"{method} {path} on {service} matches deny pattern")
        if path.startswith("/stock"):
            return 200, json.dumps(STOCK).encode()
        if path.startswith("/orders/"):
            return 200, json.dumps({"id": path.rsplit("/", 1)[-1], "sku": "WIDGET-1", "qty": 3}).encode()
        return 404, b"not found"

    async def invoke_agent(
        self, ctx: CallContext, tool: str, target_service: str, target_agent: str, input: str, context_json: str = ""
    ) -> str:
        self.contexts.append(ctx)
        self.calls.append(("agent", (tool, target_service, target_agent, input, context_json)))
        return f"{target_agent} says: WIDGET-1 has 42 on hand, reorder point 50, reorder now."

    async def invoke_http(self, ctx: CallContext, tool: str, method: str, url: str, headers, body):
        self.contexts.append(ctx)
        self.calls.append(("http", (tool, method, url, body)))
        return 200, b'{"ok": true}'

    async def report_event(self, record: dict[str, Any]) -> ReportOutcome:
        if self.in_flight is not None and record.get("request_id") not in self.in_flight:
            self.rejected.append(record)
            return ReportOutcome(RULE_REPORT_REJECTED, rejected=True)
        self.events.append(record)
        return ReportOutcome(self.report_rule)

    async def propose_lesson(self, ctx: CallContext, note: str, rationale: str, run_request_id: str) -> LessonOutcome:
        self.lessons.append((ctx, note, rationale, run_request_id))
        return self.lesson_outcome


@pytest.fixture
def sidecar() -> FakeSidecar:
    return FakeSidecar()


@pytest.fixture
def ops_assistant() -> AgentSpec:
    return AgentSpec.model_validate(
        {
            "name": "ops-assistant",
            "type": "orchestrator",
            "model": "mock",
            "system": "You are the ops assistant.",
            "tools": [
                {
                    "name": "lookup_order",
                    "description": "Look up an order by id in the orders service.",
                    "type": "service",
                    "service": "orders",
                    "method": "GET",
                    "path": "/orders/{order_id}",
                    "parameters": {
                        "type": "object",
                        "properties": {"order_id": {"type": "string"}},
                        "required": ["order_id"],
                    },
                },
                {
                    "name": "stock_analyst",
                    "description": "Ask the inventory service's stock analyst agent about stock levels, SKUs and reorder advice.",
                    "type": "agent",
                    "agent": "stock-analyst",
                    "service": "inventory",
                },
                {
                    "name": "inventory_admin_reset",
                    "description": "Reset the inventory admin counters (administrative, destructive).",
                    "type": "service",
                    "service": "inventory",
                    "method": "POST",
                    "path": "/admin/reset",
                },
            ],
            "budgets": {
                "max_tokens_per_call": 512,
                "max_calls_per_minute": 30,
                "max_cost_usd_per_day": 5.0,
                "max_steps": 4,
            },
        }
    )


@pytest.fixture
def ctx() -> CallContext:
    return CallContext("req-1", "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", "ops-assistant", 0)
