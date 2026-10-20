"""The agent entry the sidecar sends in ExecuteRequest.agent_spec_json (CONTRACT.md §3, after allowed_tools)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Budgets(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_tokens_per_call: int = 1024
    max_calls_per_minute: int = 60
    max_cost_usd_per_day: float = 10.0
    max_steps: int = 8


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str
    type: Literal["service", "agent", "http"]
    parameters: dict[str, Any] | None = None
    service: str | None = None
    method: str | None = None
    path: str | None = None
    agent: str | None = None
    url: str | None = None

    def input_schema(self) -> dict[str, Any]:
        if self.parameters:
            return self.parameters
        if self.type == "agent":
            return {
                "type": "object",
                "properties": {"input": {"type": "string", "description": "What to ask the agent."}},
                "required": ["input"],
            }
        return {"type": "object", "properties": {}}

    def anthropic_tool(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema()}


class AgentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    name: str
    type: Literal["agent", "orchestrator"] = "agent"
    model: str
    system: str = ""
    tools: list[ToolSpec] = Field(default_factory=list)
    budgets: Budgets = Field(default_factory=Budgets)

    def tool(self, name: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.name == name), None)
