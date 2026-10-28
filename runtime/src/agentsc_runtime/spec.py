"""The agent entry the sidecar sends in ExecuteRequest.agent_spec_json (CONTRACT.md §3, after allowed_tools).

Since v0.2 the sidecar also sends the agent's resolved skills, its harness and learning settings
(defaults filled) and its active memory notes (CONTRACT.md §4.3, `Charter::runtime_spec`). Since
charter schema level 6 it always sends the agent's practices, every field filled, and three more
learning fields (`require_evidence`, `contrast_runs`, `scopes`; agent-practices design). The
defaults here are the Rust defaults, so a spec without them means the same thing. Every model here
forbids unknown fields, so a sidecar/runtime mismatch fails loudly instead of being ignored.
"""

from __future__ import annotations

import copy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Budgets(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_tokens_per_call: int = 1024
    max_calls_per_minute: int = 60
    max_cost_usd_per_day: float = 10.0
    max_steps: int = 8


# The `parameters` of an agent tool that declares none (CONTRACT.md §3.1): the question as `input`,
# and an optional `context` object the callee gets as its context, which is how a calling agent
# answers the callee's questions. The sidecar fills the same schema (Rust `agent_tool_parameters`).
AGENT_TOOL_PARAMETERS: dict[str, Any] = {
    "type": "object",
    "properties": {
        "input": {"type": "string", "description": "What to ask the agent."},
        "context": {
            "type": "object",
            "description": "Optional JSON the agent gets as its context. To answer questions it asked, call it again"
            ' with the same input and every answer so far here: {"answers": [{"question": "…", "answer": "…"}]}.',
        },
    },
    "required": ["input"],
}


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
            return copy.deepcopy(AGENT_TOOL_PARAMETERS)
        return {"type": "object", "properties": {}}

    def anthropic_tool(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema()}


class Skill(BaseModel):
    """A skill the agent uses, resolved by the sidecar. `inline`: instructions shorter than 2048 bytes,
    which go into the system prompt; the others are loaded on demand with the `load_skill` tool."""

    model_config = ConfigDict(extra="forbid")
    name: str
    description: str
    instructions: str
    inline: bool


class Harness(BaseModel):
    """Retries, timeouts and the fallback model (charter `agents[].harness`, defaults filled)."""

    model_config = ConfigDict(extra="forbid")
    max_retries: int = 2
    request_timeout_seconds: int = 120
    fallback_model: str | None = None
    tool_result_max_chars: int = 20000


LessonScope = Literal["invariant", "domain"]
Brevity = Literal["normal", "lite", "full", "ultra"]


class Learning(BaseModel):
    """Governed learning (charter `agents[].learning`, defaults filled). `require_evidence`: a lesson
    must cite the steps of the run it rests on; `contrast_runs`: how many digests of earlier runs the
    reflection sees (0 = none); `scopes`: the lesson scopes that are kept."""

    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    mode: Literal["review", "auto"] = "review"
    max_notes: int = 20
    max_note_chars: int = 500
    note_ttl_days: int = 7
    from_peers: bool = False
    max_proposals_per_hour: int = 10
    require_evidence: bool = True
    contrast_runs: int = 5
    scopes: list[LessonScope] = Field(default_factory=lambda: ["invariant", "domain"])


class Practices(BaseModel):
    """The working practices (charter `agents[].practices`, defaults filled; agent-practices design).
    Only switches and levels: the texts are the runtime's own, so these settings carry no
    instructions. `brevity` applies when the service's own app (or another local caller without a
    calling agent) is the caller, `agent_brevity` when another agent is."""

    model_config = ConfigDict(extra="forbid")
    plan: bool = True
    clarify: Literal["never", "blocking", "always"] = "blocking"
    max_questions: int = 5
    brevity: Brevity = "lite"
    agent_brevity: Brevity = "full"
    auto_clarity: bool = True


class MemoryNote(BaseModel):
    """An active note from earlier runs. It is data for the model, never an instruction."""

    model_config = ConfigDict(extra="forbid")
    id: str
    text: str


# The name of the tool the runtime offers for skills that are not inline (no charter tool may use it).
LOAD_SKILL_TOOL = "load_skill"
# The name of the tool the runtime offers when practices.clarify is not `never`: calling it ends the run
# with questions for the caller (no charter tool may use it).
ASK_CALLER_TOOL = "ask_caller"


class AgentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    name: str
    type: Literal["agent", "orchestrator"] = "agent"
    model: str
    system: str = ""
    tools: list[ToolSpec] = Field(default_factory=list)
    budgets: Budgets = Field(default_factory=Budgets)
    skills: list[Skill] = Field(default_factory=list)
    harness: Harness = Field(default_factory=Harness)
    learning: Learning = Field(default_factory=Learning)
    practices: Practices = Field(default_factory=Practices)
    memory: list[MemoryNote] = Field(default_factory=list)

    @model_validator(mode="after")
    def _memory_needs_learning(self) -> AgentSpec:
        """Memory exists only for agents with learning enabled (design §3): the sidecar sends none
        for the others, and should notes arrive anyway they never reach the model."""
        if not self.learning.enabled and self.memory:
            self.memory = []
        return self

    def tool(self, name: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.name == name), None)

    def skill(self, name: str) -> Skill | None:
        return next((s for s in self.skills if s.name == name), None)

    def inline_skills(self) -> list[Skill]:
        """Skills whose instructions go into the system prompt."""
        return [s for s in self.skills if s.inline]

    def loadable_skills(self) -> list[Skill]:
        """Skills the model loads with the `load_skill` tool."""
        return [s for s in self.skills if not s.inline]
