"""agent_spec_json since v0.2: resolved skills, harness, learning and memory (CONTRACT.md §4.3), and since
level 6 the practices and the evidence-backed learning fields (agent-practices design)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsc_runtime.spec import (
    AGENT_TOOL_PARAMETERS,
    ASK_CALLER_TOOL,
    LOAD_SKILL_TOOL,
    AgentSpec,
    Harness,
    Learning,
    Practices,
    ToolSpec,
)

# Written by the Rust side (`Charter::runtime_spec`, kept in sync by a cargo test): the same file
# is what the sidecar sends, so the two sides cannot drift apart unnoticed.
EXAMPLE = Path(__file__).resolve().parents[2] / "schemas" / "runtime-agent-spec.example.json"

# What a v0.1 sidecar sends: the charter's agent entry after allowed_tools, nothing else.
V01 = {
    "name": "stock-analyst",
    "type": "agent",
    "model": "mock",
    "system": "You answer questions about stock levels.",
    "tools": [
        {
            "name": "get_stock",
            "description": "Get stock for one SKU.",
            "type": "service",
            "service": "inventory",
            "method": "GET",
            "path": "/stock/{sku}",
        }
    ],
    "budgets": {"max_tokens_per_call": 1024, "max_calls_per_minute": 60, "max_cost_usd_per_day": 2.0, "max_steps": 4},
}


def example() -> dict[str, Any]:
    return json.loads(EXAMPLE.read_text())


def test_agent_tools_default_to_the_parameters_the_sidecar_fills():
    """The sidecar fills the `parameters` of an agent tool that declares none (Rust `agent_tool_parameters`):
    `input` and an optional `context` object (CONTRACT.md §3.1). A spec without them means the same."""
    triage = next(t for t in example()["tools"] if t["type"] == "agent")
    assert triage["parameters"] == AGENT_TOOL_PARAMETERS
    assert AGENT_TOOL_PARAMETERS["required"] == ["input"]
    assert AGENT_TOOL_PARAMETERS["properties"]["context"]["type"] == "object"
    bare = ToolSpec.model_validate({k: v for k, v in triage.items() if k != "parameters"})
    assert bare.input_schema() == triage["parameters"]
    bare.input_schema()["required"].append("context")
    assert bare.input_schema()["required"] == ["input"], "each call gets its own copy"
    own = {"type": "object", "properties": {"order": {"type": "string"}}}
    assert ToolSpec.model_validate({**triage, "parameters": own}).input_schema() == own


def test_the_sidecars_v02_spec_parses():
    spec = AgentSpec.model_validate_json(EXAMPLE.read_text())
    assert spec.name == "support"
    assert [s.name for s in spec.skills] == ["refund-policy", "escalation"]
    assert [s.name for s in spec.inline_skills()] == ["refund-policy"]
    assert [s.name for s in spec.loadable_skills()] == ["escalation"]
    refund = spec.skill("refund-policy")
    assert refund is not None and refund.instructions.startswith("Look up the order")
    assert spec.skill("nope") is None
    assert spec.harness.fallback_model == "claude-haiku-5-5"
    assert spec.harness.max_retries == 2
    assert spec.learning.enabled is True and spec.learning.mode == "review"
    assert [n.text for n in spec.memory] == [
        "Orders older than 30 days are never refunded.",
        "Ask for the order id before looking anything up.",
    ], "oldest first, as sent"
    assert spec.tool("get_order") is not None
    assert LOAD_SKILL_TOOL not in {t.name for t in spec.tools}
    assert ASK_CALLER_TOOL not in {t.name for t in spec.tools}
    assert spec.practices == Practices()
    assert (spec.learning.require_evidence, spec.learning.contrast_runs, spec.learning.scopes) == (
        True,
        5,
        ["invariant", "domain"],
    )


def test_the_golden_spec_sends_every_practice_and_learning_field():
    data = example()
    assert data["practices"] == {
        "plan": True,
        "clarify": "blocking",
        "max_questions": 5,
        "brevity": "lite",
        "agent_brevity": "full",
        "auto_clarity": True,
    }
    assert data["practices"] == Practices().model_dump()
    learning = data["learning"]
    assert {k: learning[k] for k in ("require_evidence", "contrast_runs", "scopes")} == {
        "require_evidence": True,
        "contrast_runs": 5,
        "scopes": ["invariant", "domain"],
    }
    assert learning == {**Learning().model_dump(), "enabled": True}


def test_inline_follows_the_size_rule_in_the_example():
    for skill in example()["skills"]:
        assert skill["inline"] == (len(skill["instructions"].encode()) < 2048), skill["name"]


def test_a_v01_spec_gets_the_v02_defaults():
    spec = AgentSpec.model_validate(V01)
    assert spec.skills == [] and spec.memory == []
    assert spec.harness == Harness()
    assert (
        spec.harness.max_retries,
        spec.harness.request_timeout_seconds,
        spec.harness.fallback_model,
        spec.harness.tool_result_max_chars,
    ) == (2, 120, None, 20000)
    assert spec.learning == Learning()
    assert (
        spec.learning.enabled,
        spec.learning.mode,
        spec.learning.max_notes,
        spec.learning.max_note_chars,
        spec.learning.note_ttl_days,
        spec.learning.from_peers,
        spec.learning.max_proposals_per_hour,
    ) == (False, "review", 20, 500, 7, False, 10)


def test_a_spec_without_the_level_4_fields_gets_the_rust_defaults():
    # the defaults of PracticesSpec and LearningSpec::*_or_default in crates/agentsc-charter
    spec = AgentSpec.model_validate(V01)
    assert spec.practices == Practices()
    assert (
        spec.practices.plan,
        spec.practices.clarify,
        spec.practices.max_questions,
        spec.practices.brevity,
        spec.practices.agent_brevity,
        spec.practices.auto_clarity,
    ) == (True, "blocking", 5, "lite", "full", True)
    assert (spec.learning.require_evidence, spec.learning.contrast_runs, spec.learning.scopes) == (
        True,
        5,
        ["invariant", "domain"],
    )
    # each spec gets its own list
    other = AgentSpec.model_validate(V01)
    other.learning.scopes.append("domain")
    assert spec.learning.scopes == ["invariant", "domain"]
    assert ASK_CALLER_TOOL == "ask_caller"


def test_partial_blocks_are_filled_with_defaults():
    spec = AgentSpec.model_validate({**V01, "harness": {"max_retries": 5}, "learning": {"enabled": True}})
    assert spec.harness.max_retries == 5 and spec.harness.request_timeout_seconds == 120
    assert spec.learning.enabled and spec.learning.max_notes == 20
    spec = AgentSpec.model_validate({**V01, "practices": {"brevity": "normal"}, "learning": {"scopes": ["domain"]}})
    assert spec.practices == Practices(brevity="normal")
    assert spec.practices.plan and spec.practices.clarify == "blocking" and spec.practices.auto_clarity
    assert spec.learning.scopes == ["domain"] and spec.learning.contrast_runs == 5


@pytest.mark.parametrize(
    ("where", "patch"),
    [
        ("top level", {"notes": []}),
        ("skills[]", {"skills": [{"name": "s", "description": "d", "instructions": "i", "inline": True, "tools": []}]}),
        ("harness", {"harness": {"max_retry": 1}}),
        ("learning", {"learning": {"auto": True}}),
        ("memory[]", {"memory": [{"id": "n1", "text": "t", "source": "auto"}]}),
        ("practices", {"practices": {"plans": True}}),
        ("practices", {"practices": {"text": "Be brief."}}),
        ("learning", {"learning": {"evidence": True}}),
    ],
)
def test_unknown_fields_are_rejected(where: str, patch: dict[str, Any]):
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AgentSpec.model_validate({**V01, **patch})


@pytest.mark.parametrize(
    "patch",
    [
        {"skills": [{"name": "s", "description": "d", "instructions": "i"}]},  # inline is required
        {"skills": ["refund-policy"]},  # names only: the sidecar always resolves skills
        {"learning": {"mode": "always"}},
        {"memory": [{"id": "n1"}]},
        {"practices": {"clarify": "sometimes"}},
        {"practices": {"clarify": "off"}},  # the old name of never
        {"practices": {"brevity": "caveman"}},
        {"practices": {"agent_brevity": False}},
        {"practices": {"brevity": "off"}},  # the old name of normal
        {"practices": {"agent_brevity": "off"}},
        {"practices": {"max_questions": "five"}},
        {"practices": "on"},
        {"learning": {"scopes": ["subject"]}},
        {"learning": {"scopes": "invariant"}},
        {"learning": {"contrast_runs": "many"}},
        {"learning": {"require_evidence": "maybe"}},
    ],
)
def test_malformed_new_fields_are_rejected(patch: dict[str, Any]):
    with pytest.raises(ValidationError):
        AgentSpec.model_validate({**V01, **patch})


def test_round_trip_keeps_every_field():
    data = example()
    spec = AgentSpec.model_validate(data)
    again = AgentSpec.model_validate(spec.model_dump())
    assert again == spec
    assert again.model_dump()["memory"] == data["memory"]
    assert again.model_dump()["skills"] == data["skills"]
    assert again.model_dump()["practices"] == data["practices"]
    assert again.model_dump()["learning"] == data["learning"]
