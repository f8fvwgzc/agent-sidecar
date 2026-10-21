"""agent_spec_json since v0.2: resolved skills, harness, learning and memory (CONTRACT.md §4.3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from agentsc_runtime.spec import LOAD_SKILL_TOOL, AgentSpec, Harness, Learning

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


def test_partial_blocks_are_filled_with_defaults():
    spec = AgentSpec.model_validate({**V01, "harness": {"max_retries": 5}, "learning": {"enabled": True}})
    assert spec.harness.max_retries == 5 and spec.harness.request_timeout_seconds == 120
    assert spec.learning.enabled and spec.learning.max_notes == 20


@pytest.mark.parametrize(
    ("where", "patch"),
    [
        ("top level", {"notes": []}),
        ("skills[]", {"skills": [{"name": "s", "description": "d", "instructions": "i", "inline": True, "tools": []}]}),
        ("harness", {"harness": {"max_retry": 1}}),
        ("learning", {"learning": {"auto": True}}),
        ("memory[]", {"memory": [{"id": "n1", "text": "t", "source": "auto"}]}),
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
