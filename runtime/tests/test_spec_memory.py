"""Memory exists only for agents with learning enabled (design §3, CONTRACT.md §4.3)."""

from __future__ import annotations

from typing import Any

from agentsc_runtime.spec import AgentSpec

BASE: dict[str, Any] = {"name": "support", "model": "mock", "system": "You help customers."}
NOTES = [{"id": "n1", "text": "Ask for the order id first."}, {"id": "n2", "text": "Refunds take 5 days."}]


def test_a_learning_agent_keeps_its_notes_in_order():
    spec = AgentSpec.model_validate({**BASE, "learning": {"enabled": True}, "memory": NOTES})
    assert [n.id for n in spec.memory] == ["n1", "n2"]


def test_notes_for_an_agent_without_learning_never_reach_it():
    # learning switched off, or absent (the defaults: off): the notes are dropped
    for learning in ({"enabled": False}, {"enabled": False, "mode": "review", "max_notes": 5}, None):
        data = {**BASE, "memory": NOTES}
        if learning is not None:
            data["learning"] = learning
        spec = AgentSpec.model_validate(data)
        assert spec.learning.enabled is False
        assert spec.memory == [], learning


def test_a_spec_without_memory_is_unchanged():
    spec = AgentSpec.model_validate({**BASE, "learning": {"enabled": True}})
    assert spec.memory == []
    spec = AgentSpec.model_validate(BASE)
    assert spec.memory == []
    assert AgentSpec.model_validate(spec.model_dump()) == spec
