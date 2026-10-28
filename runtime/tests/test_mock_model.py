import pytest

from agentsc_runtime.models import MockModel, ModelUnavailable, model_for, provider
from agentsc_runtime.prompts import load_skill_tool, reflection_system
from agentsc_runtime.spec import Skill


def tool(name: str, desc: str, props=None, required=None):
    return {
        "name": name,
        "description": desc,
        "input_schema": {"type": "object", "properties": props or {}, "required": required or []},
    }


TOOLS = [
    tool(
        "lookup_order", "Look up an order by id in the orders service.", {"order_id": {"type": "string"}}, ["order_id"]
    ),
    tool(
        "stock_analyst",
        "Ask the inventory service's stock analyst agent about stock levels, SKUs and reorder advice.",
        {"input": {"type": "string"}},
        ["input"],
    ),
    tool("inventory_admin_reset", "Reset the inventory admin counters (administrative, destructive).", {}),
]


def test_picks_the_best_matching_tool_deterministically():
    assert (
        MockModel.pick_tool("How many WIDGET-1 do we have in stock and should we reorder?", TOOLS)["name"]
        == "stock_analyst"
    )
    assert MockModel.pick_tool("Reset the inventory admin counters", TOOLS)["name"] == "inventory_admin_reset"
    assert MockModel.pick_tool("Show me order 1001", TOOLS)["name"] == "lookup_order"
    assert MockModel.pick_tool("hello there", TOOLS) is None


def test_fills_arguments_heuristically():
    args = MockModel.fill_arguments("Show me order 1001", TOOLS[0]["input_schema"])
    assert args == {"order_id": "1001"}
    args = MockModel.fill_arguments("How many WIDGET-1 in stock?", TOOLS[1]["input_schema"])
    assert args == {"input": "How many WIDGET-1 in stock?"}
    sku_schema = {"type": "object", "properties": {"sku": {"type": "string"}}}
    assert MockModel.fill_arguments("How many WIDGET-1 in stock?", sku_schema) == {"sku": "WIDGET-1"}
    assert MockModel.fill_arguments("all stock please", sku_schema) == {}


def test_two_turn_conversation():
    m = MockModel()
    first = m.complete("sys", [{"role": "user", "content": "How many WIDGET-1 in stock?"}], TOOLS, 256)
    assert first.stop_reason == "tool_use"
    use = first.tool_uses()[0]
    assert use["name"] == "stock_analyst"
    msgs = [
        {"role": "user", "content": "How many WIDGET-1 in stock?"},
        {"role": "assistant", "content": first.content},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use["id"], "content": "42 on hand"}]},
    ]
    second = m.complete("sys", msgs, TOOLS, 256)
    assert second.stop_reason == "end_turn"
    assert second.text() == "Based on stock_analyst: 42 on hand"
    assert second.input_tokens > 0 and second.output_tokens > 0


def test_model_for_fails_closed_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AGENTSC_MOCK_FALLBACK", raising=False)
    with pytest.raises(ModelUnavailable, match="ANTHROPIC_API_KEY"):
        model_for("claude-opus-5-5")
    assert provider() == "none"
    assert model_for("mock").name == "mock", "model: mock never needs a key"


def test_model_for_falls_back_to_mock_only_when_asked(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("AGENTSC_MOCK_FALLBACK", "1")
    m = model_for("claude-opus-5-5")
    assert m.provider == "mock" and m.name == "mock"
    assert provider() == "mock"
    monkeypatch.setenv("AGENTSC_MOCK_FALLBACK", "true")
    with pytest.raises(ModelUnavailable):
        model_for("claude-opus-5-5")


def load_skill(*skills: tuple[str, str]) -> dict:
    return load_skill_tool([Skill(name=n, description=d, instructions="x" * 2048, inline=False) for n, d in skills])


def test_picks_the_best_matching_skill_deterministically():
    tool = load_skill(
        ("refund-policy", "How to decide whether a refund is allowed."), ("escalation", "Hand to a human.")
    )
    assert MockModel.pick_skill("Is a refund allowed for order 7?", tool) == "refund-policy"
    assert MockModel.pick_skill("I want a human now", tool) == "escalation"
    assert MockModel.pick_skill("hello there", tool) is None
    assert MockModel.pick_skill("refund", {"name": "load_skill"}) is None, "a malformed tool offers nothing"


def test_loads_a_skill_once_then_uses_a_tool_then_answers():
    m = MockModel()
    tools = [*TOOLS, load_skill(("stock-rules", "Rules for stock questions."))]
    msgs: list[dict] = [{"role": "user", "content": "How many WIDGET-1 in stock?"}]
    first = m.complete("sys", msgs, tools, 256)
    assert first.tool_uses() == [
        {"type": "tool_use", "id": "toolu_mock_1", "name": "load_skill", "input": {"name": "stock-rules"}}
    ]
    msgs += [
        {"role": "assistant", "content": first.content},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_mock_1", "content": "RULES"}]},
    ]
    second = m.complete("sys", msgs, tools, 256)
    assert [u["name"] for u in second.tool_uses()] == ["stock_analyst"], "the skill is loaded once"
    use = second.tool_uses()[0]
    msgs += [
        {"role": "assistant", "content": second.content},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use["id"], "content": "42"}]},
    ]
    assert m.complete("sys", msgs, tools, 256).text() == "Based on stock_analyst: 42", "skill text is not summarised"


def test_answers_with_the_skill_named_when_no_tool_fits():
    m = MockModel()
    tools = [load_skill(("greeting", "How to greet visitors politely."))]
    msgs: list[dict] = [{"role": "user", "content": "greet the visitors"}]
    first = m.complete("sys", msgs, tools, 256)
    msgs += [
        {"role": "assistant", "content": first.content},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_mock_1", "content": "Say hi."}]},
    ]
    assert m.complete("sys", msgs, tools, 256).text() == "Mock answer for: greet the visitors (with skill greeting)"


BOTH = ["invariant", "domain"]


def reflection(system: str, *lines: str) -> str:
    transcript = "\n".join(["<transcript>", "agent: a", "caller: local", *lines, "</transcript>"])
    return MockModel().complete(system, [{"role": "user", "content": transcript}], [], 256).text()


def test_reflection_lessons_are_deterministic():
    system = reflection_system(80, BOTH, True)
    denied = reflection(
        system,
        "input: Reset it",
        "s1 call reset: {}",
        "s2 result reset (error): denied by authz.services.deny-admin: no",
        "s3 outcome: ok",
    )
    full = "reset is refused by authz.services.deny-admin: answer without it or say it is not allowed."
    assert len(full) > 80, "held to the limit the prompt names"
    assert denied == f"SCOPE: domain\nTARGET: tool:reset\nEVIDENCE: s2\nNOTE: {full[:80].rstrip()}"
    used = reflection(
        system,
        "input: How   many\tWIDGET-1?",
        "s1 call load_skill: {}",
        "s2 result load_skill: (skill instructions)",
        "s3 call ask_caller: {}",
        "s4 call stock: {}",
        "s5 outcome: ok",
    )
    assert (
        used == "SCOPE: domain\nTARGET: tool:stock\nEVIDENCE: s4\nNOTE: Use stock for requests like: How many WIDGET-1?"
    )
    ended = reflection(system, "input: x", "s1 outcome: error (budget.max_steps): too long")
    assert ended == (
        "SCOPE: invariant\nTARGET: notes\nEVIDENCE: s1\nNOTE: Runs like this one end error with rule budget.max_steps."
    )
    cut_off = reflection(system, "input: x", "s1 call stock (not run): {}", "s2 outcome: error (budget.max_tokens)")
    assert cut_off.splitlines()[:3] == ["SCOPE: invariant", "TARGET: notes", "EVIDENCE: s2"], "a call not run is unused"
    assert reflection(system, "input: hi", "s1 outcome: ok") == "NONE"


def test_the_mock_reflection_keeps_to_the_one_scope_the_prompt_allows():
    only_invariant = reflection_system(500, ["invariant"], True)
    used = reflection(only_invariant, "input: stock?", "s1 call stock: {}", "s2 outcome: ok")
    assert used.splitlines()[0] == "SCOPE: invariant"
    only_domain = reflection_system(500, ["domain"], False)
    ended = reflection(only_domain, "input: x", "s1 outcome: denied (model.refusal)")
    assert ended.splitlines()[:3] == ["SCOPE: domain", "TARGET: notes", "EVIDENCE: s1"]
