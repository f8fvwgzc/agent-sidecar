from attache_runtime.models import MockModel, model_for


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


def test_model_for_falls_back_to_mock_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    m = model_for("claude-opus-5-5")
    assert m.provider == "mock"
    assert model_for("mock").name == "mock"
