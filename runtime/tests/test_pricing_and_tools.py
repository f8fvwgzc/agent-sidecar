from attache_runtime import pricing
from attache_runtime.tools import fill_path


def test_pricing():
    assert pricing.cost_usd("mock", 1000, 1000) == 0.0
    assert pricing.cost_usd("claude-opus-5-5", 1_000_000, 0) == 4.0
    assert pricing.cost_usd("claude-opus-5-5", 0, 1_000_000) == 20.0
    assert pricing.cost_usd("claude-haiku-5-5", 1_000_000, 1_000_000) == 0.6
    assert pricing.cost_usd("unknown-model", 1_000_000, 0) == 10.0, "unknown models are priced at the top tier"


def test_fill_path():
    assert fill_path("/orders/{order_id}", {"order_id": "1001"}) == ("/orders/1001", {})
    assert fill_path("/stock/{sku}", {}) == ("/stock", {})
    assert fill_path("/stock/{sku}", {"sku": "W-1", "verbose": True}) == ("/stock/W-1", {"verbose": True})
    assert fill_path("https://x.io/{a}/b/{c}", {"a": "1", "c": "2"}) == ("https://x.io/1/b/2", {})
