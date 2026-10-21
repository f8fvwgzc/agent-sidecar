import asyncio

import pytest

from attache_runtime import pricing
from attache_runtime.spec import ToolSpec
from attache_runtime.tools import ToolDenied, fill_path, run_tool, with_query


def test_pricing():
    assert pricing.cost_usd("mock", 1000, 1000) == 0.0
    assert pricing.cost_usd("claude-opus-5-5", 1_000_000, 0) == 4.0
    assert pricing.cost_usd("claude-opus-5-5", 0, 1_000_000) == 20.0
    assert pricing.cost_usd("claude-haiku-5-5", 100_000, 100_000) == 0.06
    assert pricing.cost_usd("unknown-model", 1_000_000, 0) == 10.0, "unknown models are priced at the top tier"


def test_fill_path():
    assert fill_path("/orders/{order_id}", {"order_id": "1001"}) == ("/orders/1001", {})
    assert fill_path("/stock/{sku}", {"sku": "W-1", "verbose": True}) == ("/stock/W-1", {"verbose": True})
    assert fill_path("https://x.io/{a}/b/{c}", {"a": "1", "c": "2"}) == ("https://x.io/1/b/2", {})
    assert fill_path("/orders/{id}/", {"id": 7}) == ("/orders/7/", {}), "the template is kept as written"
    assert fill_path("/files/{name}.json", {"name": "r"}) == ("/files/r.json", {})


def test_fill_path_optional_last_segment():
    assert fill_path("/stock/{sku?}", {}) == ("/stock", {})
    assert fill_path("/stock/{sku?}", {"sku": ""}) == ("/stock", {})
    assert fill_path("/stock/{sku?}", {"sku": None, "x": 1}) == ("/stock", {"x": 1})
    assert fill_path("/stock/{sku?}", {"sku": "W-1"}) == ("/stock/W-1", {})
    assert fill_path("/{x?}", {}) == ("/", {})
    assert fill_path("https://x.io/v1/items/{id?}", {}) == ("https://x.io/v1/items", {})
    with pytest.raises(ToolDenied):
        fill_path("/stock/{sku?}", {"sku": ".."})


@pytest.mark.parametrize("value", [None, "", ".", "..", "..."])
@pytest.mark.parametrize("template", ["/orders/{order_id}", "/orders/{order_id}/cancel", "https://x.io/{order_id}"])
def test_fill_path_refuses_values_that_drop_or_climb_a_segment(template, value):
    args = {} if value is None else {"order_id": value}
    with pytest.raises(ToolDenied) as e:
        fill_path(template, args)
    assert e.value.rule == "guardrail.tool_spec"


def test_query_templates_and_leftovers():
    assert fill_path("/search?q={term}", {"term": "a b", "page": 2}) == ("/search?q=a%20b", {"page": 2})
    assert fill_path("/search?q={term}", {}) == ("/search?q=", {}), "query values may be empty"
    assert fill_path("https://x.io/v1/{id}?k={k}", {"id": "7", "k": "v/w"}) == ("https://x.io/v1/7?k=v%2Fw", {})
    assert fill_path("/a/{x?}?q={y}", {"y": "1"}) == ("/a?q=1", {})
    assert with_query("/search?q=a", {"page": 2}) == "/search?q=a&page=2"
    assert with_query("/search?", {"page": 2}) == "/search?page=2"
    assert with_query("/stock/W-1", {"since": "2026/10/21"}) == "/stock/W-1?since=2026%2F10%2F21"


def test_bad_path_argument_is_a_tool_error_and_never_reaches_the_sidecar(sidecar, ctx):
    tool = ToolSpec(
        name="cancel_order",
        description="Cancel an order.",
        type="service",
        service="orders",
        method="DELETE",
        path="/orders/{order_id}",
    )
    out = asyncio.run(run_tool(tool, {"order_id": ""}, ctx, sidecar))
    assert out.is_error and out.decision == "deny" and out.rule == "guardrail.tool_spec"
    assert "order_id" in out.content
    assert sidecar.calls == []
    search = ToolSpec(
        name="search", description="Search.", type="service", service="orders", method="GET", path="/search?q={q}"
    )
    asyncio.run(run_tool(search, {"q": "a", "page": 2}, ctx, sidecar))
    assert sidecar.calls[-1][1][3] == "/search?q=a&page=2"


def test_fill_path_encodes_values_so_they_cannot_add_segments():
    assert fill_path("/stock/{sku}", {"sku": "../admin/reset"}) == ("/stock/..%2Fadmin%2Freset", {})
    assert fill_path("/stock/{sku}", {"sku": "%2e%2e"}) == ("/stock/%252e%252e", {})
    assert fill_path("/q/{term}", {"term": "a b?c#d"}) == ("/q/a%20b%3Fc%23d", {})


def test_haiku_long_prompt_tier():
    assert pricing.cost_usd("claude-haiku-5-5", 100_000, 0) == 0.01
    assert pricing.cost_usd("claude-haiku-5-5", 200_000, 0) == 0.1
