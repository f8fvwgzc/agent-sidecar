"""USD per 1M tokens (Anthropic API list prices, cached 2026-10-06). `mock` costs nothing."""

PRICES: dict[str, tuple[float, float]] = {
    "claude-fable-5-1": (10.00, 50.00),
    "claude-fable-5": (10.00, 50.00),
    "claude-opus-5-5": (4.00, 20.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-haiku-4-5": (1.00, 5.00),
    "mock": (0.0, 0.0),
}

# Unknown model ids are priced like the most expensive tier so a budget never under-counts.
_FALLBACK = (10.00, 50.00)


def cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    inp, out = PRICES.get(model, _FALLBACK)
    return round((input_tokens * inp + output_tokens * out) / 1_000_000, 6)
