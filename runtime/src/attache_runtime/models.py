"""Model providers: the Anthropic API when ANTHROPIC_API_KEY is set, else a deterministic mock (CONTRACT.md §9)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

STOPWORDS = {
    "the",
    "and",
    "for",
    "are",
    "with",
    "that",
    "this",
    "from",
    "have",
    "what",
    "how",
    "many",
    "much",
    "about",
    "should",
    "please",
    "can",
    "you",
    "our",
    "your",
    "its",
    "into",
    "when",
    "will",
    "does",
    "did",
    "get",
    "ask",
    "tell",
    "all",
    "any",
    "one",
    "use",
    "used",
    "using",
    "level",
    "levels",
    "service",
    "agent",
    "tool",
    "call",
}


@dataclass
class ModelResponse:
    content: list[dict[str, Any]]
    stop_reason: str
    input_tokens: int
    output_tokens: int
    raw: Any = field(default=None, repr=False)

    def text(self) -> str:
        return "".join(b.get("text", "") for b in self.content if b.get("type") == "text")

    def tool_uses(self) -> list[dict[str, Any]]:
        return [b for b in self.content if b.get("type") == "tool_use"]


class Model(Protocol):
    name: str
    provider: str

    def complete(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int
    ) -> ModelResponse: ...


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower().replace("_", " ")) if len(w) >= 3 and w not in STOPWORDS}


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class MockModel:
    """Deterministic, offline. Picks the single best-matching tool on the first turn, then summarises."""

    provider = "mock"

    def __init__(self, name: str = "mock") -> None:
        self.name = name
        self._counter = 0

    @staticmethod
    def pick_tool(user_input: str, tools: list[dict[str, Any]]) -> dict[str, Any] | None:
        words = _words(user_input)
        best, best_score = None, 0
        for tool in tools:  # declaration order breaks ties
            score = len(words & _words(f"{tool['name']} {tool.get('description', '')}"))
            if score > best_score:
                best, best_score = tool, score
        return best

    @staticmethod
    def fill_arguments(user_input: str, schema: dict[str, Any]) -> dict[str, Any]:
        props: dict[str, Any] = schema.get("properties", {}) or {}
        required = set(schema.get("required", []) or [])
        ident = re.search(r"\b[A-Z][A-Z0-9]*-\d+\b", user_input) or re.search(r"\b\d{3,}\b", user_input)
        args: dict[str, Any] = {}
        for name, prop in props.items():
            typ = prop.get("type", "string")
            lname = name.lower()
            if lname in {"input", "question", "query", "prompt", "text", "message", "task"}:
                args[name] = user_input
            elif lname in {"sku", "id", "order_id", "product_id", "item", "item_id", "customer_id"}:
                if ident:
                    args[name] = ident.group(0)
                elif name in required:
                    args[name] = "unknown"
            elif typ in {"integer", "number"}:
                if name in required:
                    args[name] = 1
            elif typ == "boolean":
                if name in required:
                    args[name] = True
            elif name in required:
                args[name] = user_input
        return args

    def complete(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int
    ) -> ModelResponse:
        user_input = ""
        tool_results: list[tuple[str, str]] = []
        tool_names: dict[str, str] = {}
        for m in messages:
            content = m.get("content")
            if m.get("role") == "assistant" and isinstance(content, list):
                for b in content:
                    if b.get("type") == "tool_use":
                        tool_names[b["id"]] = b["name"]
            if m.get("role") != "user":
                continue
            if isinstance(content, str):
                if not user_input:
                    user_input = content
            elif isinstance(content, list):
                for b in content:
                    if b.get("type") == "text" and not user_input:
                        user_input = b.get("text", "")
                    elif b.get("type") == "tool_result":
                        c = b.get("content")
                        text = c if isinstance(c, str) else "".join(x.get("text", "") for x in (c or []))
                        tool_results.append((tool_names.get(b.get("tool_use_id", ""), "tool"), text))
        prompt_tokens = _estimate_tokens(system) + sum(_estimate_tokens(str(m.get("content"))) for m in messages)

        if tool_results:
            parts = [f"{name}: {text[:600]}" for name, text in tool_results]
            text = "Based on " + "; ".join(parts)
            return ModelResponse([{"type": "text", "text": text}], "end_turn", prompt_tokens, _estimate_tokens(text))

        tool = self.pick_tool(user_input, tools) if tools else None
        if tool is None:
            text = f"Mock answer for: {user_input}"
            return ModelResponse([{"type": "text", "text": text}], "end_turn", prompt_tokens, _estimate_tokens(text))

        self._counter += 1
        args = self.fill_arguments(user_input, tool.get("input_schema", {}))
        block = {"type": "tool_use", "id": f"toolu_mock_{self._counter}", "name": tool["name"], "input": args}
        return ModelResponse([block], "tool_use", prompt_tokens, _estimate_tokens(str(args)) + 8)


class AnthropicModel:
    provider = "anthropic"

    def __init__(self, name: str) -> None:
        import anthropic

        self.name = name
        self._client = anthropic.Anthropic()

    def complete(
        self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], max_tokens: int
    ) -> ModelResponse:
        kwargs: dict[str, Any] = {"model": self.name, "max_tokens": max_tokens, "messages": messages}
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        # Budgets are small by design; keep reasoning short. Older SDKs without output_config fall back.
        try:
            resp = self._client.messages.create(**kwargs, output_config={"effort": "low"})
        except TypeError:
            resp = self._client.messages.create(**kwargs)
        content = [b.model_dump(exclude_none=True) for b in resp.content]
        return ModelResponse(
            content, resp.stop_reason or "end_turn", resp.usage.input_tokens, resp.usage.output_tokens, raw=resp
        )


def anthropic_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def model_for(name: str) -> Model:
    if name == "mock" or not anthropic_available():
        return MockModel(name if name == "mock" else "mock")
    return AnthropicModel(name)
