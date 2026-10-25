"""Model providers: the Anthropic API, or a deterministic mock for `model: mock` (CONTRACT.md §9).

Without ANTHROPIC_API_KEY a Claude model fails closed, unless AGENTSC_MOCK_FALLBACK=1 lets it run on the mock.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .prompts import NONE, NOTES_OPEN, REFLECTION_MARKER, TRANSCRIPT_CLOSE, TRANSCRIPT_OPEN
from .spec import LOAD_SKILL_TOOL

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


class ModelError(Exception):
    """A failed model call, with the usage the provider had reported when it failed (and may bill)."""

    def __init__(self, cause: Exception, input_tokens: int, output_tokens: int) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class Model(Protocol):
    name: str
    provider: str

    # `timeout`: seconds left for this call (None: the provider's default).
    def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        timeout: float | None = None,
    ) -> ModelResponse: ...


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower().replace("_", " ")) if len(w) >= 3 and w not in STOPWORDS}


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class MockModel:
    """Deterministic, offline. Loads the best-matching skill that is not inline, picks the single
    best-matching tool, then summarises; on the reflection prompt it writes a fixed-form note."""

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
    def pick_skill(user_input: str, load_skill: dict[str, Any]) -> str | None:
        """The skill offered by `load_skill` whose name and description share the most words with the
        input (ties: the order offered), or None when none shares a word."""
        schema = load_skill.get("input_schema") or {}
        names = ((schema.get("properties") or {}).get("name") or {}).get("enum") or []
        described: dict[str, str] = {}
        for line in str(load_skill.get("description", "")).splitlines():
            if m := re.match(r"- ([a-z0-9-]+): (.*)", line):
                described[m.group(1)] = m.group(2)
        words = _words(user_input)
        best, best_score = None, 0
        for name in names:
            if not isinstance(name, str):
                continue
            score = len(words & _words(f"{name} {described.get(name, '')}"))
            if score > best_score:
                best, best_score = name, score
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

    @staticmethod
    def reflect(system: str, transcript: str) -> str:
        """A note drawn from the reflection transcript by fixed rules: a refused tool call, else the
        first tool used and the input it answered, else a run that ended denied or in error, else NONE."""
        limit = int(m.group(1)) if (m := re.search(r"at most (\d+) characters", system)) else 500
        body = transcript.split(TRANSCRIPT_OPEN, 1)[-1].split(TRANSCRIPT_CLOSE, 1)[0]
        asked = next((line[len("input: ") :] for line in body.splitlines() if line.startswith("input: ")), "")
        if denied := re.search(r"^result (\S+) \(error\): denied by (\S+?):", body, re.MULTILINE):
            note = f"{denied.group(1)} is refused by {denied.group(2)}: answer without it or say it is not allowed."
        elif used := next(
            (m for m in re.finditer(r"^call (\S+): ", body, re.MULTILINE) if m.group(1) != LOAD_SKILL_TOOL), None
        ):
            note = f"Use {used.group(1)} for requests like: {' '.join(asked.split())}"
        elif ended := re.search(r"^outcome: (denied|error) \(([^)\s]+)\)", body, re.MULTILINE):
            note = f"Runs like this one end {ended.group(1)} with rule {ended.group(2)}."
        else:
            return NONE
        return note[: max(1, limit)].rstrip()

    def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        timeout: float | None = None,
    ) -> ModelResponse:
        user_input = ""
        tool_results: list[tuple[str, str]] = []
        tool_names: dict[str, str] = {}
        loaded: list[str] = []
        for m in messages:
            content = m.get("content")
            if m.get("role") == "assistant" and isinstance(content, list):
                for b in content:
                    if b.get("type") == "tool_use":
                        tool_names[b["id"]] = b["name"]
                        if b["name"] == LOAD_SKILL_TOOL and isinstance(b.get("input"), dict):
                            loaded.append(str(b["input"].get("name")))
            if m.get("role") != "user":
                continue
            if isinstance(content, str):
                if not user_input:
                    user_input = content
            elif isinstance(content, list):
                for b in content:
                    if b.get("type") == "text":
                        text = b.get("text", "")
                        if not user_input and not text.startswith(NOTES_OPEN):  # memory is not the question
                            user_input = text
                    elif b.get("type") == "tool_result":
                        name = tool_names.get(b.get("tool_use_id", ""), "tool")
                        if name == LOAD_SKILL_TOOL:  # skill instructions, not an answer to summarise
                            continue
                        c = b.get("content")
                        text = c if isinstance(c, str) else "".join(x.get("text", "") for x in (c or []))
                        tool_results.append((name, text))
        prompt_tokens = _estimate_tokens(system) + sum(_estimate_tokens(str(m.get("content"))) for m in messages)

        if system.startswith(REFLECTION_MARKER):
            text = self.reflect(system, user_input)
            return ModelResponse([{"type": "text", "text": text}], "end_turn", prompt_tokens, _estimate_tokens(text))

        if tool_results:
            parts = [f"{name}: {text[:600]}" for name, text in tool_results]
            text = "Based on " + "; ".join(parts)
            return ModelResponse([{"type": "text", "text": text}], "end_turn", prompt_tokens, _estimate_tokens(text))

        skill_tool = next((t for t in tools if t["name"] == LOAD_SKILL_TOOL), None)
        skill = self.pick_skill(user_input, skill_tool) if skill_tool else None
        if skill is not None and skill not in loaded:
            return self._use(LOAD_SKILL_TOOL, {"name": skill}, prompt_tokens)

        plain = [t for t in tools if t["name"] != LOAD_SKILL_TOOL]
        tool = self.pick_tool(user_input, plain) if plain else None
        if tool is None:
            text = f"Mock answer for: {user_input}"
            if loaded:
                text += f" (with skill {', '.join(loaded)})"
            return ModelResponse([{"type": "text", "text": text}], "end_turn", prompt_tokens, _estimate_tokens(text))
        return self._use(tool["name"], self.fill_arguments(user_input, tool.get("input_schema", {})), prompt_tokens)

    def _use(self, name: str, args: dict[str, Any], prompt_tokens: int) -> ModelResponse:
        self._counter += 1
        block = {"type": "tool_use", "id": f"toolu_mock_{self._counter}", "name": name, "input": args}
        return ModelResponse([block], "tool_use", prompt_tokens, _estimate_tokens(str(args)) + 8)


_client: Any = None
_client_lock = threading.Lock()


def anthropic_client() -> Any:
    """The one Anthropic client of this process, created on first use and reused by every Execute
    (connection pool included). `max_retries=0`: the harness owns retries (design §12)."""
    global _client
    with _client_lock:
        if _client is None:
            import anthropic

            _client = anthropic.Anthropic(max_retries=0)
        return _client


def set_anthropic_client(client: Any) -> Any:
    """Replace the process-wide client (tests inject one; None makes the next use create it). Returns
    the previous one."""
    global _client
    with _client_lock:
        previous, _client = _client, client
    return previous


class AnthropicModel:
    provider = "anthropic"

    def __init__(self, name: str, client: Any = None) -> None:
        self.name = name
        self._client = client  # None: the process-wide client

    def client(self) -> Any:
        own = getattr(self, "_client", None)
        return own if own is not None else anthropic_client()

    def complete(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        timeout: float | None = None,
    ) -> ModelResponse:
        kwargs: dict[str, Any] = {"model": self.name, "max_tokens": max_tokens, "messages": messages}
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        if supports_effort(self.name):
            # Budgets are small by design; keep reasoning short.
            kwargs["output_config"] = {"effort": "low"}
        # `timeout` is the whole attempt's time (design §12). The SDK's timeout bounds the connect and each
        # wait for the next chunk; the loop below ends a stream that is still sending when time is up, at
        # its first event after that (the SDK swallows `ping` events, so pings alone do not end it).
        ends = None if timeout is None else time.monotonic() + timeout
        if timeout is not None:
            kwargs["timeout"] = timeout
        # Streaming, collected into one message: the SDK refuses large non-streaming max_tokens,
        # and a stream never hits the HTTP read timeout on a long turn.
        stream = None
        try:
            with self.client().messages.stream(**kwargs) as stream:
                for _ in stream:
                    if ends is not None and time.monotonic() > ends:
                        raise _timed_out(stream)
                resp = stream.get_final_message()
        except Exception as e:
            raise ModelError(_sdk_error(e, stream), *_usage_so_far(stream)) from e
        content = [b.model_dump(exclude_none=True) for b in resp.content]
        return ModelResponse(
            content, resp.stop_reason or "end_turn", resp.usage.input_tokens, resp.usage.output_tokens, raw=resp
        )


def _request_of(stream: Any) -> Any:
    try:
        return stream.response.request
    except (AttributeError, RuntimeError):
        return None


def _timed_out(stream: Any) -> Exception:
    """The SDK's own timeout error for an attempt that ran out of time mid-stream (the harness retries
    it like any APITimeoutError); the stream is closed on the way out."""
    import anthropic

    return anthropic.APITimeoutError(request=_request_of(stream))


def _sdk_error(err: Exception, stream: Any) -> Exception:
    """A transport failure while reading the stream (a read timeout, a dropped connection), which the SDK
    lets through from its HTTP library, as the SDK class it raises for the same failure before the
    response: APITimeoutError or APIConnectionError. Anything else unchanged."""
    import anthropic

    names = {c.__name__ for c in type(err).__mro__}
    if isinstance(err, anthropic.APIError) or "TransportError" not in names:
        return err
    request = _request_of(stream)
    if "TimeoutException" in names:
        mapped: Exception = anthropic.APITimeoutError(request=request)
    else:
        mapped = anthropic.APIConnectionError(message=f"{type(err).__name__}: {err}", request=request)
    mapped.__cause__ = err
    return mapped


def _usage_so_far(stream: Any) -> tuple[int, int]:
    """Tokens the API had reported when a stream broke: none before `message_start`, then its input
    count and the output count it last sent (the full output count only comes in the final delta)."""
    if stream is None:
        return 0, 0
    try:
        usage = stream.current_message_snapshot.usage
    except (AssertionError, AttributeError):  # no message_start yet
        return 0, 0
    return usage.input_tokens or 0, usage.output_tokens or 0


# Models that reject output_config.effort (CONTRACT.md §9). Everything newer accepts it.
_NO_EFFORT_PREFIXES = (
    "claude-haiku-4-5",
    "claude-sonnet-4-5",
    "claude-opus-4-1",
    "claude-opus-4-0",
    "claude-sonnet-4-0",
    "claude-3",
)


def supports_effort(model: str) -> bool:
    return not model.startswith(_NO_EFFORT_PREFIXES)


def anthropic_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def mock_fallback() -> bool:
    """AGENTSC_MOCK_FALLBACK=1: without ANTHROPIC_API_KEY, run every agent on the mock (demos, CI)."""
    return os.environ.get("AGENTSC_MOCK_FALLBACK") == "1"


def provider() -> str:
    """What a non-mock agent runs on: `anthropic`, `mock` (the fallback), or `none` (it is refused)."""
    if anthropic_available():
        return "anthropic"
    return "mock" if mock_fallback() else "none"


class ModelUnavailable(Exception):
    """A Claude model was asked for, and there is no ANTHROPIC_API_KEY and no mock fallback."""


def model_for(name: str) -> Model:
    if name == "mock":
        return MockModel("mock")
    if anthropic_available():
        return AnthropicModel(name)
    if mock_fallback():
        return MockModel("mock")
    raise ModelUnavailable(
        f"model {name!r} needs ANTHROPIC_API_KEY; set it, use `model: mock`, "
        "or set AGENTSC_MOCK_FALLBACK=1 to run on the deterministic mock"
    )
