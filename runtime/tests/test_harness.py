"""The model-call harness (design §12): one client, retries by SDK error class, retry-after, backoff,
the Execute deadline, the per-attempt timeout and the fallback model."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any

import anthropic
import httpx2
import pytest

from agentsc_runtime import agent, harness, models
from agentsc_runtime.agent import run_agent
from agentsc_runtime.models import AnthropicModel, ModelError, ModelResponse
from agentsc_runtime.tools import HOP_MARGIN

REQ = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def status_error(cls: type[anthropic.APIStatusError], status: int, headers=None, body=None):
    return cls("boom", response=httpx2.Response(status, headers=headers or {}, request=REQ), body=body)


def overloaded_mid_stream() -> anthropic.APIStatusError:
    """What the SDK raises for an SSE `error` event after the stream started with HTTP 200."""
    body = {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}
    return status_error(anthropic.APIStatusError, 200, body=body)


def ok(text: str = "done", inp: int = 10, out: int = 2) -> ModelResponse:
    return ModelResponse([{"type": "text", "text": text}], "end_turn", inp, out)


class Scripted:
    """A provider model that plays a script: an exception (raised as ModelError with 7 input tokens
    billed) or a response per call. It records the timeout of every call."""

    provider = "anthropic"

    def __init__(self, name: str, script: list[Any]) -> None:
        self.name, self.script, self.timeouts = name, list(script), []
        self.headers: list[dict[str, str]] = []  # the run binding each call carried to the gateway

    def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
        self.timeouts.append(timeout)
        self.headers.append(dict(headers or {}))
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise ModelError(item, 7, 0)
        return item


@pytest.fixture
def waits(monkeypatch) -> list[float]:
    """The harness's waits between attempts, recorded instead of slept."""
    seen: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        seen.append(seconds)

    monkeypatch.setattr(agent, "_sleep", fake_sleep)
    return seen


# --- classification ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "err",
    [
        status_error(anthropic.RateLimitError, 429),
        status_error(anthropic.InternalServerError, 500),
        status_error(anthropic.InternalServerError, 503),
        status_error(anthropic.OverloadedError, 529),
        status_error(anthropic.ServiceUnavailableError, 503),
        status_error(anthropic.DeadlineExceededError, 504),
        anthropic.APIConnectionError(request=REQ),
        anthropic.APITimeoutError(REQ),
        overloaded_mid_stream(),
    ],
    ids=lambda e: f"{type(e).__name__}-{getattr(e, 'status_code', '')}",
)
def test_retryable_errors(err):
    assert harness.is_retryable(err)
    assert harness.is_retryable(ModelError(err, 0, 0)), "the wrapper the model raises is looked through"
    wrapped = RuntimeError("stream broke")
    wrapped.__cause__ = err
    assert harness.is_retryable(wrapped), "so is a __cause__ chain"


@pytest.mark.parametrize(
    "err",
    [
        status_error(anthropic.BadRequestError, 400),
        status_error(anthropic.AuthenticationError, 401),
        status_error(anthropic.PermissionDeniedError, 403),
        status_error(anthropic.NotFoundError, 404),
        status_error(anthropic.ConflictError, 409),  # the SDK would retry it; the harness never retries a 4xx
        status_error(anthropic.RequestTooLargeError, 413),
        status_error(anthropic.UnprocessableEntityError, 422),
        status_error(anthropic.APIStatusError, 408),
        status_error(anthropic.APIStatusError, 200, body={"type": "error", "error": {"type": "api_error"}}),
        ValueError("not an SDK error"),
        ConnectionError("not an SDK error either"),
    ],
    ids=lambda e: f"{type(e).__name__}-{getattr(e, 'status_code', '')}",
)
def test_final_errors(err):
    assert not harness.is_retryable(err)
    assert not harness.is_retryable(ModelError(err, 0, 0))


def test_retry_after_headers():
    def after(headers):
        return harness.retry_after(status_error(anthropic.RateLimitError, 429, headers=headers))

    assert after({"retry-after-ms": "1500"}) == 1.5
    assert after({"retry-after-ms": "250", "retry-after": "9"}) == 0.25, "milliseconds win"
    assert after({"retry-after": "3"}) == 3.0
    assert after({"retry-after": "2.5"}) == 2.5
    assert after({"retry-after": "-4"}) == 0.0
    later = format_datetime(datetime.now(UTC) + timedelta(seconds=30), usegmt=True)
    assert 25 < after({"retry-after": later}) <= 30
    assert after({"retry-after": "soon"}) is None
    assert after({"retry-after-ms": "nan"}) is None
    assert after({"retry-after": "inf"}) is None
    assert after({}) is None
    assert harness.retry_after(anthropic.APIConnectionError(request=REQ)) is None, "no response, no header"
    assert harness.retry_after(ModelError(status_error(anthropic.RateLimitError, 429, {"retry-after": "4"}), 0, 0)) == 4


def test_backoff_doubles_from_half_a_second_and_caps_at_eight():
    assert [harness.backoff(n) for n in range(7)] == [0.5, 1.0, 2.0, 4.0, 8.0, 8.0, 8.0]
    assert harness.backoff(10_000) == 8.0
    err = status_error(anthropic.RateLimitError, 429)
    assert harness.retry_delay(2, err) == 2.0
    assert harness.retry_delay(2, status_error(anthropic.RateLimitError, 429, {"retry-after": "0"})) == 0.0


# --- the loop -----------------------------------------------------------------------------------


def test_a_retryable_failure_is_retried_and_every_attempt_reported(ops_assistant, sidecar, ctx, waits):
    model = Scripted("claude-opus-5-5", [status_error(anthropic.RateLimitError, 429, {"retry-after": "2"}), ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "ok" and res.output == "done"
    assert waits == [2.0], "the API's retry-after is honoured"
    assert [(s.kind, s.name, s.summary) for s in res.steps] == [
        ("model_call", "claude-opus-5-5", "attempt 1/3: error RateLimitError"),
        ("model_call", "claude-opus-5-5", "attempt 2/3: stop=end_turn"),
    ]
    assert sidecar.events == [], "the gateway records a provider's calls, not the runtime"
    assert [h["x-agentsc-attempt"] for h in model.headers] == ["1", "2"]
    assert all(
        h["x-agentsc-request-id"] == ctx.request_id and h["x-agentsc-agent"] == ops_assistant.name
        for h in model.headers
    ), "every attempt is bound to the run"
    assert (res.input_tokens, res.output_tokens) == (17, 2), "the failed attempt's usage counts too"


def test_backoff_between_retries_without_retry_after(ops_assistant, sidecar, ctx, waits):
    ops_assistant.harness.max_retries = 3
    errors = [status_error(anthropic.OverloadedError, 529), anthropic.APIConnectionError(request=REQ)]
    model = Scripted("claude-opus-5-5", [*errors, overloaded_mid_stream(), ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "ok" and waits == [0.5, 1.0, 2.0]
    assert [s.summary for s in res.steps] == [
        "attempt 1/4: error OverloadedError",
        "attempt 2/4: error APIConnectionError",
        "attempt 3/4: error APIStatusError",
        "attempt 4/4: stop=end_turn",
    ]


def test_a_final_error_is_not_retried_and_skips_the_fallback(ops_assistant, sidecar, ctx, waits):
    model = Scripted("claude-opus-5-5", [status_error(anthropic.BadRequestError, 400)])
    fallback = Scripted("claude-haiku-5-5", [ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar, fallback=fallback))
    assert res.status == "error" and res.rule == "model.error" and res.reason == "BadRequestError: boom"
    assert len(res.steps) == len(model.headers) == 1 and waits == [] and fallback.timeouts == []


def test_after_the_last_retry_the_fallback_model_gets_one_attempt(ops_assistant, sidecar, ctx, waits):
    errors = [
        status_error(anthropic.OverloadedError, 529),
        status_error(anthropic.InternalServerError, 500),
        anthropic.APITimeoutError(REQ),
    ]
    model = Scripted("claude-opus-5-5", errors)
    fallback = Scripted("claude-haiku-5-5", [ok("from haiku", 1000, 100)])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar, fallback=fallback))
    assert res.status == "ok" and res.output == "from haiku"
    assert waits == [0.5, 1.0], "no wait before the fallback: it is another model"
    assert [(s.name, s.summary) for s in res.steps] == [
        ("claude-opus-5-5", "attempt 1/3: error OverloadedError"),
        ("claude-opus-5-5", "attempt 2/3: error InternalServerError"),
        ("claude-opus-5-5", "attempt 3/3: error APITimeoutError"),
        ("claude-haiku-5-5", "fallback: stop=end_turn"),
    ]
    assert [h["x-agentsc-attempt"] for h in model.headers + fallback.headers] == ["1", "2", "3", "fallback"]
    assert (res.input_tokens, res.output_tokens) == (3 * 7 + 1000, 100)


def test_a_failed_fallback_ends_the_step(ops_assistant, sidecar, ctx, waits):
    ops_assistant.harness.max_retries = 0
    model = Scripted("claude-opus-5-5", [status_error(anthropic.RateLimitError, 429)])
    fallback = Scripted("claude-haiku-5-5", [status_error(anthropic.RateLimitError, 429), ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar, fallback=fallback))
    assert res.status == "error" and res.reason == "RateLimitError: boom"
    assert [s.summary for s in res.steps] == ["attempt 1/1: error RateLimitError", "fallback: error RateLimitError"]
    assert len(fallback.script) == 1, "exactly one fallback attempt"


def test_retries_and_fallback_are_one_step_of_max_steps(ops_assistant, sidecar, ctx, waits):
    ops_assistant.budgets.max_steps = 1
    model = Scripted("claude-opus-5-5", [status_error(anthropic.OverloadedError, 529)] * 3)
    fallback = Scripted("claude-haiku-5-5", [ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar, fallback=fallback))
    assert res.status == "ok" and len(res.steps) == 4


def test_no_retry_wait_that_ends_past_the_deadline(ops_assistant, sidecar, ctx, waits):
    ctx.deadline = time.monotonic() + HOP_MARGIN + 0.4  # room for an attempt, not for a 0.5 s backoff
    model = Scripted("claude-opus-5-5", [status_error(anthropic.OverloadedError, 529), ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "error" and res.rule == "model.error" and waits == []
    assert len(model.script) == 1, "the retry was not started"

    # The fallback needs no wait, so it still gets its attempt.
    sidecar.events.clear()
    ctx.deadline = time.monotonic() + HOP_MARGIN + 0.4
    model = Scripted("claude-opus-5-5", [status_error(anthropic.OverloadedError, 529)])
    fallback = Scripted("claude-haiku-5-5", [ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar, fallback=fallback))
    assert res.status == "ok" and waits == [] and [s.summary for s in res.steps][-1] == "fallback: stop=end_turn"
    assert 0 < fallback.timeouts[0] <= 0.4


def test_a_retry_after_longer_than_the_deadline_is_not_waited_for(ops_assistant, sidecar, ctx, waits):
    ctx.deadline = time.monotonic() + 30
    model = Scripted("claude-opus-5-5", [status_error(anthropic.RateLimitError, 429, {"retry-after": "60"}), ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "error" and waits == []


def test_without_a_deadline_a_long_retry_after_is_capped(ops_assistant, sidecar, ctx, waits):
    model = Scripted("claude-opus-5-5", [status_error(anthropic.RateLimitError, 429, {"retry-after": "3600"}), ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "ok" and waits == [harness.RETRY_AFTER_CAP_NO_DEADLINE]


def test_no_attempt_starts_once_the_deadline_is_nearly_up(ops_assistant, sidecar, ctx, waits):
    ctx.deadline = time.monotonic() + HOP_MARGIN / 2
    model = Scripted("claude-opus-5-5", [ok()])
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "error" and res.rule == "deadline.exceeded" and model.timeouts == []


def test_the_per_attempt_timeout_is_the_harness_timeout_held_inside_the_deadline(ops_assistant, sidecar, ctx, waits):
    ops_assistant.harness.request_timeout_seconds = 7
    model = Scripted("claude-opus-5-5", [status_error(anthropic.RateLimitError, 429), ok()])
    asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert model.timeouts == [7.0, 7.0], "no deadline: request_timeout_seconds for every attempt"

    ctx.deadline = time.monotonic() + 3
    model = Scripted("claude-opus-5-5", [ok()])
    asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert 2 < model.timeouts[0] <= 3 - HOP_MARGIN


# --- the real SDK, without the network ----------------------------------------------------------

MESSAGE = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-opus-5-5",
    "content": [],
    "stop_reason": None,
    "stop_sequence": None,
    "usage": {"input_tokens": 11, "output_tokens": 1},
}
STREAM = [
    ("message_start", {"type": "message_start", "message": MESSAGE}),
    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hi"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 5}}),
    ("message_stop", {"type": "message_stop"}),
]
OVERLOADED = {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}


def sse(events: list[tuple[str, Any]]) -> httpx2.Response:
    body = "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events)
    return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=body.encode())


def sdk_client(responses: list[httpx2.Response]) -> anthropic.Anthropic:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return responses.pop(0)

    transport = httpx2.MockTransport(handler)
    return anthropic.Anthropic(api_key="test", max_retries=0, http_client=httpx2.Client(transport=transport))


def test_sdk_errors_from_the_wire_are_classified_and_retried(ops_assistant, sidecar, ctx, waits):
    """A 529 with retry-after-ms, then an overload mid-stream, then an answer — through the SDK."""
    client = sdk_client(
        [
            httpx2.Response(529, headers={"retry-after-ms": "1500"}, json=OVERLOADED),
            sse([*STREAM[:3], ("error", OVERLOADED)]),
            sse(STREAM),
        ]
    )
    model = AnthropicModel("claude-opus-5-5", client=client)
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "ok" and res.output == "hi"
    assert waits == [1.5, 1.0], "retry-after-ms first, then the backoff for retry 2"
    assert [s.summary for s in res.steps] == [
        "attempt 1/3: error OverloadedError",
        "attempt 2/3: error APIStatusError",
        "attempt 3/3: stop=end_turn",
    ]
    # 0 before the 529's answer, 11 + 1 from message_start on, then 11 + 5
    assert (res.input_tokens, res.output_tokens) == (22, 6)


def test_a_400_from_the_wire_is_final(ops_assistant, sidecar, ctx, waits):
    bad = {"type": "error", "error": {"type": "invalid_request_error", "message": "bad"}}
    model = AnthropicModel("claude-opus-5-5", client=sdk_client([httpx2.Response(400, json=bad)]))
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert res.status == "error" and res.reason.startswith("BadRequestError") and len(res.steps) == 1


def slow_sse(events: list[tuple[str, Any]], then: list[tuple[str, Any]], gap: float, fail: Exception | None = None):
    """An SSE response that sends `events` at once, then each of `then` after `gap` seconds; and
    then raises `fail`, if given, the way the HTTP library does when the connection breaks."""

    def body():
        for name, data in events:
            yield f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()
        for name, data in then:
            time.sleep(gap)
            yield f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()
        if fail is not None:
            raise fail

    return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=body())


DELTA = STREAM[2]


def test_an_attempt_that_keeps_streaming_ends_when_its_time_is_up():
    """The per-attempt timeout caps the whole attempt, not only each wait for the next chunk."""
    model = AnthropicModel("claude-opus-5-5", client=sdk_client([slow_sse(STREAM[:2], [DELTA] * 100, 0.02)]))
    started = time.monotonic()
    with pytest.raises(ModelError) as info:
        model.complete("sys", [{"role": "user", "content": "x"}], [], 64, timeout=0.3)
    took = time.monotonic() - started
    assert isinstance(info.value.cause, anthropic.APITimeoutError) and harness.is_retryable(info.value)
    assert 0.3 <= took < 1.0, "cut at its first event after 0.3 s, not after the 2 s the stream would take"
    assert (info.value.input_tokens, info.value.output_tokens) == (11, 1), "billed from message_start on"


def test_no_attempt_runs_past_the_deadline_while_the_stream_keeps_coming(ops_assistant, sidecar, ctx, waits):
    ctx.deadline = time.monotonic() + 1.2  # 0.7 s for the attempt, no room for a retry after it
    model = AnthropicModel("claude-opus-5-5", client=sdk_client([slow_sse(STREAM[:2], [DELTA] * 200, 0.02)]))
    res = asyncio.run(run_agent(ops_assistant, "hi", "", ctx, model, sidecar))
    assert time.monotonic() < ctx.deadline - HOP_MARGIN + 0.3, "not the 4 s the stream would take"
    assert res.status == "error" and res.reason.startswith("APITimeoutError") and waits == []
    assert [s.summary for s in res.steps] == ["attempt 1/3: error APITimeoutError"]


@pytest.mark.parametrize(
    "broken,expected",
    [
        (httpx2.ReadTimeout("read timed out", request=REQ), anthropic.APITimeoutError),
        (httpx2.RemoteProtocolError("peer closed connection", request=REQ), anthropic.APIConnectionError),
    ],
)
def test_a_stream_broken_by_the_network_is_retried(ops_assistant, sidecar, ctx, waits, broken, expected):
    """The SDK raises its connection and timeout errors only before the response; mid-stream the HTTP
    library's own errors come through, and the model call reports them as the SDK classes."""
    client = sdk_client([slow_sse(STREAM[:3], [], 0, fail=broken), sse(STREAM)])
    res = asyncio.run(
        run_agent(ops_assistant, "hi", "", ctx, AnthropicModel("claude-opus-5-5", client=client), sidecar)
    )
    assert res.status == "ok" and res.output == "hi" and waits == [0.5]
    assert [s.summary for s in res.steps] == [f"attempt 1/3: error {expected.__name__}", "attempt 2/3: stop=end_turn"]
    assert (res.input_tokens, res.output_tokens) == (22, 6), "the broken attempt's 11 + 1 count too"


# --- one client per process ---------------------------------------------------------------------


def test_one_client_per_process_without_sdk_retries(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(models, "anthropic_available", lambda: True)
    previous = models.set_anthropic_client(None)
    try:
        first = models.anthropic_client()
        assert models.anthropic_client() is first, "created once, then reused"
        assert isinstance(first, anthropic.Anthropic) and first.max_retries == 0, "the harness owns retries"
        assert str(first.base_url).rstrip("/") == models.GATEWAY_BASE_URL, "every call goes to the gateway"
        assert first.api_key == models.GATEWAY_API_KEY, "the runtime holds no key"
        a, b = models.model_for("claude-opus-5-5"), models.model_for("claude-sonnet-5-5")
        assert isinstance(a, AnthropicModel) and isinstance(b, AnthropicModel)
        assert a.client() is b.client() is first, "every Execute shares it"
    finally:
        models.set_anthropic_client(previous)


def test_the_process_wide_client_can_be_injected():
    calls = []

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def __iter__(self):
            return iter(())

        def get_final_message(self):
            raise status_error(anthropic.RateLimitError, 429)

    class Fake:
        class messages:
            @staticmethod
            def stream(**kw):
                calls.append(kw)
                return Stream()

    previous = models.set_anthropic_client(Fake())
    try:
        with pytest.raises(ModelError) as info:
            AnthropicModel("claude-opus-5-5").complete("sys", [{"role": "user", "content": "x"}], [], 64, timeout=3)
        assert isinstance(info.value.cause, anthropic.RateLimitError) and calls[0]["timeout"] == 3
    finally:
        models.set_anthropic_client(previous)
