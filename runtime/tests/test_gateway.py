"""The runtime's side of the model gateway (CONTRACT.md §4.4): no provider key in the runtime, every
call to the sidecar's unix socket with the run binding, and the gateway's rule surfaced."""

from __future__ import annotations

import asyncio
import http.server
import json
import os
import shutil
import socketserver
import tempfile
import threading
from typing import Any

import anthropic
import pytest

from agentsc_runtime import models
from agentsc_runtime.agent import run_agent
from agentsc_runtime.harness import is_retryable
from agentsc_runtime.models import AnthropicModel, ModelError

STREAM = [
    {
        "type": "message_start",
        "message": {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [],
            "model": "claude-opus-5-5",
            "stop_reason": None,
            "usage": {"input_tokens": 11, "output_tokens": 1},
        },
    },
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "hi"}},
    {"type": "content_block_stop", "index": 0},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 5}},
    {"type": "message_stop"},
]


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class FakeGateway:
    """An HTTP server on a unix socket that answers like the sidecar's gateway."""

    def __init__(self, providers: list[str], answer: tuple[int, dict[str, str], bytes]) -> None:
        self.providers, self.answer = providers, answer
        self.seen: list[tuple[str, dict[str, str], Any]] = []
        self.dir = tempfile.mkdtemp(prefix="agw")  # short: a unix socket path has a length limit
        self.path = os.path.join(self.dir, "model.sock")
        gateway = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def address_string(self) -> str:
                return "uds"

            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, headers: dict[str, str], body: bytes) -> None:
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                gateway.seen.append((self.path, dict(self.headers), None))
                self._send(
                    200, {"content-type": "application/json"}, json.dumps({"providers": gateway.providers}).encode()
                )

            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                gateway.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                self._send(*gateway.answer)

        self.server = _Server(self.path, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)


def sse_body(events: list[dict[str, Any]]) -> bytes:
    return "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events).encode()


@pytest.fixture
def gateway(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)  # the runtime never needs one
    made: list[FakeGateway] = []

    def make(providers=("anthropic",), answer=None) -> FakeGateway:
        g = FakeGateway(
            list(providers),
            answer
            or (
                200,
                {"content-type": "text/event-stream", "x-agentsc-rule": "budget.max_cost_usd_per_day"},
                sse_body(STREAM),
            ),
        )
        made.append(g)
        models.configure_gateway(f"unix:{g.path}")
        models.set_anthropic_client(None)
        return g

    yield make
    models.configure_gateway(None)
    models.set_anthropic_client(None)
    for g in made:
        g.close()


def test_the_gateway_address_defaults_next_to_the_sidecar_socket():
    assert models.gateway_for_sidecar("unix:/run/agentsc/sidecar.sock") == "unix:/run/agentsc/model.sock"
    assert models.gateway_for_sidecar("unix:.local/sock-orders/sidecar.sock") == "unix:.local/sock-orders/model.sock"


def test_the_provider_list_comes_from_the_gateway(gateway, monkeypatch):
    monkeypatch.delenv("AGENTSC_MOCK_FALLBACK", raising=False)
    gateway(providers=["anthropic"])
    assert models.anthropic_available() and isinstance(models.model_for("claude-opus-5-5"), AnthropicModel)
    assert models.provider() == "anthropic"
    gateway(providers=[])
    assert not models.anthropic_available(), "no key in the sidecar"
    with pytest.raises(models.ModelUnavailable):
        models.model_for("claude-opus-5-5")
    monkeypatch.setenv("AGENTSC_MOCK_FALLBACK", "1")
    assert models.model_for("claude-opus-5-5").provider == "mock", "only with the fallback asked for"
    models.configure_gateway("unix:/nonexistent/model.sock")
    assert not models.anthropic_available(), "no gateway, no provider"


def test_a_model_call_goes_to_the_gateway_bound_to_its_run(gateway, ops_assistant, sidecar, ctx):
    g = gateway()
    ops_assistant.model = "claude-opus-5-5"
    res = asyncio.run(run_agent(ops_assistant, "hello", "", ctx, AnthropicModel("claude-opus-5-5"), sidecar))
    assert res.status == "ok" and res.output == "hi" and (res.input_tokens, res.output_tokens) == (11, 5)
    [(_, headers, body)] = [s for s in g.seen if s[0] == "/v1/messages"]
    assert headers["x-agentsc-request-id"] == ctx.request_id and headers["x-agentsc-agent"] == "ops-assistant"
    assert headers["x-agentsc-attempt"] == "1"
    assert headers["x-api-key"] == models.GATEWAY_API_KEY, "a placeholder: the sidecar adds the real key"
    assert body["model"] == "claude-opus-5-5" and body["max_tokens"] == ops_assistant.budgets.max_tokens_per_call
    assert sidecar.events == [], "the gateway writes the model_call record"
    assert res.cost_budget_exhausted, "the gateway's x-agentsc-rule reaches the run"


def test_a_call_the_gateway_refuses_is_final_and_names_its_rule(gateway):
    refusal = {"type": "error", "error": {"type": "permission_error", "message": "budget.max_steps: too many"}}
    gateway(
        answer=(
            403,
            {"content-type": "application/json", "x-agentsc-rule": "budget.max_steps"},
            json.dumps(refusal).encode(),
        )
    )
    with pytest.raises(ModelError) as info:
        AnthropicModel("claude-opus-5-5").complete("s", [{"role": "user", "content": "x"}], [], 64, 5, {"a": "b"})
    assert isinstance(info.value.cause, anthropic.PermissionDeniedError)
    assert info.value.rule == "budget.max_steps"
    assert not is_retryable(info.value), "a refusal is not retried"
