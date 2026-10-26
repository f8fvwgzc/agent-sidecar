"""The real model path, end to end (`.github/workflows/real-model.yml`, `make test-live`).

A real `agentscd` with the Anthropic key in its environment starts the real runtime, which calls
the real API through the sidecar's model gateway (CONTRACT.md §4.4). Between the gateway and the
API sits a small proxy (`--anthropic-base-url`) that passes calls through and, when a test asks,
answers one call with a 429 or a 529, cuts a stream with an overload error, stalls a stream, or
answers in the API's refusal shape: these cannot be had from the API on purpose, and the runtime's
harness must meet them as the SDK reports them.

Skipped unless `AGENTSC_LIVE=1` and `ANTHROPIC_API_KEY` are set. Needs `target/debug/agentscd`
(`cargo build -p agentscd`; or `AGENTSC_LIVE_AGENTSCD`). The model is `AGENTSC_LIVE_MODEL`
(default `claude-opus-5-5`); the charter caps the run's spend at $1 a day, which the gateway holds.
"""

from __future__ import annotations

import collections
import http.server
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

import grpc
import httpx2
import pytest

ROOT = Path(__file__).resolve().parents[3]
AGENTSCD = Path(os.environ.get("AGENTSC_LIVE_AGENTSCD", ROOT / "target" / "debug" / "agentscd"))
MODEL = os.environ.get("AGENTSC_LIVE_MODEL", "claude-opus-5-5")
# Where the proxy sends calls on: the API (a local fake only to try this harness without a key).
API = os.environ.get("AGENTSC_LIVE_API", "https://api.anthropic.com")

pytestmark = pytest.mark.skipif(
    os.environ.get("AGENTSC_LIVE") != "1" or not os.environ.get("ANTHROPIC_API_KEY"),
    reason="the real model path: set AGENTSC_LIVE=1 and ANTHROPIC_API_KEY",
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Threads(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class Chaos:
    """The proxy in front of the API. `next(mode)` makes the next call go that way."""

    HOP: ClassVar[set[str]] = {
        "connection",
        "keep-alive",
        "transfer-encoding",
        "content-length",
        "host",
        "accept-encoding",
    }

    def __init__(self) -> None:
        self.modes: collections.deque[str] = collections.deque()
        self.calls: list[str] = []
        self.client = httpx2.Client(timeout=httpx2.Timeout(120.0, connect=10.0))
        chaos = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"  # the body ends when the connection closes

            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                chaos.handle(self)

        self.server = _Threads(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def next(self, *modes: str) -> None:
        self.modes.extend(modes)

    def _json(self, h: http.server.BaseHTTPRequestHandler, status: int, body: dict[str, Any], **headers: str) -> None:
        data = json.dumps(body).encode()
        h.send_response(status)
        h.send_header("content-type", "application/json")
        for k, v in headers.items():
            h.send_header(k.replace("_", "-"), v)
        h.end_headers()
        h.wfile.write(data)

    def handle(self, h: http.server.BaseHTTPRequestHandler) -> None:
        body = h.rfile.read(int(h.headers["content-length"]))
        mode = self.modes.popleft() if self.modes else "pass"
        self.calls.append(mode)
        if mode == "429":
            err = {"type": "error", "error": {"type": "rate_limit_error", "message": "injected by the test proxy"}}
            return self._json(h, 429, err, retry_after="1")
        if mode == "529":
            err = {"type": "error", "error": {"type": "overloaded_error", "message": "injected by the test proxy"}}
            return self._json(h, 529, err)
        if mode == "refusal":
            return self._refusal(h, json.loads(body))
        headers = {k: v for k, v in h.headers.items() if k.lower() not in self.HOP}
        headers["accept-encoding"] = "identity"  # the stream goes on byte for byte
        with self.client.stream("POST", f"{API}{h.path}", headers=headers, content=body) as r:
            h.send_response(r.status_code)
            for k, v in r.headers.items():
                if k.lower() not in self.HOP:
                    h.send_header(k, v)
            h.end_headers()
            for chunk in r.iter_raw():
                h.wfile.write(chunk)
                h.wfile.flush()
                if mode == "overload" and b"message_start" in chunk:
                    err = {"type": "error", "error": {"type": "overloaded_error", "message": "injected"}}
                    h.wfile.write(f"event: error\ndata: {json.dumps(err)}\n\n".encode())
                    return
                if mode == "stall":
                    time.sleep(30)
                    return

    def _refusal(self, h: http.server.BaseHTTPRequestHandler, req: dict[str, Any]) -> None:
        events = [
            {
                "type": "message_start",
                "message": {
                    "id": "msg_refusal",
                    "type": "message",
                    "role": "assistant",
                    "model": req.get("model"),
                    "content": [],
                    "stop_reason": None,
                    "usage": {"input_tokens": 12, "output_tokens": 1},
                },
            },
            {"type": "message_delta", "delta": {"stop_reason": "refusal"}, "usage": {"output_tokens": 1}},
            {"type": "message_stop"},
        ]
        h.send_response(200)
        h.send_header("content-type", "text/event-stream")
        h.end_headers()
        for e in events:
            h.wfile.write(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode())

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class OrdersApp:
    """The service the agent's tool calls: `GET /orders/<id>`."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        app = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                app.paths.append(self.path)
                data = json.dumps({"id": self.path.rsplit("/", 1)[-1], "status": "shipped", "carrier": "DHL"}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = _Threads(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def charter(app_port: int, audit: Path) -> str:
    return json.dumps(
        {
            "apiVersion": "agentsc.io/v1alpha1",
            "kind": "Charter",
            "service": {"name": "orders", "namespace": "live", "app_port": app_port},
            "agents": [
                {
                    "name": "ops",
                    "model": MODEL,
                    "system": "You answer questions about orders. Use lookup_order for order details. Be brief.",
                    "tools": [
                        {
                            "name": "lookup_order",
                            "description": "Look up an order by id.",
                            "type": "service",
                            "service": "orders",
                            "method": "GET",
                            "path": "/orders/{order_id}",
                            "parameters": {
                                "type": "object",
                                "properties": {"order_id": {"type": "string"}},
                                "required": ["order_id"],
                            },
                        }
                    ],
                    "budgets": {"max_tokens_per_call": 4096, "max_cost_usd_per_day": 1.0, "max_steps": 4},
                    "harness": {"max_retries": 2, "request_timeout_seconds": 60},
                }
            ],
            "authz": {
                "default": "deny",
                "callers": [{"identity": "local", "agents": ["*"]}],
                "services": [
                    {"name": "own-orders", "identity": "local", "service": "orders", "allow": ["GET /orders/*"]}
                ],
            },
            "audit": {"sink": "file", "file": str(audit)},
        }
    )


class Stack:
    def __init__(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="agl"))  # short: unix socket paths have a length limit
        self.audit = self.dir / "audit.jsonl"
        self.app = OrdersApp()
        self.chaos = Chaos()
        (self.dir / "charter.yaml").write_text(charter(self.app.port, self.audit))  # JSON is YAML
        self.http, self.grpc = free_port(), free_port()
        self.log = open(self.dir / "agentscd.log", "w")  # noqa: SIM115 — closed in close()
        runtime = f"{shutil.which('uv') or 'uv'} run --quiet --project {ROOT / 'runtime'} agentsc-runtime"
        self.proc = subprocess.Popen(
            [
                str(AGENTSCD),
                "--charter",
                str(self.dir / "charter.yaml"),
                "--tls-dir",
                str(self.dir / "no-tls"),
                "--socket-dir",
                str(self.dir / "s"),
                "--http-addr",
                f"127.0.0.1:{self.http}",
                "--grpc-addr",
                f"127.0.0.1:{self.grpc}",
                "--mesh-addr",
                "127.0.0.1:0",
                "--runtime-cmd",
                runtime,
                "--anthropic-base-url",
                self.chaos.url,
            ],
            stdout=self.log,
            stderr=subprocess.STDOUT,
            env=os.environ.copy(),  # ANTHROPIC_API_KEY: the sidecar's, and only the sidecar's
        )
        self.base = f"http://127.0.0.1:{self.http}"
        deadline = time.monotonic() + 180
        while True:
            try:
                ready = httpx2.get(f"{self.base}/readyz", timeout=2).json()
                if ready.get("runtime") and ready.get("model_provider") == "anthropic":
                    break
            except httpx2.HTTPError:
                pass
            if time.monotonic() > deadline or self.proc.poll() is not None:
                self.close()
                raise RuntimeError(f"agentscd did not get ready; see {self.dir / 'agentscd.log'}")
            time.sleep(0.5)

    def invoke(self, text: str, timeout: float = 240) -> tuple[int, dict[str, Any]]:
        r = httpx2.post(f"{self.base}/v1/agents/ops/invoke", json={"input": text}, timeout=timeout)
        return r.status_code, r.json()

    def records(self, request_id: str, kind: str | None = None) -> list[dict[str, Any]]:
        out = []
        for line in self.audit.read_text().splitlines() if self.audit.exists() else []:
            rec = json.loads(line)
            if rec.get("request_id") == request_id and (kind is None or rec.get("kind") == kind):
                out.append(rec)
        return out

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()
        self.app.close()
        self.chaos.close()
        if os.environ.get("AGENTSC_LIVE_KEEP"):
            print(f"live stack kept in {self.dir}", file=sys.stderr)
        else:
            out = os.environ.get("AGENTSC_LIVE_LOGS")
            if out:
                shutil.copytree(
                    self.dir, Path(out) / self.dir.name, dirs_exist_ok=True, ignore=shutil.ignore_patterns("s")
                )
            shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture(scope="module")
def stack():
    s = Stack()
    yield s
    s.close()


def summaries(body: dict[str, Any]) -> list[str]:
    return [s.get("summary", "") for s in body["steps"] if s["kind"] == "model_call"]


def test_streaming_and_tool_use_through_the_gateway(stack):
    status, body = stack.invoke("What is the status of order 1001? Look it up.")
    assert status == 200, body
    tools = [s for s in body["steps"] if s["kind"] == "service_call"]
    assert tools and tools[0]["decision"] == "allow", body["steps"]
    assert "/orders/1001" in stack.app.paths
    calls = stack.records(body["request_id"], "model_call")
    assert len(calls) >= 2, "a tool_use turn, then the answer"
    assert all(c["callee"] == f"anthropic:{MODEL}" and c["tokens"]["input"] > 0 for c in calls)
    tool_use = [b for c in calls for b in (c["output"] or []) if b.get("type") == "tool_use"]
    assert tool_use and tool_use[0]["name"] == "lookup_order" and tool_use[0]["input"] == {"order_id": "1001"}
    spent = round(sum(c["cost_usd"] for c in calls), 6)
    assert body["usage"]["cost_usd"] == spent > 0, "the answer carries what the gateway measured"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
def test_the_runtime_process_holds_no_key(stack):
    children = Path(f"/proc/{stack.proc.pid}/task/{stack.proc.pid}/children").read_text().split()
    assert children, "agentscd started the runtime"
    pids = list(children)
    for pid in children:  # `uv run` starts the interpreter as its own child
        task = Path(f"/proc/{pid}/task/{pid}/children")
        if task.exists():
            pids += task.read_text().split()
    for pid in pids:
        env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        names = {e.split(b"=", 1)[0] for e in env}
        assert b"ANTHROPIC_API_KEY" not in names, f"process {pid} has the key"
        assert b"AGENTSC_MODEL_GATEWAY" in names


@pytest.mark.parametrize(
    "mode,error",
    [("429", "RateLimitError"), ("529", "OverloadedError"), ("overload", "APIStatusError")],
)
def test_rate_limits_and_overloads_are_retried(stack, mode, error):
    stack.chaos.next(mode)
    status, body = stack.invoke("Say hello in one word.")
    assert status == 200, body
    assert summaries(body)[:2] == [f"attempt 1/3: error {error}", "attempt 2/3: stop=end_turn"], body["steps"]
    calls = stack.records(body["request_id"], "model_call")
    assert calls[0]["error"] and calls[1]["error"] is None
    if mode == "overload":
        assert calls[0]["tokens"]["input"] > 0, "the input billed before the overload is counted"


def test_a_refusal_is_a_denial(stack):
    stack.chaos.next("refusal")
    status, body = stack.invoke("Say hello in one word.")
    assert (status, body["status"], body["rule"]) == (403, "denied", "model.refusal"), body
    [call] = stack.records(body["request_id"], "model_call")
    assert call["decision"] == "deny" and call["rule"] == "model.refusal"


def test_a_stalled_stream_ends_at_the_deadline(stack):
    from agentsc_runtime.pb.agentsc.v1alpha1 import app_pb2_grpc, common_pb2

    stack.chaos.next("stall", "stall", "stall", "stall")
    channel = grpc.insecure_channel(f"127.0.0.1:{stack.grpc}")
    started = time.monotonic()
    with pytest.raises(grpc.RpcError) as info:
        app_pb2_grpc.AppApiStub(channel).InvokeAgent(
            common_pb2.InvokeAgentRequest(agent="ops", input="Say hello in one word."), timeout=8
        )
    took = time.monotonic() - started
    assert took < 8.5, f"the sidecar answered inside the deadline ({took:.1f}s)"
    assert info.value.code() in {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED}
    stack.chaos.modes.clear()
