"""The real-API path without the network, and the sidecar error mapping (CONTRACT.md §4.3, §9)."""

import asyncio
from types import SimpleNamespace

import grpc
import pytest

from attache_runtime import models
from attache_runtime.agent import _now, run_agent
from attache_runtime.models import MockModel, ModelResponse, supports_effort
from attache_runtime.sidecar import GrpcSidecar
from attache_runtime.tools import ToolDenied, ToolFailed


class FakeStream:
    def __init__(self, recorder, kwargs):
        self.recorder, self.kwargs = recorder, kwargs

    def __enter__(self):
        self.recorder.append(self.kwargs)
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        block = SimpleNamespace(model_dump=lambda exclude_none=True: {"type": "text", "text": "hi"})
        return SimpleNamespace(
            content=[block], stop_reason="end_turn", usage=SimpleNamespace(input_tokens=10, output_tokens=2)
        )


def test_anthropic_model_streams_and_sends_effort_only_where_supported(monkeypatch):
    calls = []
    m = models.AnthropicModel.__new__(models.AnthropicModel)
    m.name = "claude-opus-5-5"
    m._client = SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: FakeStream(calls, kw)))
    resp = m.complete("sys", [{"role": "user", "content": "x"}], [], 64000)
    assert resp.text() == "hi" and resp.input_tokens == 10
    assert calls[0]["max_tokens"] == 64000 and calls[0]["output_config"] == {"effort": "low"}
    m.name = "claude-haiku-4-5"
    m.complete("sys", [{"role": "user", "content": "x"}], [], 512)
    assert "output_config" not in calls[1]
    assert supports_effort("claude-sonnet-5-5") and supports_effort("claude-fable-5-1")
    assert not supports_effort("claude-sonnet-4-5")


def test_max_tokens_without_text_is_an_error_not_an_empty_answer(ops_assistant, sidecar, ctx):
    class Truncating(MockModel):
        def complete(self, system, messages, tools, max_tokens):
            return ModelResponse([{"type": "thinking", "thinking": "", "signature": "s"}], "max_tokens", 50, max_tokens)

    res = asyncio.run(run_agent(ops_assistant, "stock?", "", ctx, Truncating(), sidecar))
    assert res.status == "error" and res.rule == "budget.max_tokens_per_call"

    class TruncatedToolCall(MockModel):
        def complete(self, system, messages, tools, max_tokens):
            return ModelResponse(
                [{"type": "tool_use", "id": "t", "name": "stock_analyst", "input": {}}], "max_tokens", 5, 5
            )

    res = asyncio.run(run_agent(ops_assistant, "stock?", "", ctx, TruncatedToolCall(), sidecar))
    assert res.status == "error" and sidecar.calls == [], "a cut-off tool call must not run"

    class TruncatedText(MockModel):
        def complete(self, system, messages, tools, max_tokens):
            return ModelResponse([{"type": "text", "text": "partial answ"}], "max_tokens", 5, 5)

    res = asyncio.run(run_agent(ops_assistant, "stock?", "", ctx, TruncatedText(), sidecar))
    assert res.status == "ok" and res.output == "partial answ"


def test_timestamp_format():
    ts = _now()
    assert len(ts) == 24 and ts.endswith("Z") and ts[19] == "."


def rpc_error(code, rule=None, details="x"):
    md = grpc.aio.Metadata(("x-attache-rule", rule)) if rule else grpc.aio.Metadata()
    return grpc.aio.AioRpcError(code, grpc.aio.Metadata(), md, details=details)


@pytest.mark.parametrize(
    "code,rule,expected",
    [
        (grpc.StatusCode.PERMISSION_DENIED, "authz.services.deny-admin", ToolDenied),
        (grpc.StatusCode.RESOURCE_EXHAUSTED, "budget.max_calls_per_minute", ToolDenied),
        (grpc.StatusCode.RESOURCE_EXHAUSTED, None, ToolFailed),  # gRPC message-size limit, not policy
        (grpc.StatusCode.UNAVAILABLE, "mesh.unavailable", ToolFailed),
        (grpc.StatusCode.NOT_FOUND, "agent.unknown", ToolFailed),
    ],
)
def test_sidecar_status_mapping(code, rule, expected):
    sc = GrpcSidecar.__new__(GrpcSidecar)

    async def fail():
        raise rpc_error(code, rule)

    with pytest.raises(expected) as info:
        asyncio.run(sc._call(fail()))
    if expected is ToolDenied:
        assert info.value.rule == rule
