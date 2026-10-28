"""`ask_caller` (agent-practices design, "`ask_caller`"; CONTRACT.md §9): a valid call ends the run with
status ok and the questions, an invalid one is an error tool result and the loop goes on, how such
runs show in the reflection's transcript and digest, and the gRPC Execute handler returns the
questions in ExecuteResponse."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from agentsc_runtime.agent import run_agent
from agentsc_runtime.learning import Learner, RunDigest, digest, should_reflect, transcript
from agentsc_runtime.models import MockModel, ModelResponse
from agentsc_runtime.pb.agentsc.v1alpha1 import common_pb2, runtime_pb2
from agentsc_runtime.prompts import ask_caller_tool
from agentsc_runtime.server import RuntimeServicer
from agentsc_runtime.spec import Practices

RENDERED = (
    "I need these decisions from you before I go on:\n"
    "\n"
    "1. Refund to the card or as store credit?\n"
    "   Recommended: The card: the customer paid by card.\n"
    "\n"
    "2. Include the shipping cost?\n"
    "   Recommended: No, the order shipped."
)
QUESTIONS = [
    {"question": "Refund to the card or as store credit?", "recommended": "The card: the customer paid by card."},
    {"question": "Include the shipping cost?", "recommended": "No, the order shipped."},
]
INVALID = "ask_caller needs 1 to 5 questions, each with a non-empty question and recommended answer."


class Scripted(MockModel):
    """Answers with the given responses, in order, and records what each call was given."""

    def __init__(self, *responses: ModelResponse) -> None:
        super().__init__()
        self.responses = list(responses)
        self.seen: list[dict[str, Any]] = []

    def complete(self, system, messages, tools, max_tokens, timeout=None, headers=None):
        self.seen.append({"messages": [dict(m) for m in messages], "tools": tools})
        return self.responses.pop(0)


def block(name: str, args: Any, id_: str) -> dict[str, Any]:
    return {"type": "tool_use", "id": id_, "name": name, "input": args}


def turn(*blocks: dict[str, Any], stop: str = "tool_use") -> ModelResponse:
    return ModelResponse(list(blocks), stop, 5, 5)


def ask(questions: Any, id_: str = "q1") -> dict[str, Any]:
    return block("ask_caller", {"questions": questions}, id_)


def done(text: str = "ok") -> ModelResponse:
    return ModelResponse([{"type": "text", "text": text}], "end_turn", 5, 5)


def execute(spec, model, sidecar, ctx):
    return asyncio.run(run_agent(spec, "Refund order 1001", "", ctx, model, sidecar))


# --- a valid call -------------------------------------------------------------------------------


def test_a_valid_call_ends_the_run_with_the_questions(ops_assistant, sidecar, ctx):
    ops_assistant.learning.enabled = True
    padded = [{"question": f"  {q['question']}\n", "recommended": f"\t{q['recommended']} "} for q in QUESTIONS]
    # Other tool calls of the turn are not run, whether they come before ask_caller or after it.
    model = Scripted(
        turn(
            block("lookup_order", {"order_id": "1001"}, "t1"),
            ask(padded),
            block("stock_analyst", {"input": "x"}, "t2"),
        )
    )
    res = execute(ops_assistant, model, sidecar, ctx)
    assert res.status == "ok" and (res.rule, res.reason) == ("", "")
    assert res.output == RENDERED
    assert res.questions == QUESTIONS, "whitespace trimmed"
    assert len(model.seen) == 1 and model.responses == [], "no further model call"
    assert sidecar.calls == [], "no other tool of that turn ran"
    assert [(s.kind, s.name, s.decision, s.rule, s.summary) for s in res.steps] == [
        ("model_call", "mock", "allow", "", "attempt 1/3: stop=tool_use"),
        ("tool_call", "ask_caller", "allow", "", "2 questions"),
    ]
    assert [e["kind"] for e in sidecar.events] == ["model_call"], "no tool_call record for ask_caller"
    assert res.tools_used == [] and not should_reflect(ops_assistant, res, "local"), "a run that only asked"


def test_one_question_its_singular_summary_and_an_input_sent_as_a_json_string(ops_assistant, sidecar, ctx):
    one = [{"question": "Which warehouse?", "recommended": "North: it has stock."}]
    res = execute(
        ops_assistant, Scripted(turn(block("ask_caller", json.dumps({"questions": one}), "q1"))), sidecar, ctx
    )
    assert res.questions == one and res.steps[-1].summary == "1 question"
    assert res.output == (
        "I need these decisions from you before I go on:\n\n1. Which warehouse?\n   Recommended: North: it has stock."
    )


def test_a_valid_call_after_an_invalid_one_in_the_same_turn_still_ends_the_run(ops_assistant, sidecar, ctx):
    model = Scripted(turn(ask([], "q1"), ask(QUESTIONS, "q2")))
    res = execute(ops_assistant, model, sidecar, ctx)
    assert res.questions == QUESTIONS and len(model.seen) == 1
    assert [s.summary for s in res.steps if s.kind == "tool_call"] == ["2 questions"]


def test_a_tool_used_before_asking_still_counts_for_learning(ops_assistant, sidecar, ctx):
    ops_assistant.learning.enabled = True
    model = Scripted(turn(block("lookup_order", {"order_id": "1001"}, "t1")), turn(ask(QUESTIONS)))
    res = execute(ops_assistant, model, sidecar, ctx)
    assert res.questions == QUESTIONS and res.tools_used == ["lookup_order"]
    assert should_reflect(ops_assistant, res, "local")
    assert [(s.kind, s.summary) for s in res.steps][-1] == ("tool_call", "2 questions")


def test_a_call_cut_off_by_max_tokens_never_asks(ops_assistant, sidecar, ctx):
    res = execute(ops_assistant, Scripted(turn(ask(QUESTIONS), stop="max_tokens")), sidecar, ctx)
    assert res.status == "error" and res.rule == "budget.max_tokens_per_call" and res.questions == []
    assert res.ask_call_id == ""
    assert transcript(ops_assistant, res, "local").splitlines()[4].startswith("s1 call ask_caller (not run): ")


def test_the_transcript_shows_the_other_calls_of_the_turn_that_asked_as_not_run(ops_assistant, sidecar, ctx):
    model = Scripted(
        turn(
            block("lookup_order", {"order_id": "1001"}, "t1"),
            ask([], "q0"),
            ask(QUESTIONS, "q1"),
            block("stock_analyst", {"input": "x"}, "t2"),
        )
    )
    res = execute(ops_assistant, model, sidecar, ctx)
    assert res.questions == QUESTIONS and res.ask_call_id == "q1"
    assert transcript(ops_assistant, res, "local").splitlines()[4:-1] == [
        's1 call lookup_order (not run): {"order_id": "1001"}',
        's2 call ask_caller (not run): {"questions": []}',
        f"s3 call ask_caller: {json.dumps({'questions': QUESTIONS})}",  # the call that asked
        's4 call stock_analyst (not run): {"input": "x"}',
        "s5 outcome: ok",
    ]


# --- an invalid call ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        {"questions": []},
        {},
        {"questions": "Which one?"},
        {"questions": [QUESTIONS[0]] * 6},
        {"questions": [{"question": "  ", "recommended": "x"}]},
        {"questions": [{"question": "q", "recommended": ""}]},
        {"questions": [{"question": "q"}]},
        {"questions": [{"question": "q", "recommended": 3}]},
        {"questions": ["q"]},
        "not json",
    ],
)
def test_an_invalid_call_gets_an_error_result_and_the_loop_goes_on(ops_assistant, sidecar, ctx, args):
    model = Scripted(turn(block("ask_caller", args, "q1")), done("answered without asking"))
    res = execute(ops_assistant, model, sidecar, ctx)
    assert res.status == "ok" and res.output == "answered without asking" and res.questions == []
    [result] = model.seen[1]["messages"][-1]["content"]
    assert result == {"type": "tool_result", "tool_use_id": "q1", "content": INVALID, "is_error": True}
    step = res.steps[1]
    assert (step.kind, step.name, step.decision, step.rule, step.summary) == (
        "tool_call",
        "ask_caller",
        "allow",
        "",
        "error: invalid questions",
    )
    assert res.tools_used == [] and [e["kind"] for e in sidecar.events] == ["model_call", "model_call"]


def test_an_invalid_call_then_a_tool_gives_a_digest_of_that_tool_alone(ops_assistant, sidecar, ctx):
    model = Scripted(turn(ask([], "q1")), turn(block("lookup_order", {"order_id": "1001"}, "t1")), done())
    res = execute(ops_assistant, model, sidecar, ctx)
    assert res.status == "ok" and res.questions == [] and res.tools_used == ["lookup_order"]
    # s1 call ask_caller, s2 its error result, s3 call lookup_order, s4 its result, s5 the answer, s6 the outcome.
    assert digest(ops_assistant, res) == RunDigest("ok", "", 6, ("lookup_order",))


def test_max_questions_bounds_the_tool_and_the_check(ops_assistant, sidecar, ctx):
    ops_assistant.practices = Practices(max_questions=2)
    three = [*QUESTIONS, {"question": "Tell the customer?", "recommended": "Yes."}]
    model = Scripted(turn(ask(three)), turn(ask(QUESTIONS, "q2")))
    res = execute(ops_assistant, model, sidecar, ctx)
    offered = model.seen[0]["tools"][-1]
    assert offered == ask_caller_tool(2) and offered["input_schema"]["properties"]["questions"]["maxItems"] == 2
    [result] = model.seen[1]["messages"][-1]["content"]
    assert result["content"] == INVALID.replace("1 to 5", "1 to 2") and result["is_error"] is True
    assert res.questions == QUESTIONS, "two are allowed"


def test_the_tool_is_the_one_the_design_gives():
    tool = ask_caller_tool(5)
    assert tool == {
        "name": "ask_caller",
        "description": (
            "Ask the caller for the decisions you need before you can act. The run ends here and the caller gets "
            "your questions. Ask every open question in one call, each with the answer you recommend."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 5,
                    "items": {
                        "type": "object",
                        "properties": {
                            "question": {"type": "string", "description": "One decision, asked as a question."},
                            "recommended": {
                                "type": "string",
                                "description": "The answer you recommend, with the reason in a few words.",
                            },
                        },
                        "required": ["question", "recommended"],
                    },
                }
            },
            "required": ["questions"],
        },
    }


def test_with_clarify_never_ask_caller_is_an_unknown_tool(ops_assistant, sidecar, ctx):
    ops_assistant.practices = Practices(clarify="never")
    model = Scripted(turn(ask(QUESTIONS)), done())
    res = execute(ops_assistant, model, sidecar, ctx)
    assert "ask_caller" not in [t["name"] for t in model.seen[0]["tools"]]
    assert res.status == "ok" and res.questions == [] and len(model.seen) == 2
    step = res.steps[1]
    assert (step.name, step.decision, step.rule) == ("ask_caller", "deny", "guardrail.allowed_tools")
    assert res.tools_used == [], "ask_caller never counts as a tool use"


# --- the mock -----------------------------------------------------------------------------------


def test_the_mock_never_calls_ask_caller(ops_assistant, sidecar, ctx):
    # Every word of this input is in ask_caller's description, none in a charter tool's.
    words = "Ask the caller for the decisions you need before you can act; ask every open question in one call"
    m = MockModel()
    first = m.complete("sys", [{"role": "user", "content": words}], [ask_caller_tool(5)], 256)
    assert first.tool_uses() == [] and first.text() == f"Mock answer for: {words}"
    res = asyncio.run(run_agent(ops_assistant, words, "", ctx, MockModel(), sidecar))
    assert res.status == "ok" and res.questions == [] and res.output == f"Mock answer for: {words}"
    assert [s.kind for s in res.steps] == ["model_call"]


# --- the Execute handler ------------------------------------------------------------------------


class Context:
    """Stands in for grpc.aio.ServicerContext."""

    def time_remaining(self) -> float:
        return 30.0

    async def abort(self, code, details):
        raise AssertionError(f"aborted: {code} {details}")


def handle(spec, model, sidecar) -> runtime_pb2.ExecuteResponse:
    request = runtime_pb2.ExecuteRequest(
        request_id="req-7",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
        span_id="00f067aa0ba902b7",
        agent_spec_json=spec.model_dump_json(),
        input="Refund order 1001",
        caller="local",
    )

    async def go() -> runtime_pb2.ExecuteResponse:
        learner = Learner()
        resp = await RuntimeServicer(sidecar, learner=learner, models=lambda name: model).Execute(request, Context())
        await learner.drain()
        return resp

    # Through the wire format, as the sidecar reads it.
    return runtime_pb2.ExecuteResponse.FromString(asyncio.run(go()).SerializeToString())


def test_the_execute_handler_returns_the_questions(ops_assistant, sidecar):
    resp = handle(ops_assistant, Scripted(turn(ask(QUESTIONS))), sidecar)
    assert resp.status == "ok" and resp.output == RENDERED
    assert list(resp.questions) == [
        common_pb2.Question(question=q["question"], recommended=q["recommended"]) for q in QUESTIONS
    ]
    assert [(s.kind, s.name, s.summary) for s in resp.steps][-1] == ("tool_call", "ask_caller", "2 questions")


def test_a_run_that_did_not_ask_returns_no_questions(ops_assistant, sidecar):
    resp = handle(ops_assistant, MockModel(), sidecar)
    assert resp.status == "ok" and len(resp.questions) == 0
