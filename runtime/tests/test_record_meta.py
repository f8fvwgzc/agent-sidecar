"""model_call records carry attempt/fallback (harness) and purpose (reflection): design §6.5, §11.1, §12."""

from attache_runtime.agent import _attempt_meta, model_call_record
from attache_runtime.models import model_for
from attache_runtime.spec import AgentSpec
from attache_runtime.tools import CallContext


def _record(meta):
    spec = AgentSpec(name="a", model="mock")
    ctx = CallContext("req-1", "0" * 32, "1" * 16, "a", 0)
    return model_call_record(
        spec, ctx, "local", "", model_for("mock"), "", [], [], None, "end_turn", 1, 2, 3, meta=meta
    )


def test_attempt_labels_map_to_input_fields():
    assert _attempt_meta("attempt 1/3") == {"attempt": 1, "fallback": False}
    assert _attempt_meta("attempt 3/3") == {"attempt": 3, "fallback": False}
    assert _attempt_meta("fallback") == {"fallback": True}


def test_meta_lands_in_input_without_replacing_fields():
    rec = _record({"attempt": 2, "fallback": False})
    assert rec["input"]["attempt"] == 2 and rec["input"]["fallback"] is False
    assert {"system", "messages", "tools"} <= set(rec["input"])
    assert _record({"purpose": "reflection"})["input"]["purpose"] == "reflection"
    assert "attempt" not in _record(None)["input"]
