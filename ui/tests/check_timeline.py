#!/usr/bin/env python3
"""Checks for the agent timeline view (design docs/design/agent-platform.md §11, §11.1).

1. Security grep over ui/js/timeline (and ui/timeline.html): no HTML parsing sinks, no eval,
   no inline handlers, scripts or styles.
2. Fixtures: traces.json (TraceSummary), every trace-<id>.json (Span, §10.1.1) and
   timeline-live.sse (span_start and audit events, §10.2) have the documented fields and enums;
   every handoff (agent_call) has its target lane; summaries agree with their traces; the live
   transcript up to its snapshot rebuilds exactly the running trace's spans.

Run from anywhere: python3 -I ui/tests/check_timeline.py   (stdlib only; exit status 1 on failure)
"""

import datetime as dt
import json
import re
import sys
from pathlib import Path

UI = Path(__file__).resolve().parent.parent
JS_DIR = UI / "js" / "timeline"
FIXTURES = UI / "fixtures"

errors = []


def fail(msg):
    errors.append(msg)


# ---- 1. forbidden APIs ---------------------------------------------------------------------------

FORBIDDEN = [
    (r"\.html\s*\(", ".html() (d3/jQuery HTML setter)"),
    (r"\binnerHTML\b", "innerHTML"),
    (r"\bouterHTML\b", "outerHTML"),
    (r"\binsertAdjacentHTML\b", "insertAdjacentHTML"),
    (r"\bcreateContextualFragment\b", "createContextualFragment"),
    (r"\bDOMParser\b", "DOMParser"),
    (r"\bdocument\.write(ln)?\s*\(", "document.write"),
    (r"(?<![\w.])eval\s*\(", "eval"),
    (r"\bnew\s+Function\b", "new Function"),
    (r"\bset(Timeout|Interval)\s*\(\s*[\"'`]", "string passed to setTimeout/setInterval"),
    (r"setAttribute\s*\(\s*[\"'`]on", "inline event handler via setAttribute"),
    (r"\.attr\s*\(\s*[\"'`]on", "inline event handler via d3 .attr"),
    (r"setAttribute\s*\(\s*[\"'`]style[\"'`]", "inline style attribute"),
    (r"\.attr\s*\(\s*[\"'`]style[\"'`]", "inline style attribute via d3 .attr"),
    (r"<\s*script", "script markup in a string"),
    (r"javascript\s*:", "javascript: URL"),
    (r"\bimport\s*\(\s*[\"'`]https?:", "remote dynamic import"),
    (r"^\s*import\s[^;]*from\s*[\"'`]https?:", "remote import"),
]


def strip_comments(src):
    # Line and block comments; good enough for our own sources (no regex literals with //).
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"(^|[^:\\])//[^\n]*", r"\1", src)


def check_js():
    files = sorted(JS_DIR.glob("*.js"))
    if not files:
        fail("no files in ui/js/timeline")
    for path in files:
        src = strip_comments(path.read_text(encoding="utf-8"))
        for lineno, line in enumerate(src.splitlines(), 1):
            for pattern, what in FORBIDDEN:
                if re.search(pattern, line):
                    fail("%s:%d: forbidden %s" % (path.relative_to(UI), lineno, what))
        if re.search(r"\bwindow\.d3\b|\bimport\s+[^;]*\bd3\b[^;]*from", src):
            fail("%s: use globalThis.d3 (d3 is a classic script)" % path.relative_to(UI))


def check_html():
    path = UI / "timeline.html"
    if not path.exists():
        fail("ui/timeline.html is missing")
        return
    html = path.read_text(encoding="utf-8")
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, flags=re.S | re.I):
        attrs, body = m.group(1), m.group(2)
        if "src=" not in attrs or body.strip():
            fail("timeline.html: inline <script>")
        src = re.search(r"src=\"([^\"]+)\"", attrs)
        if src and re.match(r"https?:", src.group(1)):
            fail("timeline.html: remote script %s" % src.group(1))
    if re.search(r"<style\b", html, flags=re.I):
        fail("timeline.html: inline <style>")
    if re.search(r"\sstyle\s*=", html, flags=re.I):
        fail("timeline.html: style attribute")
    if re.search(r"\son[a-z]+\s*=", html, flags=re.I):
        fail("timeline.html: inline event handler attribute")
    d3_at = html.find("vendor/d3.v7.9.0.min.js")
    mod_at = html.find('type="module"')
    if d3_at < 0 or mod_at < 0 or d3_at > mod_at:
        fail("timeline.html: d3 must load as a classic script before the module")


# ---- 2. fixtures ---------------------------------------------------------------------------------

SPAN_FIELDS = [
    "span_id", "parent_span_id", "kind", "agent", "namespace", "service", "callee", "callee_node", "start", "end",
    "latency_ms", "status", "decision", "rule", "request_id", "caller", "caller_agent", "tokens_in", "tokens_out",
    "cost_usd", "call_index", "segment", "attempt", "fallback",
]
SPAN_OPTIONAL = {"events"}
SUMMARY_FIELDS = [
    "trace_id", "title", "root_agent", "root_request_id", "started_at", "ended_at", "duration_ms", "status", "agents",
    "invocations", "model_calls", "tool_calls", "tokens_in", "tokens_out", "cost_usd",
]
SPAN_START_FIELDS = [
    "namespace", "service", "request_id", "trace_id", "span_id", "parent_span_id", "kind", "agent", "agent_node",
    "caller", "caller_agent", "callee", "callee_node", "ts", "call_index",
]
AUDIT_FIELDS = [
    "ts", "kind", "request_id", "trace_id", "span_id", "parent_span_id", "service", "namespace", "agent", "caller",
    "caller_agent", "callee", "direction", "input", "output", "input_sha256", "output_sha256", "tokens", "cost_usd",
    "latency_ms", "decision", "rule", "reason", "error",
]
SPAN_KINDS = ["agent_invocation", "agent_call", "service_call", "http_call", "model_call", "tool_call"]
SEGMENT_OF = {
    "model_call": "thinking", "service_call": "tool", "http_call": "tool", "tool_call": "tool",
    "agent_call": "waiting", "agent_invocation": "invocation",
}
STATUSES = {"running", "ok", "denied", "error"}
SEGMENTS = {"thinking", "tool", "waiting", "invocation"}
AGENT_NODE = re.compile(r"^agent:[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
NODE = re.compile(r"^(agent:[^/]+/[^/]+/[^/]+|app:[^/]+/[^/]+|svc:[^/]+/[^/]+|model:(anthropic|mock)|external:https?://[^/]+)$")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")


def ms(ts):
    return int(dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc).timestamp() * 1000)


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def check_span(where, s):
    keys = set(s)
    missing = [f for f in SPAN_FIELDS if f not in keys]
    extra = sorted(keys - set(SPAN_FIELDS) - SPAN_OPTIONAL)
    if missing:
        fail("%s: missing fields %s" % (where, missing))
        return False
    if extra:
        fail("%s: unknown fields %s" % (where, extra))
    if s["kind"] not in SPAN_KINDS:
        fail("%s: kind %r is not a span kind" % (where, s["kind"]))
        return False
    if s["segment"] not in SEGMENTS:
        fail("%s: segment %r" % (where, s["segment"]))
    elif s["segment"] != SEGMENT_OF[s["kind"]]:
        fail("%s: segment %s does not match kind %s" % (where, s["segment"], s["kind"]))
    if s["status"] not in STATUSES:
        fail("%s: status %r" % (where, s["status"]))
    if not HEX16.match(s["span_id"] or ""):
        fail("%s: span_id %r" % (where, s["span_id"]))
    if s["parent_span_id"] is not None and not HEX16.match(s["parent_span_id"]):
        fail("%s: parent_span_id %r" % (where, s["parent_span_id"]))
    if s["agent"] is not None and not AGENT_NODE.match(s["agent"]):
        fail("%s: agent %r is not an agent node id" % (where, s["agent"]))
    if s["callee_node"] is not None and not NODE.match(s["callee_node"]):
        fail("%s: callee_node %r" % (where, s["callee_node"]))
    try:
        start = ms(s["start"])
        end = ms(s["end"]) if s["end"] is not None else None
    except (TypeError, ValueError):
        fail("%s: bad start/end %r %r" % (where, s["start"], s["end"]))
        return False
    running = s["end"] is None
    if running != (s["status"] == "running"):
        fail("%s: status %s with end %r" % (where, s["status"], s["end"]))
    if running:
        for f in ("latency_ms", "decision", "rule"):
            if s[f] is not None:
                fail("%s: running span has %s" % (where, f))
    else:
        if end < start:
            fail("%s: end before start" % where)
        if s["latency_ms"] != end - start:
            fail("%s: latency_ms %r != end - start %d" % (where, s["latency_ms"], end - start))
        if s["decision"] not in ("allow", "deny"):
            fail("%s: decision %r" % (where, s["decision"]))
        if (s["decision"] == "deny") != (s["status"] == "denied"):
            fail("%s: decision %s with status %s" % (where, s["decision"], s["status"]))
    for f in ("tokens_in", "tokens_out"):
        if s[f] is not None and (not is_int(s[f]) or s[f] < 0):
            fail("%s: %s %r" % (where, f, s[f]))
    if s["cost_usd"] is not None and (not isinstance(s["cost_usd"], (int, float)) or s["cost_usd"] < 0):
        fail("%s: cost_usd %r" % (where, s["cost_usd"]))
    if not is_int(s["call_index"]) or s["call_index"] < 1:
        fail("%s: call_index %r" % (where, s["call_index"]))
    if not is_int(s["attempt"]) or s["attempt"] < 1:
        fail("%s: attempt %r" % (where, s["attempt"]))
    if not isinstance(s["fallback"], bool):
        fail("%s: fallback %r" % (where, s["fallback"]))
    if s["kind"] != "model_call" and (s["attempt"] != 1 or s["fallback"]):
        fail("%s: attempt/fallback only apply to model calls" % where)
    for i, ev in enumerate(s.get("events", [])):
        if set(ev) != {"kind", "rule", "decision", "ts"}:
            fail("%s: events[%d] fields %s" % (where, i, sorted(ev)))
        elif ev["kind"] in SPAN_KINDS:
            fail("%s: events[%d] has a span kind" % (where, i))
    return True


def check_trace(trace_id, doc):
    where = "trace-%s.json" % trace_id
    if doc.get("trace_id") != trace_id or set(doc) != {"trace_id", "spans"}:
        fail("%s: expected {trace_id, spans} for %s" % (where, trace_id))
    spans = doc.get("spans") or []
    if not spans:
        fail("%s: no spans" % where)
    seen = set()
    ok = []
    for i, s in enumerate(spans):
        w = "%s spans[%d]" % (where, i)
        if check_span(w, s):
            key = (s["span_id"], s["kind"])
            if key in seen:
                fail("%s: duplicate (span_id, kind) %s" % (w, key))
            seen.add(key)
            ok.append(s)
    by_id = {s["span_id"]: s for s in ok}
    lanes = {s["agent"] for s in ok if s["agent"]}
    roots = [s for s in ok if s["kind"] == "agent_invocation" and (s["parent_span_id"] is None or s["parent_span_id"] not in by_id)]
    if not roots:
        fail("%s: no root agent_invocation" % where)
    for s in ok:
        if s["parent_span_id"] and s["parent_span_id"] not in by_id and s["status"] != "running" and s not in roots:
            # Only in-flight calls may miss their parent (the tool_call wrapper is written when they end).
            parent_kinds = {"agent_call", "service_call", "http_call"}
            if s["kind"] not in parent_kinds:
                fail("%s: span %s has unknown parent %s" % (where, s["span_id"], s["parent_span_id"]))
        if s["kind"] == "agent_call":
            target = s["callee_node"]
            if not target or not target.startswith("agent:"):
                fail("%s: agent_call %s has no agent callee_node" % (where, s["span_id"]))
            elif target not in lanes:
                fail("%s: handoff %s targets %s, which has no lane" % (where, s["span_id"], target))
            children = [c for c in ok if c["parent_span_id"] == s["span_id"] and c["kind"] == "agent_invocation"]
            for c in children:
                if c["agent"] != target:
                    fail("%s: handoff %s goes to %s but its invocation runs %s" % (where, s["span_id"], target, c["agent"]))
    # call_index: repeated calls from the same agent to the same callee, by start.
    counts = {}
    for s in sorted(ok, key=lambda s: (ms(s["start"]), SPAN_KINDS.index(s["kind"]))):
        k = (s["agent"], s["kind"], s["callee"], s["service"])
        counts[k] = counts.get(k, 0) + 1
        if s["call_index"] != counts[k]:
            fail("%s: span %s call_index %s, expected %d" % (where, s["span_id"], s["call_index"], counts[k]))
    return ok, roots


def check_summary(i, s, spans, roots):
    where = "traces.json[%d]" % i
    if list(s) != SUMMARY_FIELDS:
        fail("%s: fields %s, expected %s" % (where, list(s), SUMMARY_FIELDS))
        return
    if not HEX32.match(s["trace_id"]):
        fail("%s: trace_id %r" % (where, s["trace_id"]))
    if s["status"] not in STATUSES:
        fail("%s: status %r" % (where, s["status"]))
    if not isinstance(s["title"], str) or not s["title"] or len(s["title"]) > 120:
        fail("%s: title must be 1..120 characters" % where)
    if not roots:
        return
    root = sorted(roots, key=lambda r: ms(r["start"]))[0]
    if s["root_agent"] != root["agent"] or s["root_request_id"] != root["request_id"] or s["started_at"] != root["start"]:
        fail("%s: root fields disagree with the trace" % where)
    if s["ended_at"] != root["end"] or s["status"] != root["status"]:
        fail("%s: ended_at/status disagree with the root invocation" % where)
    expect_dur = None if root["end"] is None else ms(root["end"]) - ms(root["start"])
    if s["duration_ms"] != expect_dur:
        fail("%s: duration_ms %r, expected %r" % (where, s["duration_ms"], expect_dur))
    models = [x for x in spans if x["kind"] == "model_call" and x["end"] is not None]
    tok = sum((x["tokens_in"] or 0) + (x["tokens_out"] or 0) for x in models)
    if s["tokens_in"] + s["tokens_out"] != tok:
        fail("%s: tokens %d, the trace's model calls have %d" % (where, s["tokens_in"] + s["tokens_out"], tok))
    cost = sum(x["cost_usd"] or 0 for x in models)
    if abs(s["cost_usd"] - cost) > 1e-6:
        fail("%s: cost_usd %r, the trace's model calls cost %r" % (where, s["cost_usd"], round(cost, 6)))
    counts = {
        "invocations": sum(1 for x in spans if x["kind"] == "agent_invocation"),
        "model_calls": sum(1 for x in spans if x["kind"] == "model_call"),
        "tool_calls": sum(1 for x in spans if x["kind"] == "tool_call"),
        "agents": len({x["agent"] for x in spans if x["kind"] == "agent_invocation"}),
    }
    for k, v in counts.items():
        if s[k] != v:
            fail("%s: %s %r, the trace has %d" % (where, k, s[k], v))


def parse_sse(text):
    events, comments = [], []
    for block in re.split(r"\n\n+", text):
        ev = {"type": None, "id": None, "data": None}
        for line in block.split("\n"):
            if line.startswith(":"):
                comments.append(line[1:].strip())
            elif line.startswith("event: "):
                ev["type"] = line[7:]
            elif line.startswith("id: "):
                ev["id"] = line[4:]
            elif line.startswith("data: "):
                ev["data"] = json.loads(line[6:])
        if ev["data"] is not None:
            events.append(ev)
    return events, comments


def node_of_record(r):
    if r["agent"] is None:
        return None
    if r["direction"] == "inbound" and r["kind"] != "agent_invocation" and r["caller"].startswith("spiffe://"):
        parts = r["caller"].split("/")
        return "agent:%s/%s/%s" % (parts[4], parts[6], r["agent"])
    return "agent:%s/%s/%s" % (r["namespace"], r["service"], r["agent"])


def rebuild(events, cutoff):
    """Spans from span_start + audit events up to `cutoff`, merged by (span_id, kind) (§10.1.1)."""
    spans, order, pending = {}, [], {}
    for ev in events:
        if ev["type"] == "span_start":
            p = ev["data"]
            if ms(p["ts"]) > cutoff:
                continue
            key = (p["span_id"], p["kind"])
            if key not in spans:
                spans[key] = {"span_id": p["span_id"], "parent_span_id": p["parent_span_id"], "kind": p["kind"],
                              "agent": p["agent_node"], "start": p["ts"], "end": None, "status": "running",
                              "call_index": p["call_index"], "events": []}
                order.append(key)
        elif ev["type"] == "audit":
            r = ev["data"]["record"]
            if ms(r["ts"]) > cutoff:
                continue
            if r["kind"] not in SPAN_KINDS:
                pending.setdefault(r["span_id"], []).append({"kind": r["kind"], "rule": r["rule"], "decision": r["decision"], "ts": r["ts"]})
                continue
            key = (r["span_id"], r["kind"])
            s = spans.get(key)
            if s is None:
                s = {"span_id": r["span_id"], "parent_span_id": r["parent_span_id"], "kind": r["kind"],
                     "agent": node_of_record(r), "start": None, "call_index": None, "events": []}
                spans[key] = s
                order.append(key)
                end = ms(r["ts"])
                s["start"] = dt.datetime.fromtimestamp((end - r["latency_ms"]) / 1000, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % ((end - r["latency_ms"]) % 1000)
            inp = r["input"] if isinstance(r["input"], dict) else {}
            s.update({
                "end": r["ts"],
                "status": "denied" if r["decision"] == "deny" else ("error" if r["error"] else "ok"),
                "tokens_in": r["tokens"]["input"] if r["tokens"] else None,
                "tokens_out": r["tokens"]["output"] if r["tokens"] else None,
                "cost_usd": r["cost_usd"],
                "attempt": int(inp.get("attempt", 1)) if r["kind"] == "model_call" else 1,
                "fallback": bool(inp.get("fallback", False)) if r["kind"] == "model_call" else False,
            })
    for (sid, _k), s in spans.items():
        s["events"].extend(pending.get(sid, []))
    return [spans[k] for k in order]


def check_live(traces):
    path = FIXTURES / "timeline-live.sse"
    if not path.exists():
        fail("fixtures/timeline-live.sse is missing")
        return
    events, comments = parse_sse(path.read_text(encoding="utf-8"))
    snap = [c for c in comments if c.startswith("snapshot ")]
    if len(snap) != 1:
        fail("timeline-live.sse: needs one ': snapshot <ts>' comment")
        return
    cutoff = ms(snap[0][9:].strip())
    ids = [int(e["id"]) for e in events if e["id"] is not None]
    if len(ids) != len(events) or ids != sorted(ids) or len(set(ids)) != len(ids):
        fail("timeline-live.sse: every event needs a unique, increasing id")
    live = [e for e in events if e["type"] in ("span_start", "audit")]
    if not live:
        fail("timeline-live.sse: no span_start/audit events")
        return
    trace_ids = {e["data"]["trace_id"] if e["type"] == "span_start" else e["data"]["record"]["trace_id"] for e in live}
    if len(trace_ids) != 1:
        fail("timeline-live.sse: expected one trace, got %s" % sorted(trace_ids))
        return
    trace_id = trace_ids.pop()
    last = None
    for i, e in enumerate(live):
        w = "timeline-live.sse event %s" % e["id"]
        if e["type"] == "span_start":
            d = e["data"]
            if list(d) != SPAN_START_FIELDS:
                fail("%s: span_start fields %s" % (w, list(d)))
                continue
            if d["kind"] not in ("agent_invocation", "agent_call", "service_call", "http_call"):
                fail("%s: span_start for kind %s (§6.4: invocations and agent/service/http calls only)" % (w, d["kind"]))
            if not AGENT_NODE.match(d["agent_node"] or "") or (d["callee_node"] and not NODE.match(d["callee_node"])):
                fail("%s: bad node ids" % w)
            t = ms(d["ts"])
        else:
            d = e["data"]
            if set(d) != {"record", "edge_id", "animate"}:
                fail("%s: audit payload fields %s" % (w, sorted(d)))
                continue
            r = d["record"]
            if list(r) != AUDIT_FIELDS:
                fail("%s: audit record fields %s" % (w, list(r)))
                continue
            if r["direction"] not in ("inbound", "outbound", "internal") or r["decision"] not in ("allow", "deny"):
                fail("%s: bad direction/decision" % w)
            t = ms(r["ts"])
        if last is not None and t < last:
            fail("%s: events are not in arrival (time) order" % w)
        last = t
    if trace_id not in traces:
        fail("timeline-live.sse: trace %s is not in traces.json" % trace_id)
        return
    summary, spans = traces[trace_id]
    if summary["status"] != "running":
        fail("traces.json: the live trace %s should be running at the snapshot" % trace_id)
    if not any(ms(e["data"]["ts"] if e["type"] == "span_start" else e["data"]["record"]["ts"]) > cutoff for e in live):
        fail("timeline-live.sse: nothing happens after the snapshot")
    rebuilt = {(s["span_id"], s["kind"]): s for s in rebuild(live, cutoff)}
    snapshot = {(s["span_id"], s["kind"]): s for s in spans}
    if set(rebuilt) != set(snapshot):
        fail("trace-%s.json: spans differ from the transcript up to the snapshot (only in file: %s; only in transcript: %s)"
             % (trace_id, sorted(set(snapshot) - set(rebuilt))[:3], sorted(set(rebuilt) - set(snapshot))[:3]))
        return
    for key, r in rebuilt.items():
        s = snapshot[key]
        for f in ("parent_span_id", "agent", "start", "end", "status", "attempt", "fallback", "events", "tokens_in", "tokens_out", "cost_usd"):
            if f in r and r[f] != s[f]:
                fail("trace-%s.json: span %s %s is %r, the transcript says %r" % (trace_id, key, f, s[f], r[f]))
        if r.get("call_index") is not None and r["call_index"] != s["call_index"]:
            fail("trace-%s.json: span %s call_index %r, span_start says %r" % (trace_id, key, s["call_index"], r["call_index"]))
    full = rebuild(live, float("inf"))
    root = [s for s in full if s["kind"] == "agent_invocation" and s["parent_span_id"] is None]
    if not root or root[0]["end"] is None:
        fail("timeline-live.sse: the run never ends (the replay needs an end)")


def check_fixtures():
    path = FIXTURES / "traces.json"
    try:
        summaries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        fail("fixtures/traces.json: %s" % e)
        return
    starts = [s.get("started_at") for s in summaries]
    if starts != sorted(starts, reverse=True):
        fail("traces.json: not newest first")
    traces = {}
    statuses = set()
    for i, s in enumerate(summaries):
        tid = s.get("trace_id", "")
        tpath = FIXTURES / ("trace-%s.json" % tid)
        if not tpath.exists():
            fail("traces.json[%d]: %s is missing" % (i, tpath.name))
            continue
        spans, roots = check_trace(tid, json.loads(tpath.read_text(encoding="utf-8")))
        check_summary(i, s, spans, roots)
        traces[tid] = (s, spans)
        statuses.add(s.get("status"))
    for missing in sorted({"running", "ok", "denied", "error"} - statuses):
        fail("traces.json: no %s run" % missing)
    orphans = {p.name for p in FIXTURES.glob("trace-*.json")} - {"trace-%s.json" % t for t in traces}
    for name in sorted(orphans):
        fail("fixtures/%s is not listed in traces.json" % name)
    check_live(traces)


def main():
    check_js()
    check_html()
    check_fixtures()
    if errors:
        for e in errors:
            print("FAIL", e)
        print("%d problem(s)" % len(errors))
        return 1
    n = len(list((FIXTURES).glob("trace-*.json")))
    print("ok: ui/js/timeline passes the security grep; %d traces and the live transcript match §10.1.1/§10.2" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
