// The span model of one run (trace), design §10.1.1 and §11.1.
//
// Spans come from `GET /traces/{id}` and are kept up to date by SSE `span_start` and `audit`
// events, merged by (trace_id, span_id, kind): a span start opens a running span; the audit record
// with the same key closes it. Audit records of other kinds (guardrail, authz, budget, …) attach to
// the span with their span id as `events`.

import { assignColors, displayName } from "./util.js";

export const SPAN_KINDS = ["agent_invocation", "agent_call", "service_call", "http_call", "model_call", "tool_call"];
const KIND_ORDER = Object.fromEntries(SPAN_KINDS.map((k, i) => [k, i]));
export const SEGMENT_BY_KIND = {
  model_call: "thinking",
  service_call: "tool",
  http_call: "tool",
  tool_call: "tool",
  agent_call: "waiting",
  agent_invocation: "invocation",
};
export const SEGMENTS = ["thinking", "tool", "waiting", "invocation"];
export const STATUSES = ["running", "ok", "denied", "error"];
export const MAX_SPANS = 2000;
const MAX_EVENTS_PER_SPAN = 32;
const WRAPPED_KINDS = new Set(["agent_call", "service_call", "http_call"]);

export function parseTime(v) {
  if (v === null || v === undefined || v === "") return null;
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

/** Node id of the agent a record belongs to. Inbound records other than invocations carry the calling peer's agent. */
export function agentNodeFromRecord(rec) {
  if (!rec || !rec.agent) return null;
  if (rec.direction === "inbound" && rec.kind !== "agent_invocation" && typeof rec.caller === "string") {
    const m = /^spiffe:\/\/attache\/ns\/([^/]+)\/svc\/([^/]+)$/.exec(rec.caller);
    if (m) return `agent:${m[1]}/${m[2]}/${rec.agent}`;
  }
  return `agent:${rec.namespace}/${rec.service}/${rec.agent}`;
}

/** Callee node id by the graph's mapping (design §10.1). */
export function calleeNodeFor(kind, ns, svc, callee) {
  if (typeof callee !== "string" || !callee) return null;
  switch (kind) {
    case "agent_call": {
      const i = callee.indexOf("/");
      return i > 0 ? `agent:${ns}/${callee.slice(0, i)}/${callee.slice(i + 1)}` : `agent:${ns}/${svc}/${callee}`;
    }
    case "agent_invocation":
      return `agent:${ns}/${svc}/${callee}`;
    case "service_call":
      return `app:${ns}/${callee.split(" ")[0]}`;
    case "http_call": {
      const url = callee.split(" ")[1] || "";
      const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]+)/i.exec(url);
      return m ? `external:${m[1]}://${m[2]}` : null;
    }
    case "model_call":
      return callee.startsWith("mock") ? "model:mock" : "model:anthropic";
    default:
      return null;
  }
}

function statusOfRecord(rec) {
  if (rec.decision === "deny") return "denied";
  if (rec.error) return "error";
  return "ok";
}

function num(v) {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** "anthropic:claude-opus-5-5" → { provider: "anthropic", model: "claude-opus-5-5" }. */
export function splitModel(callee) {
  if (typeof callee !== "string") return { provider: null, model: null };
  const i = callee.indexOf(":");
  if (i < 0) return { provider: callee === "mock" ? "mock" : null, model: callee };
  const provider = callee.slice(0, i);
  const model = callee.slice(i + 1) || provider;
  return { provider, model: provider === "mock" ? "mock" : model };
}

export class TraceModel {
  constructor(traceId) {
    this.traceId = traceId;
    this.spans = new Map(); // key → span
    this.pendingEvents = new Map(); // span id → events seen before their span
    this.version = 0;
    this.merged = 0; // model calls merged by the span cap
    this._cache = null;
    this._cacheVersion = -1;
  }

  static key(spanId, kind) {
    return `${spanId}\u001f${kind}`;
  }

  /** Spans from `GET /traces/{id}` (the Span shape of design §10.1.1). */
  loadSpans(list) {
    for (const s of Array.isArray(list) ? list : []) this._mergeSpan(s);
    this._changed();
  }

  _mergeSpan(s) {
    if (!s || !SPAN_KINDS.includes(s.kind) || typeof s.span_id !== "string") return;
    const key = TraceModel.key(s.span_id, s.kind);
    const prev = this.spans.get(key);
    const span = {
      key,
      span_id: s.span_id,
      parent_span_id: s.parent_span_id || null,
      kind: s.kind,
      agent: s.agent || null,
      namespace: s.namespace || null,
      service: s.service || null,
      callee: typeof s.callee === "string" ? s.callee : "",
      callee_node: s.callee_node || null,
      start: parseTime(s.start),
      end: parseTime(s.end),
      latency_ms: num(s.latency_ms),
      status: STATUSES.includes(s.status) ? s.status : s.end ? "ok" : "running",
      decision: s.decision ?? null,
      rule: s.rule ?? null,
      reason: s.reason ?? null,
      error: s.error ?? null,
      request_id: s.request_id || null,
      caller: s.caller ?? null,
      caller_agent: s.caller_agent ?? null,
      tokens_in: num(s.tokens_in),
      tokens_out: num(s.tokens_out),
      cost_usd: num(s.cost_usd),
      call_index: num(s.call_index),
      segment: SEGMENTS.includes(s.segment) ? s.segment : SEGMENT_BY_KIND[s.kind],
      attempt: num(s.attempt) || 1,
      fallback: Boolean(s.fallback),
      attemptKnown: true,
      events: Array.isArray(s.events) ? s.events.slice(0, MAX_EVENTS_PER_SPAN) : [],
      merged: num(s.merged) || 0,
    };
    if (span.start === null && span.end !== null) span.start = span.end - (span.latency_ms || 0);
    if (prev && prev.end !== null && span.end === null) {
      // A closed span is never reopened by an older view of it.
      if (prev.start === null) prev.start = span.start;
      return;
    }
    if (prev) {
      for (const ev of prev.events) if (span.events.length < MAX_EVENTS_PER_SPAN && !span.events.some((e) => sameEvent(e, ev))) span.events.push(ev);
    }
    this.spans.set(key, span);
    this._attachPending(span);
  }

  /** SSE `span_start` payload. Returns true when it belonged to this trace. */
  applySpanStart(ev) {
    if (!ev || ev.trace_id !== this.traceId || !SPAN_KINDS.includes(ev.kind)) return false;
    const key = TraceModel.key(ev.span_id, ev.kind);
    const ts = parseTime(ev.ts);
    const prev = this.spans.get(key);
    if (prev) {
      // The start comes from the SpanStart when one was seen (design §10.1.1).
      if (ts !== null) prev.start = ts;
      if (prev.end !== null && prev.start !== null) prev.latency_ms = prev.end - prev.start;
      prev.agent = prev.agent || ev.agent_node || null;
      prev.callee_node = prev.callee_node || ev.callee_node || null;
      if (prev.call_index === null) prev.call_index = num(ev.call_index);
    } else {
      const span = {
        key,
        span_id: ev.span_id,
        parent_span_id: ev.parent_span_id || null,
        kind: ev.kind,
        agent: ev.agent_node || (ev.agent ? `agent:${ev.namespace}/${ev.service}/${ev.agent}` : null),
        namespace: ev.namespace || null,
        service: ev.service || null,
        callee: ev.callee || "",
        callee_node: ev.callee_node || calleeNodeFor(ev.kind, ev.namespace, ev.service, ev.callee),
        start: ts,
        end: null,
        latency_ms: null,
        status: "running",
        decision: null,
        rule: null,
        reason: null,
        error: null,
        request_id: ev.request_id || null,
        caller: ev.caller ?? null,
        caller_agent: ev.caller_agent ?? null,
        tokens_in: null,
        tokens_out: null,
        cost_usd: null,
        call_index: num(ev.call_index),
        segment: SEGMENT_BY_KIND[ev.kind],
        attempt: 1,
        fallback: false,
        attemptKnown: false,
        events: [],
        merged: 0,
      };
      this.spans.set(key, span);
      this._attachPending(span);
    }
    this._changed();
    return true;
  }

  /** SSE `audit` record. Returns true when it belonged to this trace. */
  applyAudit(rec) {
    if (!rec || rec.trace_id !== this.traceId || typeof rec.span_id !== "string") return false;
    if (!SPAN_KINDS.includes(rec.kind)) {
      const ev = { kind: rec.kind, rule: rec.rule ?? null, decision: rec.decision ?? null, ts: rec.ts };
      const target = this._spanById(rec.span_id);
      if (target) {
        if (target.events.length < MAX_EVENTS_PER_SPAN && !target.events.some((e) => sameEvent(e, ev))) target.events.push(ev);
      } else {
        const list = this.pendingEvents.get(rec.span_id) || [];
        if (list.length < MAX_EVENTS_PER_SPAN) list.push(ev);
        this.pendingEvents.set(rec.span_id, list);
        if (this.pendingEvents.size > 512) this.pendingEvents.delete(this.pendingEvents.keys().next().value);
      }
      this._changed();
      return true;
    }
    const key = TraceModel.key(rec.span_id, rec.kind);
    const end = parseTime(rec.ts);
    const latency = num(rec.latency_ms) || 0;
    let span = this.spans.get(key);
    if (!span) {
      span = {
        key,
        span_id: rec.span_id,
        parent_span_id: rec.parent_span_id || null,
        kind: rec.kind,
        agent: agentNodeFromRecord(rec),
        namespace: rec.namespace || null,
        service: rec.service || null,
        callee: rec.callee || "",
        callee_node: calleeNodeFor(rec.kind, rec.namespace, rec.service, rec.callee),
        start: end === null ? null : end - latency,
        call_index: null,
        segment: SEGMENT_BY_KIND[rec.kind],
        events: [],
        merged: 0,
      };
      this.spans.set(key, span);
    }
    const input = rec.input && typeof rec.input === "object" && !Array.isArray(rec.input) ? rec.input : null;
    Object.assign(span, {
      end,
      latency_ms: span.start !== null && end !== null ? end - span.start : latency,
      status: statusOfRecord(rec),
      decision: rec.decision ?? null,
      rule: rec.rule ?? null,
      reason: rec.reason ?? null,
      error: rec.error ?? null,
      request_id: rec.request_id || span.request_id || null,
      caller: rec.caller ?? null,
      caller_agent: rec.caller_agent ?? null,
      tokens_in: rec.tokens ? num(rec.tokens.input) : null,
      tokens_out: rec.tokens ? num(rec.tokens.output) : null,
      cost_usd: num(rec.cost_usd),
    });
    // attempt/fallback come from the model_call record's input (design §11.1). Without payloads
    // (`input` is null) they are inferred from the calls before it when the view is derived.
    if (rec.kind === "model_call" && input) {
      span.attempt = num(input.attempt) || 1;
      span.fallback = Boolean(input.fallback);
      span.attemptKnown = true;
    } else if (!span.attemptKnown) {
      span.attempt = span.attempt || 1;
      span.fallback = Boolean(span.fallback);
      span.attemptKnown = rec.kind !== "model_call";
    }
    if (!span.agent) span.agent = agentNodeFromRecord(rec);
    if (!span.callee_node) span.callee_node = calleeNodeFor(rec.kind, rec.namespace, rec.service, rec.callee);
    this._attachPending(span);
    this._changed();
    return true;
  }

  _spanById(spanId) {
    let found = null;
    for (const kind of SPAN_KINDS) {
      const s = this.spans.get(TraceModel.key(spanId, kind));
      if (s && (!found || kind === "agent_invocation")) found = s;
    }
    return found;
  }

  _attachPending(span) {
    const list = this.pendingEvents.get(span.span_id);
    if (!list) return;
    this.pendingEvents.delete(span.span_id);
    for (const ev of list) if (span.events.length < MAX_EVENTS_PER_SPAN) span.events.push(ev);
  }

  _changed() {
    this.version += 1;
    if (this.spans.size > MAX_SPANS) this._cap();
  }

  /** At most MAX_SPANS spans per run: the oldest finished model calls are merged into their predecessor in the same invocation. */
  _cap() {
    let excess = this.spans.size - MAX_SPANS;
    const models = [...this.spans.values()]
      .filter((s) => s.kind === "model_call" && s.end !== null && s.status === "ok")
      .sort((a, b) => a.start - b.start);
    const lastByParent = new Map();
    for (const m of models) {
      if (excess <= 0) break;
      const prev = lastByParent.get(m.parent_span_id);
      if (!prev) {
        lastByParent.set(m.parent_span_id, m);
        continue;
      }
      prev.end = Math.max(prev.end, m.end);
      prev.latency_ms = prev.end - prev.start;
      prev.tokens_in = (prev.tokens_in || 0) + (m.tokens_in || 0);
      prev.tokens_out = (prev.tokens_out || 0) + (m.tokens_out || 0);
      prev.cost_usd = Math.round(((prev.cost_usd || 0) + (m.cost_usd || 0)) * 1e6) / 1e6;
      prev.merged = (prev.merged || 1) + (m.merged || 1);
      this.spans.delete(m.key);
      this.merged += 1;
      excess -= 1;
      // Pairs, so a merged block stays short and the header totals stay close to the truth.
      lastByParent.delete(m.parent_span_id);
    }
  }

  /** Everything the view needs, recomputed only when the spans changed. */
  derive() {
    if (this._cacheVersion === this.version && this._cache) return this._cache;
    this._cache = deriveRun(this);
    this._cacheVersion = this.version;
    return this._cache;
  }
}

function sameEvent(a, b) {
  return a.kind === b.kind && a.rule === b.rule && a.ts === b.ts && a.decision === b.decision;
}

function deriveRun(model) {
  const spans = [...model.spans.values()].filter((s) => s.start !== null);
  spans.sort((a, b) => a.start - b.start || KIND_ORDER[a.kind] - KIND_ORDER[b.kind]);

  const byId = new Map();
  const children = new Map();
  for (const s of spans) {
    const cur = byId.get(s.span_id);
    if (!cur || s.kind === "agent_invocation") byId.set(s.span_id, s);
    if (s.parent_span_id) {
      const list = children.get(s.parent_span_id) || [];
      list.push(s);
      children.set(s.parent_span_id, list);
    }
  }

  // call_index for spans built from audit records alone: repeated calls from the same agent to the
  // same callee, in start order.
  const counts = new Map();
  for (const s of spans) {
    const k = `${s.agent}\u001f${s.kind}\u001f${s.callee}\u001f${s.service}`;
    const n = (counts.get(k) || 0) + 1;
    counts.set(k, n);
    if (s.call_index === null || s.call_index === undefined) s.call_index = n;
  }

  // attempt/fallback of model calls seen without payloads: a model call that follows a failed one
  // in the same invocation is its retry (the harness only goes on after a retryable failure); a
  // different model after the failure is the fallback.
  const lastModel = new Map();
  for (const s of spans) {
    if (s.kind !== "model_call") continue;
    if (s.attemptKnown === false) {
      const prev = lastModel.get(s.parent_span_id);
      if (prev && prev.status === "error" && prev.end !== null && prev.end <= s.start) {
        s.attempt = (prev.attempt || 1) + 1;
        s.fallback = Boolean(prev.fallback) || splitModel(prev.callee).model !== splitModel(s.callee).model;
      } else {
        s.attempt = 1;
        s.fallback = false;
      }
    }
    lastModel.set(s.parent_span_id, s);
  }

  // Root: the invocation without a (known) parent, earliest first.
  const invocations = spans.filter((s) => s.kind === "agent_invocation");
  const root = invocations.find((s) => !s.parent_span_id || !byId.has(s.parent_span_id)) || invocations[0] || spans[0] || null;
  const runStart = root ? root.start : null;
  const runEnd = root && root.kind === "agent_invocation" ? root.end : null;
  const status = root ? (root.end === null ? "running" : root.status) : "running";

  // Hidden: tool_call wrappers whose work is drawn by their agent/service/http child, and the
  // callee side of a service hop (a service_call under a service_call).
  const hidden = new Set();
  for (const s of spans) {
    if (s.kind === "tool_call" && (children.get(s.span_id) || []).some((c) => WRAPPED_KINDS.has(c.kind))) hidden.add(s.key);
    if (s.kind === "service_call" && s.parent_span_id) {
      const p = byId.get(s.parent_span_id);
      if (p && p.kind === "service_call") hidden.add(s.key);
    }
  }

  const invsByAgent = new Map();
  for (const s of spans) {
    if (s.kind !== "agent_invocation" || !s.agent) continue;
    const list = invsByAgent.get(s.agent) || [];
    list.push(s);
    invsByAgent.set(s.agent, list);
  }
  const invCache = new Map();
  const invOf = (s) => {
    if (s.kind === "agent_invocation") return s;
    if (invCache.has(s.key)) return invCache.get(s.key);
    let p = s.parent_span_id;
    let found = null;
    for (let depth = 0; p && depth < 64; depth += 1) {
      const ps = byId.get(p);
      if (!ps) break;
      if (ps.kind === "agent_invocation") {
        found = ps;
        break;
      }
      p = ps.parent_span_id;
    }
    if (!found && s.agent) {
      // The chain is broken while a call is in flight (its tool_call wrapper is written when it
      // ends): use the same agent's invocation that was running when the span started.
      for (const inv of invsByAgent.get(s.agent) || []) {
        if (inv.start <= s.start && (inv.end === null || inv.end >= s.start)) found = inv;
      }
    }
    invCache.set(s.key, found);
    return found;
  };
  const laneOf = (s) => s.agent || (invOf(s) && invOf(s).agent) || null;

  // Handoffs: every agent_call, drawn from the caller lane to the callee's invocation.
  const handoffs = [];
  for (const s of spans) {
    if (s.kind !== "agent_call" || hidden.has(s.key)) continue;
    const child = (children.get(s.span_id) || []).find((c) => c.kind === "agent_invocation") || null;
    const to = (child && child.agent) || (s.callee_node && s.callee_node.startsWith("agent:") ? s.callee_node : null);
    const from = laneOf(s);
    if (from && to) handoffs.push({ key: `h:${s.key}`, call: s, child, from, to });
  }

  // Lanes: the root orchestrator first, then agents in first-handoff order, depth first.
  const rootLane = root ? laneOf(root) : null;
  const outs = new Map();
  for (const h of handoffs) {
    const list = outs.get(h.from) || [];
    list.push(h);
    outs.set(h.from, list);
  }
  const firstSeen = new Map();
  for (const s of spans) {
    const l = laneOf(s);
    if (l && !hidden.has(s.key) && !firstSeen.has(l)) firstSeen.set(l, s.start);
  }
  for (const h of handoffs) if (!firstSeen.has(h.to)) firstSeen.set(h.to, h.call.start);
  const order = [];
  const visited = new Set();
  const visit = (start) => {
    const stack = [start];
    while (stack.length) {
      const lane = stack.pop();
      if (visited.has(lane)) continue;
      visited.add(lane);
      order.push(lane);
      const next = (outs.get(lane) || []).map((h) => h.to).filter((l) => !visited.has(l));
      for (let i = next.length - 1; i >= 0; i -= 1) stack.push(next[i]);
    }
  };
  if (rootLane) visit(rootLane);
  for (const [lane] of [...firstSeen.entries()].sort((a, b) => a[1] - b[1])) visit(lane);

  const laneIndex = new Map(order.map((id, i) => [id, i]));
  const colors = assignColors(order, rootLane);
  const lanes = order.map((id, index) => {
    const parts = id.replace(/^agent:/, "").split("/");
    return { id, index, name: displayName(id), short: parts[parts.length - 1], namespace: parts[0] || null, service: parts.length > 2 ? parts[1] : null, isRoot: id === rootLane, model: null, provider: null };
  });
  for (const s of spans) {
    if (s.kind !== "model_call") continue;
    const lane = lanes[laneIndex.get(laneOf(s))];
    if (!lane) continue;
    if (!lane.model || (lane.fallbackOnly && !s.fallback)) {
      const m = splitModel(s.callee);
      lane.model = m.model;
      lane.provider = m.provider;
      lane.fallbackOnly = s.fallback;
    }
  }

  // Drawable items.
  const tracks = [];
  const blocks = [];
  const waits = [];
  const segsByInv = new Map();
  for (const s of spans) {
    if (hidden.has(s.key)) continue;
    const lane = laneOf(s);
    if (!laneIndex.has(lane)) continue;
    const failed = s.status === "error" || s.status === "denied";
    const item = { key: s.key, span: s, lane, laneIndex: laneIndex.get(lane), failed, type: s.segment };
    if (s.segment === "invocation") {
      tracks.push(item);
      continue;
    }
    if (s.segment === "waiting" && !failed) waits.push(item);
    else blocks.push(item);
    const inv = invOf(s);
    if (inv) {
      const list = segsByInv.get(inv.key) || [];
      list.push(item);
      segsByInv.set(inv.key, list);
    }
  }
  // A failed invocation with nothing inside it (e.g. denied on arrival) is drawn as a failed block.
  for (const t of tracks) {
    if (t.failed && !(segsByInv.get(t.key) || []).length) {
      blocks.push({ ...t, key: `${t.key}:block`, type: "invocation" });
      t.empty = true;
    }
  }

  // Overlapping blocks in a lane (parallel tool calls, two invocations of one agent) get sub-rows.
  const laneRows = new Map();
  const rowEnds = new Map();
  for (const b of blocks.sort((a, c) => a.span.start - c.span.start)) {
    const ends = rowEnds.get(b.lane) || [];
    let row = ends.findIndex((e) => e <= b.span.start);
    if (row < 0) {
      row = ends.length;
      ends.push(0);
    }
    ends[row] = b.span.end === null ? Infinity : b.span.end;
    rowEnds.set(b.lane, ends);
    b.row = row;
    laneRows.set(b.lane, Math.max(laneRows.get(b.lane) || 1, row + 1));
  }

  // Header totals: model calls by end time, with prefix sums.
  const models = spans.filter((s) => s.kind === "model_call" && s.end !== null).sort((a, b) => a.end - b.end);
  const ends = new Float64Array(models.length);
  const tokens = new Float64Array(models.length + 1);
  const costs = new Float64Array(models.length + 1);
  models.forEach((m, i) => {
    ends[i] = m.end;
    tokens[i + 1] = tokens[i] + (m.tokens_in || 0) + (m.tokens_out || 0);
    costs[i + 1] = costs[i] + (m.cost_usd || 0);
  });

  let lastKnownAt = runStart;
  for (const s of spans) lastKnownAt = Math.max(lastKnownAt ?? s.start, s.start, s.end ?? s.start);
  // A finished run plays to its last span: model calls reported after the root returned (e.g. the
  // learning reflection, accepted up to 120 s later) are part of it.
  const endAt = runEnd === null ? null : Math.max(runEnd, lastKnownAt);

  return {
    version: model.version,
    spans,
    root,
    rootLane,
    runStart,
    runEnd,
    endAt,
    status,
    lanes,
    laneIndex,
    colors,
    laneRows,
    tracks,
    blocks,
    waits,
    handoffs,
    segsByInv,
    lastKnownAt,
    totals: { ends, tokens, costs },
    merged: model.merged,
  };
}

/** Tokens and cost of the model calls that ended at or before `at` (absolute ms). */
export function totalsAt(derived, at) {
  const { ends, tokens, costs } = derived.totals;
  let lo = 0;
  let hi = ends.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (ends[mid] <= at) lo = mid + 1;
    else hi = mid;
  }
  return { tokens: tokens[lo], cost: costs[lo] };
}

/**
 * Open Thinking segments at time `at` (absolute ms): for each invocation that is still running in
 * the data (no end yet) and has no tool or agent call open at `at`, the time since its last segment
 * (model-call starts are not reported live).
 */
export function openThinking(derived, at) {
  const out = [];
  for (const t of derived.tracks) {
    const inv = t.span;
    if (inv.end !== null || inv.start > at) continue;
    const segs = derived.segsByInv.get(inv.key) || [];
    let lastEnd = inv.start;
    let open = false;
    for (const it of segs) {
      const s = it.span;
      if (s.start > at) continue;
      if (s.end === null || s.end > at) {
        open = true;
        break;
      }
      if (s.end > lastEnd) lastEnd = s.end;
    }
    if (open || at - lastEnd < 40) continue;
    out.push({ key: `open:${inv.key}`, lane: t.lane, laneIndex: t.laneIndex, type: "thinking", open: true, failed: false, row: 0, inv, start: lastEnd });
  }
  return out;
}

// ---- run summaries (the run list) -------------------------------------------------------------

/** A TraceSummary normalised for the list (times in ms). */
export function normaliseSummary(s) {
  const agents = Array.isArray(s.agents) ? s.agents.length : num(s.agents) || 0;
  return {
    trace_id: s.trace_id,
    title: typeof s.title === "string" && s.title ? s.title : null,
    root_agent: s.root_agent || null,
    root_request_id: s.root_request_id || null,
    started: parseTime(s.started_at),
    ended: parseTime(s.ended_at),
    duration_ms: num(s.duration_ms),
    status: STATUSES.includes(s.status) ? s.status : "ok",
    agents,
    invocations: num(s.invocations) || 0,
    model_calls: num(s.model_calls) || 0,
    tool_calls: num(s.tool_calls) || 0,
    tokens_in: num(s.tokens_in) || 0,
    tokens_out: num(s.tokens_out) || 0,
    cost_usd: num(s.cost_usd) || 0,
    root_span_id: typeof s.root_span_id === "string" ? s.root_span_id : null,
    seen: new Set(),
  };
}

export function summaryTitle(sum) {
  if (sum.title) return sum.title;
  const name = sum.root_agent ? sum.root_agent.split("/").pop() : "run";
  return `${name} · ${String(sum.trace_id).slice(0, 8)}`;
}

/** A summary for a run first seen through its root span start (its counts then come from events). */
export function summaryFromRootStart(ev) {
  const sum = normaliseSummary({
    root_span_id: ev.span_id,
    trace_id: ev.trace_id,
    title: null,
    root_agent: ev.agent_node || `agent:${ev.namespace}/${ev.service}/${ev.agent}`,
    root_request_id: ev.request_id,
    started_at: ev.ts,
    ended_at: null,
    duration_ms: null,
    status: "running",
    agents: 1,
    invocations: 1,
  });
  sum.liveCounts = true;
  sum.seen.add(`a:${sum.root_agent}`);
  return sum;
}

/**
 * The root invocation of a run: invoked by the local app (caller `local`, no caller agent), or
 * without a parent. An app that sends a W3C `traceparent` gives its root a parent span id that is
 * not in the trace, so a parent alone does not make an invocation a sub-agent's.
 */
export function isRootInvocation(r) {
  return Boolean(r) && r.kind === "agent_invocation" && (!r.parent_span_id || (r.caller === "local" && !r.caller_agent));
}

export function isRootStart(ev) {
  return isRootInvocation(ev);
}

/** Whether `r` (span start or audit record) is the root invocation of the run `sum` describes. */
function isSummaryRoot(sum, r, node) {
  if (sum.root_span_id) return r.span_id === sum.root_span_id;
  return isRootInvocation(r) && (!sum.root_agent || !node || node === sum.root_agent);
}

/** Keep a run-list summary current from one SSE event. Returns true when it changed. */
export function applyEventToSummary(sum, type, data) {
  if (!sum) return false;
  if (type === "span_start") {
    if (data.kind === "agent_invocation" && !sum.seen.has(`i:${data.span_id}`)) {
      sum.seen.add(`i:${data.span_id}`);
      const node = data.agent_node || (data.agent ? `agent:${data.namespace}/${data.service}/${data.agent}` : null);
      if (!isSummaryRoot(sum, data, node)) {
        sum.invocations += 1;
        if (sum.liveCounts && node && !sum.seen.has(`a:${node}`)) {
          sum.seen.add(`a:${node}`);
          sum.agents += 1;
        }
      }
      return true;
    }
    return false;
  }
  if (type !== "audit" || !data || !data.record) return false;
  const rec = data.record;
  const seenKey = `${rec.kind}:${rec.span_id}`;
  if (sum.seen.has(seenKey)) return false;
  if (sum.seen.size > 5000) sum.seen.clear();
  sum.seen.add(seenKey);
  if (rec.kind === "model_call") {
    sum.model_calls += 1;
    if (rec.tokens) {
      sum.tokens_in += rec.tokens.input || 0;
      sum.tokens_out += rec.tokens.output || 0;
    }
    sum.cost_usd += rec.cost_usd || 0;
    return true;
  }
  if (rec.kind === "tool_call") {
    sum.tool_calls += 1;
    return true;
  }
  if (rec.kind === "agent_invocation" && isSummaryRoot(sum, rec, agentNodeFromRecord(rec))) {
    sum.root_span_id = sum.root_span_id || rec.span_id;
    sum.ended = parseTime(rec.ts);
    sum.duration_ms = num(rec.latency_ms);
    if (sum.started === null && sum.ended !== null) sum.started = sum.ended - (sum.duration_ms || 0);
    if (sum.started !== null && sum.ended !== null) sum.duration_ms = sum.ended - sum.started;
    sum.status = statusOfRecord(rec);
    if (rec.tokens) {
      sum.tokens_in = rec.tokens.input || 0;
      sum.tokens_out = rec.tokens.output || 0;
      sum.cost_usd = rec.cost_usd || 0;
    }
    return true;
  }
  return false;
}
