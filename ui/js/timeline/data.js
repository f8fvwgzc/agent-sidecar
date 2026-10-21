// Data access for the timeline: the control-plane API, or the golden fixtures (`?fixtures=1`).
//
// A source has three methods (the console may pass its own object with the same shape):
//   listTraces({limit, namespace, service, agent, status}) → Promise<TraceSummary[]>, newest first
//   getTrace(traceId)                                      → Promise<{trace_id, spans: Span[]}>
//   subscribe(handler, {namespace, service})               → unsubscribe function
// `handler({type, data})` receives `span_start` and `audit` events (their SSE payloads), `reset`
// (refetch everything) and `status` ({connected}). Nothing here mutates server state.

import { TraceModel, applyEventToSummary, isRootStart, normaliseSummary, parseTime, summaryFromRootStart } from "./model.js";

const EVENT_TYPES = ["span_start", "audit"];

class HttpError extends Error {
  constructor(status, path) {
    super(status === 401 ? "Sign in to see runs." : status === 403 ? "Your token may not see these runs." : `Request failed (${status}) for ${path}`);
    this.status = status;
  }
}

function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** The control-plane API (`/api/v1`). Credentials are same-origin; every call is a GET. */
export class ApiSource {
  constructor({ baseUrl = "/api/v1", fetchImpl, eventSourceImpl } = {}) {
    this.base = baseUrl.replace(/\/$/, "");
    this.fetch = fetchImpl || ((...a) => globalThis.fetch(...a));
    this.EventSource = eventSourceImpl || globalThis.EventSource;
  }

  async _get(path) {
    const res = await this.fetch(this.base + path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!res.ok) throw new HttpError(res.status, path);
    return res.json();
  }

  listTraces({ limit = 50, namespace, service, agent, status } = {}) {
    return this._get(`/traces${query({ limit, namespace, service, agent, status })}`);
  }

  getTrace(traceId) {
    return this._get(`/traces/${encodeURIComponent(traceId)}`);
  }

  subscribe(handler, { namespace, service } = {}) {
    if (!this.EventSource) return () => {};
    const es = new this.EventSource(`${this.base}/events${query({ namespace, service })}`);
    const on = (type) => (e) => {
      let data = null;
      try {
        data = e.data ? JSON.parse(e.data) : null;
      } catch {
        return;
      }
      handler({ type, data, id: e.lastEventId || null });
    };
    for (const t of EVENT_TYPES) es.addEventListener(t, on(t));
    // `reset`: the server could not replay from Last-Event-ID; `lagged`: our queue overflowed.
    es.addEventListener("reset", () => handler({ type: "reset", data: null }));
    es.addEventListener("lagged", () => handler({ type: "reset", data: null }));
    es.addEventListener("open", () => handler({ type: "status", data: { connected: true } }));
    es.addEventListener("error", () => handler({ type: "status", data: { connected: es.readyState === 1 } }));
    return () => es.close();
  }
}

// ---- fixtures ---------------------------------------------------------------------------------

/** Parse an SSE transcript into [{id, type, data}] plus its comment lines. */
export function parseSse(text) {
  const events = [];
  const comments = [];
  for (const block of String(text).split(/\r?\n\r?\n/)) {
    let type = "message";
    let id = null;
    const data = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith(":")) comments.push(line.slice(1).trim());
      else if (line.startsWith("event:")) type = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
      else if (line.startsWith("id:")) id = line.slice(3).trim();
    }
    if (!data.length) continue;
    try {
      events.push({ id, type, data: JSON.parse(data.join("\n")) });
    } catch {
      // not JSON: ignore
    }
  }
  return { events, comments };
}

function eventTime(ev) {
  if (ev.type === "span_start") return parseTime(ev.data.ts);
  if (ev.type === "audit") return parseTime(ev.data && ev.data.record && ev.data.record.ts);
  return null;
}

const shiftIso = (v, offset) => (typeof v === "string" && v ? new Date(Date.parse(v) + offset).toISOString() : v);

function shiftSummary(s, offset) {
  return { ...s, started_at: shiftIso(s.started_at, offset), ended_at: shiftIso(s.ended_at, offset) };
}

function shiftSpan(s, offset) {
  return {
    ...s,
    start: shiftIso(s.start, offset),
    end: shiftIso(s.end, offset),
    events: (s.events || []).map((e) => ({ ...e, ts: shiftIso(e.ts, offset) })),
  };
}

function rewriteEvent(ev, offset, ids) {
  const sub = (v) => (typeof v === "string" && ids[v] ? ids[v] : v);
  if (ev.type === "span_start") {
    return { type: ev.type, id: ev.id, data: { ...ev.data, ts: shiftIso(ev.data.ts, offset), trace_id: sub(ev.data.trace_id), request_id: sub(ev.data.request_id) } };
  }
  const r = ev.data.record;
  const record = { ...r, ts: shiftIso(r.ts, offset), trace_id: sub(r.trace_id), request_id: sub(r.request_id) };
  return { type: ev.type, id: ev.id, data: { ...ev.data, record } };
}

function loopId(id, n) {
  const hex = (n & 0xffff).toString(16).padStart(4, "0");
  return id.slice(0, id.length - 4) + hex;
}

/**
 * The golden fixtures. Times are moved so that the running run's snapshot is "now"; then the
 * rest of `timeline-live.sse` is replayed on a timer, and afterwards the same run is replayed from
 * its start under a new trace id every so often, so the run list keeps getting live runs.
 */
export class FixtureSource {
  constructor({ fixturesUrl = "fixtures/", loop = true, loopGapMs = 6000 } = {}) {
    this.base = fixturesUrl.endsWith("/") ? fixturesUrl : `${fixturesUrl}/`;
    this.loop = loop;
    this.loopGapMs = loopGapMs;
    this.handlers = new Set();
    this.summaries = new Map();
    this.models = new Map(); // simulated traces: id → TraceModel
    this.timer = 0;
    this.ready = null;
  }

  async _getJson(name) {
    const res = await fetch(this.base + name, { credentials: "same-origin" });
    if (!res.ok) throw new HttpError(res.status, name);
    return res.json();
  }

  _init() {
    if (!this.ready) this.ready = this._load();
    return this.ready;
  }

  async _load() {
    const [traces, sseText] = await Promise.all([
      this._getJson("traces.json"),
      fetch(`${this.base}timeline-live.sse`, { credentials: "same-origin" }).then((r) => (r.ok ? r.text() : "")),
    ]);
    const { events, comments } = parseSse(sseText);
    this.events = events
      .filter((e) => EVENT_TYPES.includes(e.type))
      .map((e) => ({ ...e, t: eventTime(e) }))
      .filter((e) => e.t !== null);
    this.events.sort((a, b) => a.t - b.t);
    this.liveTrace = this.events.length ? (this.events[0].data.trace_id || this.events[0].data.record.trace_id) : null;
    const snapComment = comments.find((c) => c.startsWith("snapshot "));
    let snapshot = snapComment ? parseTime(snapComment.slice(9).trim()) : null;
    let liveSpans = [];
    if (this.liveTrace) {
      const doc = await this._getJson(`trace-${this.liveTrace}.json`);
      liveSpans = doc.spans || [];
      if (snapshot === null) {
        for (const s of liveSpans) snapshot = Math.max(snapshot ?? 0, parseTime(s.start) || 0, parseTime(s.end) || 0);
      }
    }
    this.snapshot = snapshot ?? Date.now();
    this.offset = Date.now() - this.snapshot;
    for (const s of traces) this.summaries.set(s.trace_id, normaliseSummary(shiftSummary(s, this.offset)));
    if (this.liveTrace) {
      const m = new TraceModel(this.liveTrace);
      m.loadSpans(liveSpans.map((s) => shiftSpan(s, this.offset)));
      this.models.set(this.liveTrace, m);
      this.liveTitle = (traces.find((t) => t.trace_id === this.liveTrace) || {}).title || null;
    }
    this.runStart = this.events.length ? this.events[0].t : this.snapshot;
    this.runEnd = this.events.length ? this.events[this.events.length - 1].t : this.snapshot;
    // First pass: what comes after the snapshot, in real time.
    this.pass = { n: 0, base: Date.now(), from: this.snapshot, offset: this.offset, ids: {}, i: this.events.findIndex((e) => e.t > this.snapshot) };
    if (this.pass.i < 0) this.pass.i = this.events.length;
  }

  async listTraces({ limit = 50, namespace, service, agent, status } = {}) {
    await this._init();
    const rows = [...this.summaries.values()]
      .filter((s) => {
        const parts = (s.root_agent || "").replace(/^agent:/, "").split("/");
        if (namespace && parts[0] !== namespace) return false;
        if (service && parts[1] !== service) return false;
        if (agent && parts[2] !== agent) return false;
        if (status && s.status !== status) return false;
        return true;
      })
      .sort((a, b) => (b.started || 0) - (a.started || 0))
      .slice(0, limit);
    return rows.map((s) => ({
      trace_id: s.trace_id,
      title: s.title,
      root_agent: s.root_agent,
      root_request_id: s.root_request_id,
      started_at: s.started === null ? null : new Date(s.started).toISOString(),
      ended_at: s.ended === null ? null : new Date(s.ended).toISOString(),
      duration_ms: s.duration_ms,
      status: s.status,
      agents: s.agents,
      invocations: s.invocations,
      model_calls: s.model_calls,
      tool_calls: s.tool_calls,
      tokens_in: s.tokens_in,
      tokens_out: s.tokens_out,
      cost_usd: Math.round(s.cost_usd * 1e6) / 1e6,
    }));
  }

  async getTrace(traceId) {
    await this._init();
    const m = this.models.get(traceId);
    if (m) return { trace_id: traceId, spans: m.toSpans() };
    if (!/^[0-9a-f]{32}$/.test(traceId)) throw new HttpError(404, traceId);
    const doc = await this._getJson(`trace-${traceId}.json`);
    return { trace_id: doc.trace_id, spans: (doc.spans || []).map((s) => shiftSpan(s, this.offset)) };
  }

  subscribe(handler) {
    this.handlers.add(handler);
    this._init()
      .then(() => {
        if (!this.handlers.has(handler)) return;
        handler({ type: "status", data: { connected: true } });
        this._schedule(0);
      })
      .catch(() => handler({ type: "status", data: { connected: false } }));
    return () => {
      this.handlers.delete(handler);
      if (!this.handlers.size) {
        clearTimeout(this.timer);
        this.timer = 0;
      }
    };
  }

  _schedule(delay) {
    if (this.timer || !this.handlers.size) return;
    this.timer = setTimeout(() => {
      this.timer = 0;
      this._tick();
    }, delay);
  }

  _tick() {
    const p = this.pass;
    const now = Date.now();
    const at = p.from + (now - p.base); // fixture time reached by this pass
    while (p.i < this.events.length && this.events[p.i].t <= at) {
      this._emit(rewriteEvent(this.events[p.i], p.offset, p.ids));
      p.i += 1;
    }
    if (p.i < this.events.length) {
      this._schedule(Math.min(250, Math.max(10, this.events[p.i].t - at)));
      return;
    }
    if (!this.loop) return;
    // Start the next pass after a pause: the same run again, from its start, as a new trace.
    const n = p.n + 1;
    const base = now + this.loopGapMs;
    const ids = {};
    const first = this.events[0];
    const traceId = first.data.trace_id || first.data.record.trace_id;
    const reqId = first.data.request_id || first.data.record.request_id;
    ids[traceId] = loopId(traceId, n);
    ids[reqId] = loopId(reqId, n);
    this.pass = { n, base, from: this.runStart, offset: base - this.runStart, ids, i: 0 };
    const model = new TraceModel(ids[traceId]);
    this.models.set(ids[traceId], model);
    if (this.models.size > 20) this.models.delete(this.models.keys().next().value);
    this._schedule(this.loopGapMs);
  }

  _emit(ev) {
    const traceId = ev.type === "span_start" ? ev.data.trace_id : ev.data.record.trace_id;
    const model = this.models.get(traceId);
    if (model) {
      if (ev.type === "span_start") model.applySpanStart(ev.data);
      else model.applyAudit(ev.data.record);
    }
    let sum = this.summaries.get(traceId);
    if (!sum && ev.type === "span_start" && isRootStart(ev.data)) {
      sum = summaryFromRootStart(ev.data);
      sum.title = this.liveTitle;
      this.summaries.set(traceId, sum);
      if (this.summaries.size > 60) {
        const oldest = [...this.summaries.values()].sort((a, b) => a.started - b.started)[0];
        this.summaries.delete(oldest.trace_id);
      }
    }
    if (sum) applyEventToSummary(sum, ev.type, ev.data);
    for (const h of [...this.handlers]) {
      try {
        h(ev);
      } catch (err) {
        console.error("timeline: event handler failed", err);
      }
    }
  }
}

/** A source for `mountTimeline`: the console's own object, or one built from options and the URL. */
export function createTimelineSource(api) {
  if (api && typeof api.listTraces === "function" && typeof api.getTrace === "function") return api;
  const opts = api || {};
  const params = new URLSearchParams(globalThis.location ? globalThis.location.search : "");
  const fixtures = opts.fixtures ?? params.get("fixtures") === "1";
  if (fixtures) return new FixtureSource({ fixturesUrl: opts.fixturesUrl, loop: opts.loop ?? params.get("loop") !== "0" });
  return new ApiSource(opts);
}
