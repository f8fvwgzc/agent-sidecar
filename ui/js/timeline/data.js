// Data access for the timeline: the control-plane API (`/api/v1`, design §10.1.1 and §10.2).
//
// A source has three methods (the console may pass its own object with the same shape):
//   listTraces({limit, namespace, service, agent, status}) → Promise<TraceSummary[]>, newest first
//   getTrace(traceId)                                      → Promise<{trace_id, spans: Span[]}>
//   subscribe(handler, {namespace, service})               → unsubscribe function
// `handler({type, data})` receives `span_start` and `audit` events (their SSE payloads), `reset`
// (refetch everything) and `status` ({connected}). Nothing here mutates server state.

const EVENT_TYPES = ["span_start", "audit"];

function absolute(base) {
  try {
    return new URL(base, globalThis.location.href).href.replace(/\/$/, "");
  } catch {
    return base;
  }
}

class SourceError extends Error {
  constructor(message, status) {
    super(message);
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

  unreachable(status) {
    return new SourceError(`Cannot reach the control plane at ${absolute(this.base)} — start embassy serve.`, status);
  }

  /** GET `path`; `notFound` is the message for a 404 from a control plane that is there. */
  async _get(path, notFound) {
    let res;
    try {
      res = await this.fetch(this.base + path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    } catch {
      throw this.unreachable(0);
    }
    if (res.status === 401) throw new SourceError("Sign in to see runs.", 401);
    if (res.status === 403) throw new SourceError("Your token may not see these runs.", 403);
    if (res.status === 404 && notFound) throw new SourceError(notFound, 404);
    if (res.status === 404 || res.status === 405 || res.status >= 500) throw this.unreachable(res.status);
    if (!res.ok) throw new SourceError(`The control plane answered HTTP ${res.status} for ${path}.`, res.status);
    const type = (res.headers && res.headers.get && res.headers.get("Content-Type")) || "";
    if (!type.includes("json")) throw this.unreachable(res.status);
    try {
      return await res.json();
    } catch {
      throw this.unreachable(res.status);
    }
  }

  async listTraces({ limit = 50, namespace, service, agent, status } = {}) {
    const rows = await this._get(`/traces${query({ limit, namespace, service, agent, status })}`);
    if (!Array.isArray(rows)) throw this.unreachable(200);
    return rows;
  }

  getTrace(traceId) {
    return this._get(`/traces/${encodeURIComponent(traceId)}`, "This run is no longer available.");
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

/** A source for `mountTimeline`: the console's own object, or the API with these options ({baseUrl}). */
export function createTimelineSource(api) {
  if (api && typeof api.listTraces === "function" && typeof api.getTrace === "function") return api;
  return new ApiSource(api || {});
}
