// The control-plane API client (docs/api/openapi.yaml). Every mutating call sends
// `Content-Type: application/json` and `X-Agentsc-CSRF: 1`; versions travel as quoted
// `If-Match` values. The session is the HttpOnly cookie from POST /login: the console never
// stores a token.
//
// The console always talks to the control plane that serves it (`embassy serve`): REST under
// `api/v1`, the live stream from `EventSource api/v1/events`. There is no offline or demo mode.
//
// Caching (docs/adr/0002-response-caching.md): the transport keeps the last body of every GET
// with its ETag and sends `If-None-Match` next time; a `304 Not Modified` is answered from the
// copy. Nothing is ever served without asking the control plane, so a mutation needs no
// invalidation; the cache only saves the payload of an unchanged graph, service list or trace.

const BASE = 'api/v1';

/** How many validated GET responses the transport keeps for `If-None-Match`. */
export const RESPONSE_CACHE_ENTRIES = 256;

/**
 * The last body per URL, with its ETag, least recently used first out. An entry without an
 * ETag is not kept: there is nothing to revalidate it with.
 */
export class ResponseCache {
  constructor(max = RESPONSE_CACHE_ENTRIES) {
    this.max = max;
    this.entries = new Map();
  }
  get size() {
    return this.entries.size;
  }
  get(key) {
    const e = this.entries.get(key);
    if (!e) return null;
    // Map keeps insertion order: re-insert to make it the most recent
    this.entries.delete(key);
    this.entries.set(key, e);
    return e;
  }
  set(key, entry) {
    if (!entry || typeof entry.etag !== 'string' || !entry.etag) return;
    this.entries.delete(key);
    this.entries.set(key, entry);
    while (this.entries.size > this.max) this.entries.delete(this.entries.keys().next().value);
  }
  delete(key) {
    this.entries.delete(key);
  }
  clear() {
    this.entries.clear();
  }
}

/** The absolute URL of the API for messages (`http://host:port/api/v1`). */
export function apiUrl(base = BASE) {
  try {
    return new URL(base, globalThis.location.href).href.replace(/\/$/, '');
  } catch {
    return base;
  }
}

/**
 * True when an error means nothing that speaks the control-plane API answered: the network
 * failed, the path does not exist (a plain static server), a proxy failed, or the reply was not
 * the API's JSON.
 */
export function isUnreachable(e) {
  if (!e || typeof e.status !== 'number') return true;
  return e.status === 0 || e.status === 404 || e.status === 405 || e.status >= 500 || e.code === 'not_the_api';
}

export const SSE_TYPES = ['audit', 'graph', 'registry', 'config', 'ack', 'proposal', 'cp_audit', 'lagged', 'reset'];

export class ApiError extends Error {
  constructor(status, body, fallback) {
    const code = (body && typeof body.error === 'string' && body.error) || fallback || `http_${status}`;
    const details = body && Array.isArray(body.details) ? body.details.map(String) : [];
    super(details.length ? `${code}: ${details.join('; ')}` : code);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.currentVersion = body && typeof body.current_version === 'string' ? body.current_version : null;
  }
}

/** `"3"` (or `W/"3"`) → `3`; anything else → null. */
export function parseEtag(etag) {
  if (typeof etag !== 'string') return null;
  const m = /^(?:W\/)?"(\d+)"$/.exec(etag.trim());
  return m ? m[1] : null;
}

const seg = encodeURIComponent;

function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

/**
 * The HTTP transport: `(method, path, {headers, body}) → {status, etag, data}`. GETs are
 * conditional (`If-None-Match` from the cache; a 304 is answered from it, as a 200 with
 * `cached: true`). The browser's own cache stays off (`cache: 'no-store'`): the validation here
 * is the one that counts, and it works the same over HTTP/1.1, HTTP/2 and HTTP/3.
 */
export function httpTransport(base, { fetchImpl = (url, init) => globalThis.fetch(url, init), cache = new ResponseCache() } = {}) {
  const transport = async (method, path, { headers = {}, body } = {}) => {
    const url = `${base}${path}`;
    const conditional = method === 'GET' || method === 'HEAD';
    const cached = conditional ? cache.get(url) : null;
    const init = {
      method,
      headers: { Accept: 'application/json', ...headers },
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    };
    if (cached && init.headers['If-None-Match'] === undefined) init.headers['If-None-Match'] = cached.etag;
    if (body !== undefined) init.body = JSON.stringify(body);
    let res;
    try {
      res = await fetchImpl(url, init);
    } catch (e) {
      throw new ApiError(0, { error: 'network', details: [String((e && e.message) || e)] });
    }
    if (res.status === 304 && cached) return { status: 200, etag: cached.etag, data: cached.data, cached: true };
    let data = null;
    const type = res.headers.get('Content-Type') || '';
    if (res.status !== 204 && type.includes('json')) {
      try {
        data = await res.json();
      } catch {
        data = null;
      }
    }
    const etag = res.headers.get('ETag');
    if (conditional) {
      if (res.status === 200 && etag) cache.set(url, { etag, data });
      else if (res.status !== 304) cache.delete(url);
    }
    return { status: res.status, etag, data };
  };
  transport.cache = cache;
  return transport;
}

/** The live stream over EventSource (the session cookie authenticates it). */
function eventStream(base, { onEvent, onStatus }) {
  let es = null;
  let closed = false;
  let timer = null;
  let retry = 1000;
  let restarted = false;
  const open = () => {
    onStatus(restarted ? 'reconnecting' : 'connecting');
    es = new EventSource(`${base}/events`);
    es.onopen = () => {
      retry = 1000;
      onStatus('live');
      // A new EventSource cannot resume (no Last-Event-ID): refetch like after `reset`.
      if (restarted) onEvent('reset', {}, null);
    };
    for (const type of SSE_TYPES) {
      es.addEventListener(type, (ev) => {
        let data;
        try {
          data = JSON.parse(ev.data);
        } catch {
          return;
        }
        onEvent(type, data, ev.lastEventId);
      });
    }
    es.onerror = () => {
      if (closed) return;
      if (es.readyState === EventSource.CLOSED) {
        onStatus('offline');
        es.close();
        restarted = true;
        timer = setTimeout(open, retry);
        retry = Math.min(retry * 2, 30000);
      } else {
        onStatus('reconnecting');
      }
    };
  };
  open();
  return {
    close() {
      closed = true;
      clearTimeout(timer);
      if (es) es.close();
      onStatus('paused');
    },
  };
}

export class Api {
  constructor(transport, { now, subscribe, baseUrl = BASE } = {}) {
    this.transport = transport;
    this.now = now;
    this.subscribeImpl = subscribe;
    this.baseUrl = baseUrl;
    this.onUnauthenticated = null;
  }

  async call(method, path, { body, ifMatch, ifNoneMatch, q } = {}) {
    const headers = {};
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      headers['X-Agentsc-CSRF'] = '1';
    }
    if (ifMatch !== undefined && ifMatch !== null) headers['If-Match'] = `"${ifMatch}"`;
    if (ifNoneMatch) headers['If-None-Match'] = '*';
    const r = await this.transport(method, path + query(q), { headers, body });
    if (r.status >= 200 && r.status < 300) return { data: r.data, version: parseEtag(r.etag) };
    const e = new ApiError(r.status, r.data);
    if (r.status === 401 && this.onUnauthenticated && !path.startsWith('/login')) this.onUnauthenticated(e);
    throw e;
  }

  // session
  whoami() {
    return this.call('GET', '/whoami');
  }
  login(token) {
    return this.call('POST', '/login', { body: { token } });
  }
  logout() {
    return this.call('POST', '/logout').finally(() => this.clearCache());
  }
  /** Forget the transport's validated copies (another session may be shown other data). */
  clearCache() {
    if (this.transport && this.transport.cache) this.transport.cache.clear();
  }

  // graph and services
  graph() {
    return this.call('GET', '/graph');
  }
  services() {
    return this.call('GET', '/services');
  }

  // charters
  charter(ns, svc) {
    return this.call('GET', `/services/${seg(ns)}/${seg(svc)}/charter`);
  }
  putCharter(ns, svc, yaml, version) {
    return this.call('PUT', `/services/${seg(ns)}/${seg(svc)}/charter`, {
      body: { yaml },
      ifMatch: version,
      ifNoneMatch: version == null,
    });
  }
  validateCharter(ns, svc, yaml) {
    return this.call('POST', `/services/${seg(ns)}/${seg(svc)}/charter/validate`, { body: { yaml } });
  }
  history(ns, svc) {
    return this.call('GET', `/services/${seg(ns)}/${seg(svc)}/charter/history`);
  }
  adopt(ns, svc, sha256) {
    return this.call('POST', `/services/${seg(ns)}/${seg(svc)}/adopt`, { body: { sha256 } });
  }

  // agents
  agent(ns, svc, name) {
    return this.call('GET', `/services/${seg(ns)}/${seg(svc)}/agents/${seg(name)}`);
  }
  createAgent(ns, svc, view, version) {
    return this.call('POST', `/services/${seg(ns)}/${seg(svc)}/agents`, { body: view, ifMatch: version });
  }
  putAgent(ns, svc, name, view, version) {
    return this.call('PUT', `/services/${seg(ns)}/${seg(svc)}/agents/${seg(name)}`, { body: view, ifMatch: version });
  }
  link(body) {
    return this.call('POST', '/links', { body });
  }

  // memory and proposals
  memory(ns, svc) {
    return this.call('GET', `/services/${seg(ns)}/${seg(svc)}/memory`);
  }
  putMemory(ns, svc, agents, version) {
    return this.call('PUT', `/services/${seg(ns)}/${seg(svc)}/memory`, { body: { agents }, ifMatch: version });
  }
  proposals(q) {
    return this.call('GET', '/proposals', { q });
  }
  decide(id, action, memoryVersion) {
    return this.call('POST', `/proposals/${seg(id)}/${action === 'approve' ? 'approve' : 'reject'}`, { ifMatch: memoryVersion });
  }

  // events
  recent(q) {
    return this.call('GET', '/events/recent', { q });
  }
  subscribe(handlers) {
    return this.subscribeImpl(handlers);
  }
}

/** The client for the control plane that serves this page. */
export function createApi() {
  return new Api(httpTransport(BASE), { now: () => Date.now(), subscribe: (h) => eventStream(BASE, h), baseUrl: apiUrl(BASE) });
}
