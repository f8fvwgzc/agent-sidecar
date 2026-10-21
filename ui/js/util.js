// Pure helpers shared by the console modules. No DOM and no d3: the node tests import
// this file directly (ui/tests/logic.test.mjs).

export const ROLES = ['viewer', 'editor', 'admin'];

/** True when `role` is at least `min` (viewer < editor < admin). Unknown roles are never enough. */
export function roleAtLeast(role, min) {
  const r = ROLES.indexOf(role);
  const m = ROLES.indexOf(min);
  return r >= 0 && m >= 0 && r >= m;
}

export const DNS_LABEL = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;
export const TOOL_NAME = /^[a-zA-Z0-9_-]{1,64}$/;
export const TOKEN_RE = /^att_[A-Za-z0-9_-]{43}$/;

export function utf8Length(s) {
  return new TextEncoder().encode(String(s)).length;
}

/** Design §3: non-empty, at most 128 bytes, no whitespace or control characters. */
export function isModelName(s) {
  // eslint-disable-next-line no-control-regex
  return typeof s === 'string' && s.length > 0 && utf8Length(s) <= 128 && !/[\s\u0000-\u001f\u007f]/.test(s);
}

/** Splits a graph node id (design §3) into its parts; null for anything else. */
export function parseNodeId(id) {
  if (typeof id !== 'string') return null;
  let m = /^(svc|app):([^/]+)\/([^/]+)$/.exec(id);
  if (m) return { kind: m[1], ns: m[2], svc: m[3] };
  m = /^agent:([^/]+)\/([^/]+)\/([^/]+)$/.exec(id);
  if (m) return { kind: 'agent', ns: m[1], svc: m[2], agent: m[3] };
  m = /^model:(.+)$/.exec(id);
  if (m) return { kind: 'model', provider: m[1] };
  m = /^external:(.+)$/.exec(id);
  if (m) return { kind: 'external', origin: m[1] };
  return null;
}

export const svcNodeId = (ns, svc) => `svc:${ns}/${svc}`;
export const appNodeId = (ns, svc) => `app:${ns}/${svc}`;
export const agentNodeId = (ns, svc, agent) => `agent:${ns}/${svc}/${agent}`;

/** The service (namespace and name) a node belongs to, from its id; null for providers and externals. */
export function serviceOf(node) {
  const p = parseNodeId(node && node.id);
  if (!p || !p.ns) return null;
  return { ns: p.ns, svc: p.svc };
}

// ---- formatting ------------------------------------------------------------------------------

export function fmtInt(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '–';
  return Math.round(n).toLocaleString('en-US');
}

export function fmtCompact(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '–';
  const a = Math.abs(n);
  if (a >= 1e6) return `${trimZero((n / 1e6).toFixed(1))}M`;
  if (a >= 1e3) return `${trimZero((n / 1e3).toFixed(1))}k`;
  return String(Math.round(n));
}

function trimZero(s) {
  return s.endsWith('.0') ? s.slice(0, -2) : s;
}

export function fmtMs(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '–';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60000) return `${trimZero((ms / 1000).toFixed(1))} s`;
  const m = Math.floor(ms / 60000);
  const s = Math.round((ms % 60000) / 1000);
  return `${m} min ${s} s`;
}

export function fmtCost(usd) {
  if (typeof usd !== 'number' || !Number.isFinite(usd)) return '–';
  if (usd === 0) return '$0';
  if (usd >= 0.1) return `$${usd.toFixed(2)}`;
  if (usd >= 0.001) return `$${usd.toFixed(3)}`;
  return `$${usd.toFixed(4)}`;
}

export function parseTs(ts) {
  if (typeof ts !== 'string') return NaN;
  return Date.parse(ts);
}

/** "just now", "12 s ago", "5 min ago", "3 h ago", "2 d ago" (or "in …" for the future). */
export function relTime(ts, now) {
  const t = typeof ts === 'number' ? ts : parseTs(ts);
  if (!Number.isFinite(t) || !Number.isFinite(now)) return '–';
  const d = now - t;
  const a = Math.abs(d);
  let s;
  if (a < 5000) return 'just now';
  if (a < 60000) s = `${Math.round(a / 1000)} s`;
  else if (a < 3600000) s = `${Math.round(a / 60000)} min`;
  else if (a < 86400000) s = `${Math.round(a / 3600000)} h`;
  else s = `${Math.round(a / 86400000)} d`;
  return d >= 0 ? `${s} ago` : `in ${s}`;
}

/** A duration in seconds as "19 h 40 min"; negative values read "expired … ago". */
export function fmtSeconds(sec) {
  if (typeof sec !== 'number' || !Number.isFinite(sec)) return '–';
  const a = Math.abs(sec);
  let s;
  if (a < 60) s = `${Math.round(a)} s`;
  else if (a < 3600) s = `${Math.round(a / 60)} min`;
  else if (a < 86400) s = `${Math.floor(a / 3600)} h ${Math.round((a % 3600) / 60)} min`;
  else s = `${Math.floor(a / 86400)} d ${Math.round((a % 86400) / 3600)} h`;
  return sec < 0 ? `expired ${s} ago` : s;
}

export function fmtClock(ts) {
  const t = parseTs(ts);
  if (!Number.isFinite(t)) return '–';
  const d = new Date(t);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function shortId(s, n = 8) {
  if (typeof s !== 'string') return '';
  return s.length > n ? s.slice(0, n) : s;
}

// ---- audit records ---------------------------------------------------------------------------

/** allow | deny | error, the colour of a record (and of its dot on the canvas). */
export function outcomeOf(record) {
  if (!record) return 'allow';
  if (record.error) return 'error';
  if (record.decision === 'deny') return 'deny';
  return 'allow';
}

function tsOrder(a, b) {
  const x = parseTs(a.ts);
  const y = parseTs(b.ts);
  if (Number.isFinite(x) && Number.isFinite(y) && x !== y) return x - y;
  return 0;
}

/**
 * Groups audit records by request_id. Groups come newest first; records inside a group oldest
 * first (the order the trail happened in). Each group has its root invocation (the
 * agent_invocation without a parent span, else the last agent_invocation) and counts.
 */
export function groupByRequest(records) {
  const groups = new Map();
  for (const r of records || []) {
    if (!r || typeof r !== 'object') continue;
    const key = typeof r.request_id === 'string' && r.request_id ? r.request_id : '(none)';
    let g = groups.get(key);
    if (!g) {
      g = { request_id: key, records: [] };
      groups.set(key, g);
    }
    g.records.push(r);
  }
  const out = [];
  for (const g of groups.values()) {
    g.records = g.records
      .map((r, i) => [r, i])
      .sort((a, b) => tsOrder(a[0], b[0]) || b[1] - a[1])
      .map(([r]) => r);
    g.first = g.records[0].ts;
    g.last = g.records[g.records.length - 1].ts;
    const invocations = g.records.filter((r) => r.kind === 'agent_invocation');
    g.root = invocations.find((r) => !r.parent_span_id) || invocations[invocations.length - 1] || null;
    g.denied = g.records.filter((r) => r.decision === 'deny').length;
    g.errors = g.records.filter((r) => r.error).length;
    g.outcome = g.root ? outcomeOf(g.root) : g.errors ? 'error' : g.denied ? 'deny' : 'allow';
    out.push(g);
  }
  out.sort((a, b) => {
    const x = parseTs(a.last);
    const y = parseTs(b.last);
    return (Number.isFinite(y) ? y : 0) - (Number.isFinite(x) ? x : 0);
  });
  return out;
}

/** A short human summary of a record's input (the question asked, the HTTP call, ...). */
export function inputSummary(record) {
  const v = record && record.input;
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'object') {
    if (typeof v.input === 'string') return v.input;
    if (typeof v.method === 'string' && typeof v.path === 'string') return `${v.method} ${v.path}`;
  }
  return '';
}

/**
 * How to show an audit payload: `hidden` (the token may not see payloads), `absent` (null but a
 * hash exists: not sent or withheld), `null`, or `value`.
 */
export function payloadState(value, sha256, canSee) {
  if (!canSee) return 'hidden';
  if (value === null || value === undefined) return sha256 ? 'absent' : 'null';
  return 'value';
}

/** The text a payload shows in a <pre>: strings as they are, everything else as indented JSON. */
export function payloadText(value) {
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

// ---- instances -------------------------------------------------------------------------------

/** The charter ack chip of one instance: pending, ✓ vN, or ✗ vN with the error. */
export function instanceChip(inst, charterVersion) {
  if (inst && inst.ack_error) {
    return { state: 'error', label: `✗ v${inst.acked_version ?? '?'}`, title: inst.ack_error };
  }
  if (inst && charterVersion != null && inst.acked_version === charterVersion) {
    return { state: 'ok', label: `✓ v${charterVersion}`, title: `applied charter v${charterVersion}` };
  }
  const last = inst && inst.acked_version != null ? `; last applied v${inst.acked_version}` : '';
  return {
    state: 'pending',
    label: 'pending',
    title: charterVersion != null ? `waiting for v${charterVersion}${last}` : `no stored charter${last}`,
  };
}

// ---- object paths and diffs --------------------------------------------------------------------

export function pathString(keys) {
  let s = '';
  for (const k of keys) {
    if (typeof k === 'number') s += `[${k}]`;
    else s += s ? `.${k}` : k;
  }
  return s;
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function sameValue(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Leaf differences between two JSON values: [{keys, path, before, after}]. Objects recurse by
 * key; arrays of equal length recurse by index; arrays of different length are one change.
 * A missing key is `undefined`.
 */
export function diffPaths(a, b, keys = []) {
  if (sameValue(a, b)) return [];
  if (isPlainObject(a) && isPlainObject(b)) {
    const names = [...new Set([...Object.keys(a), ...Object.keys(b)])];
    return names.flatMap((k) => diffPaths(a[k], b[k], [...keys, k]));
  }
  if (Array.isArray(a) && Array.isArray(b) && a.length === b.length) {
    return a.flatMap((x, i) => diffPaths(x, b[i], [...keys, i]));
  }
  return [{ keys, path: pathString(keys), before: a, after: b }];
}

export function getIn(obj, keys) {
  let cur = obj;
  for (const k of keys) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[k];
  }
  return cur;
}

/** Sets (or, for `undefined`, deletes) the value at `keys`, creating containers on the way. */
export function setIn(obj, keys, value) {
  if (!keys.length) return value;
  let cur = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const k = keys[i];
    if (cur[k] == null || typeof cur[k] !== 'object') cur[k] = typeof keys[i + 1] === 'number' ? [] : {};
    cur = cur[k];
  }
  const last = keys[keys.length - 1];
  if (value === undefined) {
    if (Array.isArray(cur) && typeof last === 'number') cur.splice(last, 1);
    else delete cur[last];
  } else {
    cur[last] = value;
  }
  return obj;
}

export function applyPaths(target, changes) {
  let out = target;
  for (const c of changes) out = setIn(out, c.keys, clone(c.after));
  return out;
}

/**
 * The changed part of two strings with a little context: common prefix and suffix are cut to
 * `ctx` characters and replaced by "…", so a one-word edit in a long prompt stays visible.
 */
export function stringChange(a, b, ctx = 24) {
  const x = String(a);
  const y = String(b);
  let p = 0;
  while (p < x.length && p < y.length && x[p] === y[p]) p++;
  let s = 0;
  while (s < x.length - p && s < y.length - p && x[x.length - 1 - s] === y[y.length - 1 - s]) s++;
  const cut = (str) => {
    const start = Math.max(0, p - ctx);
    const end = Math.min(str.length, str.length - s + ctx);
    return `${start > 0 ? '…' : ''}${str.slice(start, end)}${end < str.length ? '…' : ''}`;
  };
  return { before: cut(x), after: cut(y) };
}

/** Paths both sides changed (equal paths or one inside the other). */
export function overlappingPaths(mine, theirs) {
  const inside = (a, b) => a.length <= b.length && a.every((k, i) => k === b[i]);
  return mine.filter((m) => theirs.some((t) => inside(m.keys, t.keys) || inside(t.keys, m.keys))).map((m) => m.path);
}

export function clone(v) {
  return v === undefined ? undefined : JSON.parse(JSON.stringify(v));
}

/**
 * Line diff of two texts (LCS). Returns [{op: ' ' | '-' | '+', text}] or null when the texts
 * are too large to diff in the browser.
 */
export function diffLines(a, b, maxCells = 4_000_000) {
  const x = String(a).split('\n');
  const y = String(b).split('\n');
  const n = x.length;
  const m = y.length;
  if ((n + 1) * (m + 1) > maxCells) return null;
  const w = m + 1;
  const t = new Int32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      t[i * w + j] = x[i] === y[j] ? t[(i + 1) * w + j + 1] + 1 : Math.max(t[(i + 1) * w + j], t[i * w + j + 1]);
    }
  }
  const out = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push({ op: ' ', text: x[i] });
      i++;
      j++;
    } else if (t[(i + 1) * w + j] >= t[i * w + j + 1]) {
      out.push({ op: '-', text: x[i++] });
    } else {
      out.push({ op: '+', text: y[j++] });
    }
  }
  while (i < n) out.push({ op: '-', text: x[i++] });
  while (j < m) out.push({ op: '+', text: y[j++] });
  return out;
}

/** Keeps changed lines plus `context` lines around them; gaps become {op: '…', text}. */
export function diffHunks(ops, context = 2) {
  if (!ops) return null;
  const keep = new Array(ops.length).fill(false);
  ops.forEach((o, i) => {
    if (o.op !== ' ') for (let k = Math.max(0, i - context); k <= Math.min(ops.length - 1, i + context); k++) keep[k] = true;
  });
  const out = [];
  let gap = 0;
  ops.forEach((o, i) => {
    if (keep[i]) {
      if (gap) out.push({ op: '…', text: `${gap} unchanged line${gap === 1 ? '' : 's'}` });
      gap = 0;
      out.push(o);
    } else {
      gap++;
    }
  });
  if (gap && out.length) out.push({ op: '…', text: `${gap} unchanged line${gap === 1 ? '' : 's'}` });
  return out;
}

// ---- graph helpers -----------------------------------------------------------------------------

/**
 * The part of the graph the namespace/service filter shows: matching services with their
 * children, plus providers, externals and loose nodes connected to them. Empty filter = all.
 */
export function visibleGraph(graph, filters = {}) {
  const nodes = (graph && graph.nodes) || [];
  const edges = (graph && graph.edges) || [];
  const ns = filters.ns || '';
  const svc = filters.svc || '';
  if (!ns && !svc) return { nodes, edges };
  const matches = (n) => {
    const s = serviceOf(n);
    return !!s && (!ns || s.ns === ns) && (!svc || s.svc === svc);
  };
  const keep = new Set(nodes.filter(matches).map((n) => n.id));
  for (const e of edges) {
    if (keep.has(e.source) && !serviceOf({ id: e.target })) keep.add(e.target);
    if (keep.has(e.target) && !serviceOf({ id: e.source })) keep.add(e.source);
  }
  return {
    nodes: nodes.filter((n) => keep.has(n.id)),
    edges: edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
  };
}

/** A tool name for a new agent link: the agent name with `-` → `_`, made unique. */
export function suggestToolName(agentName, existing = []) {
  let base = String(agentName || 'agent')
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .replace(/-/g, '_')
    .slice(0, 60);
  if (!base) base = 'agent';
  const taken = new Set(existing);
  if (!taken.has(base)) return base;
  for (let i = 2; i < 1000; i++) {
    if (!taken.has(`${base}_${i}`)) return `${base}_${i}`;
  }
  return `${base}_x`;
}

/**
 * What a link from one agent node to another needs: `refused` (cross-namespace or self),
 * `admin` (cross-service: adds an authz.callers rule) or `editor` (same service).
 */
export function linkRequirement(fromId, toId) {
  const a = parseNodeId(fromId);
  const b = parseNodeId(toId);
  if (!a || !b || a.kind !== 'agent' || b.kind !== 'agent') return { level: 'refused', reason: 'Both ends must be agents.' };
  if (fromId === toId) return { level: 'refused', reason: 'An agent cannot call itself.' };
  if (a.ns !== b.ns) return { level: 'refused', reason: 'Links across namespaces are refused.' };
  if (a.svc !== b.svc) {
    return {
      level: 'admin',
      reason: `Adds an authz.callers rule to ${b.svc} for spiffe://attache/ns/${a.ns}/svc/${a.svc}.`,
    };
  }
  return { level: 'editor', reason: 'Same service.' };
}

export function throttle(fn, ms) {
  let timer = null;
  let last = 0;
  let pending = false;
  const run = () => {
    timer = null;
    last = Date.now();
    pending = false;
    fn();
  };
  const t = () => {
    if (timer) {
      pending = true;
      return;
    }
    const wait = Math.max(0, last + ms - Date.now());
    timer = setTimeout(run, wait);
  };
  t.flush = () => {
    if (timer) clearTimeout(timer);
    if (timer || pending) run();
  };
  return t;
}
