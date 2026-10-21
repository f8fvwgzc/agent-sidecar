// Fixture mode (`?fixtures=1`): a small in-browser stand-in for the control plane. It answers
// the REST calls of docs/api/openapi.yaml from the golden files in ui/fixtures/, keeps writes in
// memory (they vanish on reload), and replays ui/fixtures/events.sse on a timer as the live
// stream. Only api.js loads it, and only in fixture mode.
//
// URL parameters (fixture mode only):
//   role=viewer|editor|admin   act as that role instead of whoami.json's
//   payloads=0                 a token without payload visibility
//   signin=1                   start signed out (any well-formed att_ token signs in)
//   conflict=1                 the first agent or charter save meets a concurrent edit (409)
//   scenario=full              add services in every status, placeholders and a mock model

import { parseSse } from './sse.js';
import {
  DNS_LABEL,
  TOOL_NAME,
  TOKEN_RE,
  ROLES,
  roleAtLeast,
  isModelName,
  parseNodeId,
  clone,
  utf8Length,
  svcNodeId,
  appNodeId,
  agentNodeId,
} from './util.js';

const hasOwn = (o, k) => o != null && Object.prototype.hasOwnProperty.call(o, k);

export function uuid() {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  const b = new Uint8Array(16);
  if (c && typeof c.getRandomValues === 'function') c.getRandomValues(b);
  else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const x = [...b].map((v) => v.toString(16).padStart(2, '0')).join('');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

/** A stand-in content hash (64 hex chars); fixture mode has no need for real SHA-256. */
export function fakeSha(text) {
  let out = '';
  for (let seed = 0; seed < 8; seed++) {
    let h = 0x811c9dc5 ^ (seed * 0x9e3779b1);
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
    out += (h >>> 0).toString(16).padStart(8, '0');
  }
  return out;
}

const zeroAgentStats = () => ({
  invocations: 0,
  denied: 0,
  errors: 0,
  p50_ms: 0,
  p95_ms: 0,
  tokens_in: 0,
  tokens_out: 0,
  cost_usd: 0,
});
const zeroEdgeStats = () => ({ calls: 0, denied: 0, errors: 0, avg_ms: 0, last_ts: null });
const zeroAppStats = () => ({ calls: 0, denied: 0, errors: 0, avg_ms: 0 });

function originOf(url) {
  try {
    const u = new URL(String(url).replace(/\{[^}]*\}/g, 'x'));
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

/** The graph node a declared tool points at (design §10.1). */
export function toolTarget(ns, svc, t) {
  if (!t) return null;
  if (t.type === 'agent' && t.agent) return agentNodeId(ns, t.service || svc, t.agent);
  if (t.type === 'service' && t.service) return appNodeId(ns, t.service);
  if (t.type === 'http' && t.url) {
    const o = originOf(t.url);
    return o ? `external:${o}` : null;
  }
  return null;
}

const targetPort = (type) => (type === 'agent' ? 'invoke' : type === 'service' ? 'service' : 'http');

/** GET .../agents/{agent}: the agent with the policy around it, derived from a charter. */
export function synthAgentView(charter, name) {
  const agent = (charter.agents || []).find((a) => a.name === name);
  if (!agent) return null;
  const g = charter.guardrails || {};
  const at = hasOwn(g.allowed_tools, name) ? g.allowed_tools[name] : null;
  const as = hasOwn(g.allowed_services, name) ? g.allowed_services[name] : null;
  const callers = ((charter.authz || {}).callers || [])
    .filter((r) => (r.agents || []).includes('*') || (r.agents || []).includes(name))
    .map((r) => ({ identity: r.identity, caller_agents: r.caller_agents ?? null }));
  return { agent: clone(agent), allowed_tools: clone(at), allowed_services: clone(as), callers };
}

const RANGES = {
  'budgets.max_tokens_per_call': [1, 128000],
  'budgets.max_calls_per_minute': [1, Infinity],
  'budgets.max_steps': [1, Infinity],
  'harness.max_retries': [0, 10],
  'harness.request_timeout_seconds': [1, 600],
  'harness.tool_result_max_chars': [100, 200000],
  'learning.max_notes': [1, 200],
  'learning.max_note_chars': [50, 4000],
  'learning.note_ttl_days': [1, 365],
  'learning.max_proposals_per_hour': [1, 100],
};

/** A subset of the charter validator (design §4), enough to exercise the console's error paths. */
export function validateAgent(agent, charter) {
  const d = [];
  const at = `agents[${agent && agent.name}]`;
  if (!agent || typeof agent !== 'object') return ['agent: required'];
  if (!DNS_LABEL.test(agent.name || '')) d.push(`${at}.name: must be a DNS-1123 label`);
  if (!isModelName(agent.model)) d.push(`${at}.model: must be non-empty, at most 128 bytes, without whitespace`);
  if (agent.type && !['agent', 'orchestrator'].includes(agent.type)) d.push(`${at}.type: agent or orchestrator`);
  if (agent.system && utf8Length(agent.system) > 32768) d.push(`${at}.system: at most 32768 bytes`);
  const names = new Set();
  for (const [i, t] of (agent.tools || []).entries()) {
    const p = `${at}.tools[${i}]`;
    if (!TOOL_NAME.test(t.name || '')) d.push(`${p}.name: must match ^[a-zA-Z0-9_-]{1,64}$`);
    if (t.name === 'load_skill') d.push(`${p}.name: load_skill is reserved`);
    if (names.has(t.name)) d.push(`${p}.name: duplicate tool ${t.name}`);
    names.add(t.name);
    if (!t.description) d.push(`${p}.description: required`);
    if (t.type === 'agent' && !DNS_LABEL.test(t.agent || '')) d.push(`${p}.agent: required`);
    else if (t.type === 'service' && (!DNS_LABEL.test(t.service || '') || !t.method || !t.path)) {
      d.push(`${p}: a service tool needs service, method and path`);
    } else if (t.type === 'http' && !originOf(t.url)) d.push(`${p}.url: an http(s) URL`);
    else if (!['agent', 'service', 'http'].includes(t.type)) d.push(`${p}.type: service, agent or http`);
  }
  const skillNames = new Set((charter.skills || []).map((s) => s.name));
  for (const s of agent.skills || []) if (!skillNames.has(s)) d.push(`${at}.skills: unknown skill ${s}`);
  for (const [path, [lo, hi]] of Object.entries(RANGES)) {
    const [sec, key] = path.split('.');
    const v = agent[sec] && agent[sec][key];
    if (v === undefined) continue;
    if (!Number.isInteger(v) || v < lo || v > hi) d.push(`${at}.${path}: ${lo}..=${hi === Infinity ? '∞' : hi}`);
  }
  const cost = agent.budgets && agent.budgets.max_cost_usd_per_day;
  if (cost !== undefined && !(typeof cost === 'number' && cost > 0)) d.push(`${at}.budgets.max_cost_usd_per_day: > 0`);
  const fb = agent.harness && agent.harness.fallback_model;
  if (fb !== undefined && (!isModelName(fb) || fb === agent.model)) {
    d.push(`${at}.harness.fallback_model: a valid model different from model`);
  }
  const l = agent.learning || {};
  if (l.mode && !['review', 'auto'].includes(l.mode)) d.push(`${at}.learning.mode: review or auto`);
  if (l.mode === 'auto' && !l.enabled) d.push(`${at}.learning.mode: auto requires enabled: true`);
  return d;
}

function err(status, error, details = [], current) {
  const data = { error, details };
  if (current !== undefined) data.current_version = current;
  return { status, data };
}
const ok = (data, etag, status = 200) => ({ status, data, etag: etag == null ? null : `"${etag}"` });

function toYaml(charter) {
  return `# Written in fixture mode (JSON is valid YAML).\n${JSON.stringify(charter, null, 2)}\n`;
}

/** Fixture mode cannot parse YAML; it understands JSON (a subset of YAML) and nothing else. */
function parseJsonYaml(text) {
  const body = String(text)
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');
  try {
    const v = JSON.parse(body);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

const ADMIN_SECTIONS = ['authz', 'audit', 'telemetry', 'mesh'];

function weakenedJson(a, b) {
  const w = [];
  if ((a.authz || {}).default !== 'allow' && (b.authz || {}).default === 'allow') w.push('authz.default');
  const ga = a.guardrails || {};
  const gb = b.guardrails || {};
  if (ga.pii_redact === true && gb.pii_redact === false) w.push('guardrails.pii_redact');
  for (const k of ['input_deny', 'output_deny']) {
    const keep = new Set((gb[k] || []).map((r) => r.name));
    for (const r of ga[k] || []) if (!keep.has(r.name)) w.push(`guardrails.${k}.${r.name}`);
  }
  const ra = new Set(((b.audit || {}).redact || []).map(String));
  for (const p of (a.audit || {}).redact || []) if (!ra.has(String(p))) w.push(`audit.redact.${p}`);
  if ((a.telemetry || {}).export_payloads !== true && (b.telemetry || {}).export_payloads === true) {
    w.push('telemetry.export_payloads');
  }
  return w;
}

function topSection(text, key) {
  const lines = String(text).split('\n');
  const start = lines.findIndex((l) => l.startsWith(`${key}:`));
  if (start < 0) return '';
  let end = start + 1;
  while (end < lines.length && (lines[end] === '' || /^[\s#-]/.test(lines[end]))) end++;
  return lines.slice(start, end).join('\n');
}

function weakenedText(a, b) {
  const w = [];
  const allow = /default:\s*["']?allow/;
  if (!allow.test(a) && allow.test(b)) w.push('authz.default');
  if (/pii_redact:\s*true/.test(a) && /pii_redact:\s*false/.test(b)) w.push('guardrails.pii_redact');
  for (const k of ['input_deny', 'output_deny']) if (a.includes(`${k}:`) && !b.includes(`${k}:`)) w.push(`guardrails.${k}`);
  return w;
}

/** needs_role and weakened of a candidate charter (a heuristic stand-in for the real role-on-diff). */
export function judgeCharter(before, beforeYaml, parsed, yaml) {
  let weakened;
  let admin;
  if (parsed) {
    weakened = weakenedJson(before, parsed);
    admin = ADMIN_SECTIONS.some((k) => JSON.stringify(before[k]) !== JSON.stringify(parsed[k]));
    const ga = before.guardrails || {};
    const gb = parsed.guardrails || {};
    for (const k of ['input_deny', 'output_deny', 'pii_redact', 'max_input_bytes']) {
      if (JSON.stringify(ga[k]) !== JSON.stringify(gb[k])) admin = true;
    }
  } else {
    weakened = weakenedText(beforeYaml, yaml);
    admin = ADMIN_SECTIONS.some((k) => topSection(beforeYaml, k) !== topSection(yaml, k));
  }
  return { needs_role: admin || weakened.length ? 'admin' : 'editor', weakened };
}

export async function createFixtureServer({
  load,
  params = new URLSearchParams(),
  timers = globalThis,
  monotonic = () => globalThis.performance.now(),
  replay = true,
} = {}) {
  const read = async (name, required = true) => {
    const text = await load(name);
    if (text == null) {
      if (required) throw new Error(`fixture ${name} is missing`);
      return null;
    }
    return JSON.parse(text);
  };
  const [whoami, graph, services, proposals, recent] = await Promise.all([
    read('whoami.json'),
    read('graph.json'),
    read('services.json'),
    read('proposals.json'),
    read('events-recent.json'),
  ]);
  const [memory, history, sse] = await Promise.all([
    read('memory.json', false),
    read('history.json', false),
    load('events.sse'),
  ]);
  const names = new Set(services.map((s) => s.service));
  for (const n of graph.nodes) if (n.type === 'service' && !n.placeholder && n.service) names.add(n.service);
  const charters = [];
  for (const name of names) {
    if (!DNS_LABEL.test(name)) continue;
    const c = await read(`charter-${name}.json`, false);
    if (c) charters.push(c);
  }
  return new FixtureServer(
    { whoami, graph, services, proposals, recent, memory, history, sse: sse || '', charters },
    { params, timers, monotonic, replay },
  );
}

export class FixtureServer {
  constructor(d, { params, timers, monotonic, replay }) {
    this.timers = timers;
    this.monotonic = monotonic;
    this.t0 = monotonic();
    this.snapshot = Date.parse(d.graph.generated_at) || Date.parse('2026-10-21T10:00:00.000Z');
    this.me = { ...d.whoami };
    const role = params.get('role');
    if (ROLES.includes(role)) this.me.role = role;
    if (params.get('payloads') === '0') this.me.payloads = false;
    this.signedIn = params.get('signin') !== '1';
    this.failedLogins = 0;
    this.conflictOnce = params.get('conflict') === '1';
    this.graph = clone(d.graph);
    this.services = clone(d.services);
    this.charters = new Map();
    this.history = new Map();
    this.memory = new Map();
    this.pendingCharters = new Map();
    this.failing = new Map();
    for (const c of d.charters) {
      const s = (c.charter && c.charter.service) || {};
      if (s.name && s.namespace) this.charters.set(`${s.namespace}/${s.name}`, clone(c));
    }
    for (const [key, c] of this.charters) {
      const h = d.history && d.history.length && d.history[0].version === c.version && !this.historyTaken ? d.history : null;
      if (h) this.historyTaken = true;
      this.history.set(key, h ? clone(h) : [{ version: c.version, ts: this.iso(this.snapshot - 86400000), actor: 'system', sha256: fakeSha(c.yaml) }]);
    }
    if (d.memory) {
      const agents = Object.keys(d.memory.agents || {});
      for (const [key, c] of this.charters) {
        const own = new Set((c.charter.agents || []).map((a) => a.name));
        if (agents.length && agents.every((a) => own.has(a))) {
          this.memory.set(key, clone(d.memory));
          break;
        }
      }
    }
    this.proposals = clone(d.proposals);
    this.events = clone(d.recent);
    const parsed = parseSse(d.sse);
    this.transcript = parsed.events;
    this.seq = this.transcript.reduce((m, e) => Math.max(m, Number(e.id) || 0), 0);
    this.subs = new Set();
    this.replayEnabled = replay;
    this.replayTimers = [];
    if (params.get('scenario') === 'full') this.addScenario();
  }

  now() {
    return this.snapshot + (this.monotonic() - this.t0);
  }

  iso(t = this.now()) {
    return new Date(t).toISOString();
  }

  // ---- REST ------------------------------------------------------------------------------------

  async handle(method, url, opts = {}) {
    try {
      return clone(this.route(method, url, opts));
    } catch (e) {
      return err(500, 'internal', [String((e && e.message) || e)]);
    }
  }

  route(method, url, { headers = {}, body } = {}) {
    const H = {};
    for (const [k, v] of Object.entries(headers)) H[k.toLowerCase()] = String(v);
    const u = new URL(url, 'http://fixtures.invalid');
    const q = u.searchParams;
    let seg;
    try {
      seg = u.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    } catch {
      return err(400, 'invalid', ['bad path encoding']);
    }
    const path = `/${seg.join('/')}`;
    const mutating = method !== 'GET';
    if (mutating) {
      if (H['x-attache-csrf'] !== '1') return err(403, 'forbidden', ['X-Attache-CSRF: 1 is required']);
      if (!(H['content-type'] || '').startsWith('application/json')) {
        return err(400, 'invalid', ['Content-Type must be application/json']);
      }
    }
    if (method === 'POST' && path === '/login') return this.login(body);
    if (!this.signedIn) return err(401, 'unauthenticated', []);
    if (method === 'POST' && path === '/logout') {
      this.signedIn = false;
      return { status: 204, data: null };
    }
    if (mutating && !roleAtLeast(this.me.role, 'editor')) {
      return err(403, 'forbidden', [`the ${this.me.role} role is read-only`]);
    }
    if (method === 'GET' && path === '/whoami') return ok(this.me);
    if (method === 'GET' && path === '/graph') return ok(this.graph);
    if (method === 'GET' && path === '/services') return ok(this.servicesView());
    if (method === 'GET' && path === '/proposals') return ok(this.listProposals(q));
    if (method === 'GET' && path === '/events/recent') return this.recent(q);
    if (method === 'POST' && path === '/links') return this.link(body);
    if (seg[0] === 'proposals' && seg.length === 3 && method === 'POST' && ['approve', 'reject'].includes(seg[2])) {
      return this.decide(seg[1], seg[2], H);
    }
    if (seg[0] === 'services' && seg.length >= 3) {
      const [, ns, svc, ...rest] = seg;
      if (!this.inScope(ns) || !DNS_LABEL.test(ns) || !DNS_LABEL.test(svc)) return err(404, 'not_found', [`no service ${ns}/${svc}`]);
      return this.serviceRoute(method, ns, svc, rest, H, body);
    }
    return err(404, 'not_found', [`${method} ${path} is not available in fixture mode`]);
  }

  inScope(ns) {
    const s = this.me.namespaces || [];
    return s.includes('*') || s.includes(ns);
  }

  login(body) {
    if (this.failedLogins >= 5) return err(429, 'rate_limited', ['too many failed logins; retry in 60 s']);
    const token = body && body.token;
    if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
      this.failedLogins++;
      return err(400, 'invalid', ['token: att_ followed by 43 base64url characters']);
    }
    this.signedIn = true;
    this.failedLogins = 0;
    return ok(this.me);
  }

  summary(ns, svc) {
    return this.services.find((s) => s.namespace === ns && s.service === svc) || null;
  }

  servicesView() {
    const now = this.now();
    return this.services.map((s) => ({
      ...s,
      instances: s.instances.map((i) => {
        if (!i.last_heartbeat) return i;
        const jitter = parseInt(i.instance_id.slice(0, 4), 16) % 10000;
        return { ...i, last_heartbeat: this.iso(now - ((now - this.snapshot + jitter) % 10000)) };
      }),
    }));
  }

  statusOf(s) {
    if (!s.charter_version) return s.instances.length ? 'no_charter' : 'disconnected';
    if (!s.instances.length) return 'disconnected';
    const bad = s.instances.some((i) => i.ack_error || i.acked_version !== s.charter_version || !i.runtime_ready);
    return bad ? 'degraded' : 'connected';
  }

  precondition(H, current) {
    const im = H['if-match'];
    if (im == null) return err(400, 'invalid', ['If-Match is required']);
    const m = /^"(\d+)"$/.exec(im.trim());
    if (!m) return err(400, 'invalid', ['If-Match must be a quoted version such as "3"']);
    if (m[1] !== current) {
      return err(409, 'version_conflict', [`If-Match "${m[1]}" does not match the current version`], current);
    }
    return null;
  }

  serviceRoute(method, ns, svc, rest, H, body) {
    const key = `${ns}/${svc}`;
    const entry = this.charters.get(key);
    const r = rest.join('/');
    if (r === 'charter' && method === 'GET') {
      if (!entry) return err(404, 'not_found', [`no charter for ${key}`]);
      return ok({ epoch: entry.epoch, version: entry.version, yaml: entry.yaml, charter: entry.charter }, entry.version);
    }
    if (r === 'charter' && method === 'PUT') return this.putCharter(ns, svc, H, body);
    if (r === 'charter/validate' && method === 'POST') {
      const v = this.checkYaml(entry, body);
      return v.error ? v.error : ok({ charter: v.charter, needs_role: v.needs_role, weakened: v.weakened });
    }
    if (r === 'charter/history' && method === 'GET') {
      if (!entry) return err(404, 'not_found', [`no charter for ${key}`]);
      return ok(this.history.get(key) || []);
    }
    if (rest[0] === 'charter' && rest[1] === 'history' && rest.length === 3 && method === 'GET') {
      if (entry && rest[2] === entry.version) return ok({ yaml: entry.yaml });
      return err(404, 'not_found', [`version ${rest[2]} is not kept in fixture mode`]);
    }
    if (r === 'adopt' && method === 'POST') return this.adopt(ns, svc, body);
    if (r === 'memory' && method === 'GET') {
      if (!entry) return err(404, 'not_found', [`no charter for ${key}`]);
      const m = this.memoryOf(ns, svc);
      return ok(m, m.version);
    }
    if (r === 'memory' && method === 'PUT') return this.putMemory(ns, svc, H, body);
    if (rest[0] === 'agents') {
      if (!entry) return err(404, 'not_found', [`no charter for ${key}`]);
      if (rest.length === 1 && method === 'POST') return this.writeAgent(ns, svc, null, H, body);
      if (rest.length === 2) {
        const name = rest[1];
        if (method === 'GET') {
          const view = synthAgentView(entry.charter, name);
          return view ? ok(view, entry.version) : err(404, 'not_found', [`no agent ${name} in ${key}`]);
        }
        if (method === 'PUT') return this.writeAgent(ns, svc, name, H, body);
        if (method === 'DELETE') return this.deleteAgent(ns, svc, name, H);
      }
    }
    return err(404, 'not_found', [`${method} /services/${key}/${r} is not available in fixture mode`]);
  }

  // ---- charters --------------------------------------------------------------------------------

  checkYaml(entry, body) {
    const yaml = body && body.yaml;
    if (typeof yaml !== 'string' || !yaml.trim()) return { error: err(400, 'invalid', ['yaml: the document is empty']) };
    if (yaml.length > 262144) return { error: err(400, 'invalid', ['yaml: larger than 256 KiB']) };
    const tab = yaml.split('\n').findIndex((l) => /^\s*\t/.test(l));
    if (tab >= 0) return { error: err(400, 'invalid', [`line ${tab + 1}: tabs are not allowed in YAML indentation`]) };
    if (!/agents/.test(yaml)) return { error: err(400, 'invalid', ['agents: missing field']) };
    const parsed = parseJsonYaml(yaml);
    if (parsed) {
      const details = (parsed.agents || []).flatMap((a) => validateAgent(a, parsed));
      if (details.length) return { error: err(400, 'invalid', details) };
    }
    const before = entry ? entry.charter : {};
    const j = judgeCharter(before, entry ? entry.yaml : '', parsed, yaml);
    return { yaml, parsed, charter: parsed || before, ...j };
  }

  putCharter(ns, svc, H, body) {
    const key = `${ns}/${svc}`;
    let entry = this.charters.get(key);
    if (!entry) {
      if (H['if-none-match'] !== '*') return err(400, 'invalid', ['If-None-Match: * is required for the first charter']);
      if (!roleAtLeast(this.me.role, 'admin')) return err(403, 'forbidden', ['creating a charter with PUT requires admin']);
    } else {
      if (this.conflictOnce && H['if-match']) {
        this.conflictOnce = false;
        this.commit(ns, svc, entry.charter, { actor: 'bob', yaml: `${entry.yaml.replace(/\n*$/, '\n')}# reviewed by bob\n` });
        entry = this.charters.get(key);
      }
      const pre = this.precondition(H, entry.version);
      if (pre) return pre;
    }
    const v = this.checkYaml(entry, body);
    if (v.error) return v.error;
    if (v.needs_role === 'admin' && !roleAtLeast(this.me.role, 'admin')) {
      const details = v.weakened.length ? v.weakened.map((w) => `${w} requires admin`) : ['this change requires admin'];
      return err(403, 'forbidden', details);
    }
    const version = this.commit(ns, svc, v.parsed || (entry ? entry.charter : {}), { yaml: v.yaml });
    return ok({ version }, version);
  }

  commit(ns, svc, charter, { actor = this.me.name, source = 'api', yaml } = {}) {
    const key = `${ns}/${svc}`;
    const prev = this.charters.get(key);
    const version = String(Number((prev && prev.version) || 0) + 1);
    const text = yaml || toYaml(charter);
    this.charters.set(key, { epoch: (prev && prev.epoch) || uuid(), version, yaml: text, charter: clone(charter) });
    const hist = this.history.get(key) || [];
    hist.unshift({ version, ts: this.iso(), actor, sha256: fakeSha(text) });
    this.history.set(key, hist);
    let s = this.summary(ns, svc);
    if (!s) {
      s = { namespace: ns, service: svc, status: 'disconnected', epoch: null, charter_version: null, memory_version: null, pending_adoption: null, instances: [] };
      this.services.push(s);
    }
    s.epoch = this.charters.get(key).epoch;
    s.charter_version = version;
    s.memory_version = s.memory_version || '0';
    s.pending_adoption = null;
    s.status = this.statusOf(s);
    this.syncGraph(ns, svc);
    // Design §3: turning learning off drops the agent's notes in the same change.
    const learns = (c) => new Set(((c && c.agents) || []).filter((a) => a.learning && a.learning.enabled).map((a) => a.name));
    const now = learns(charter);
    const mem = this.memoryOf(ns, svc);
    const dropped = [...learns(prev && prev.charter)].filter((a) => !now.has(a) && hasOwn(mem.agents, a));
    if (dropped.length) {
      for (const a of dropped) delete mem.agents[a];
      this.bumpMemory(ns, svc);
    }
    this.emit('config', { namespace: ns, service: svc, version, actor, source });
    this.emit('graph', { version: this.graph.version });
    this.scheduleAcks(ns, svc, 'charter', version);
    return version;
  }

  adopt(ns, svc, body) {
    const s = this.summary(ns, svc);
    const key = `${ns}/${svc}`;
    if (this.charters.has(key)) return err(409, 'version_conflict', [`${key} already has a charter`], this.charters.get(key).version);
    if (!s || !s.pending_adoption || !body || body.sha256 !== s.pending_adoption.sha256) {
      return err(404, 'not_found', ['no pending adoption with that sha256']);
    }
    const charter = this.pendingCharters.get(key);
    if (!charter) return err(404, 'not_found', ['the pending charter is not kept in fixture mode']);
    const version = this.commit(ns, svc, charter, { source: 'adopt' });
    return ok({ version }, version);
  }

  // ---- agents ----------------------------------------------------------------------------------

  writeAgent(ns, svc, name, H, body) {
    const key = `${ns}/${svc}`;
    let entry = this.charters.get(key);
    if (name !== null && this.conflictOnce && H['if-match']) {
      this.conflictOnce = false;
      const other = clone(entry.charter);
      const a = (other.agents || []).find((x) => x.name === name);
      if (a) {
        a.system = `${(a.system || '').replace(/\n*$/, '\n')}Always state the order id you looked at.\n`;
        a.budgets = { ...(a.budgets || {}), max_steps: ((a.budgets && a.budgets.max_steps) || 4) + 2 };
      }
      this.commit(ns, svc, other, { actor: 'bob' });
      entry = this.charters.get(key);
    }
    const pre = this.precondition(H, entry.version);
    if (pre) return pre;
    const view = body || {};
    const agent = view.agent;
    if (!agent || typeof agent !== 'object') return err(400, 'invalid', ['agent: required']);
    const charter = clone(entry.charter);
    charter.agents = charter.agents || [];
    const idx = charter.agents.findIndex((a) => a.name === (name === null ? agent.name : name));
    if (name === null && idx >= 0) return err(400, 'invalid', [`agents: ${agent.name} already exists`]);
    if (name !== null && idx < 0) return err(404, 'not_found', [`no agent ${name} in ${key}`]);
    if (name !== null && agent.name !== name) return err(400, 'invalid', ['agent.name must equal the path']);
    const details = validateAgent(agent, charter);
    if (details.length) return err(400, 'invalid', details);
    const before = idx >= 0 ? charter.agents[idx] : null;
    const needAdmin = [];
    if ((agent.learning || {}).mode === 'auto' && ((before && before.learning) || {}).mode !== 'auto') {
      needAdmin.push('learning.mode: auto requires admin');
    }
    const oldOrigins = new Set(((before && before.tools) || []).filter((t) => t.type === 'http').map((t) => originOf(t.url)));
    for (const t of agent.tools || []) {
      if (t.type === 'http' && !oldOrigins.has(originOf(t.url))) needAdmin.push(`a new http tool origin (${originOf(t.url)}) requires admin`);
    }
    if (needAdmin.length && !roleAtLeast(this.me.role, 'admin')) return err(403, 'forbidden', needAdmin);
    if (idx >= 0) charter.agents[idx] = clone(agent);
    else charter.agents.push(clone(agent));
    const g = (charter.guardrails = charter.guardrails || {});
    const declared = new Set((agent.tools || []).map((t) => t.name));
    for (const [field, value] of [
      ['allowed_tools', Array.isArray(view.allowed_tools) ? view.allowed_tools.filter((t) => declared.has(t)) : null],
      ['allowed_services', Array.isArray(view.allowed_services) ? view.allowed_services : null],
    ]) {
      if (value) g[field] = { ...(g[field] || {}), [agent.name]: value };
      else if (g[field]) delete g[field][agent.name];
      if (g[field] && !Object.keys(g[field]).length) delete g[field];
    }
    if (name === null && !Array.isArray(view.callers)) {
      const authz = (charter.authz = charter.authz || { default: 'deny', callers: [] });
      authz.callers = authz.callers || [];
      const local = authz.callers.find((r) => r.identity === 'local');
      if (!local) authz.callers.push({ identity: 'local', agents: [agent.name] });
      else if (!(local.agents || []).includes('*') && !(local.agents || []).includes(agent.name)) {
        local.agents = [...(local.agents || []), agent.name];
      }
    }
    const version = this.commit(ns, svc, charter);
    return ok({ version }, version, name === null ? 201 : 200);
  }

  deleteAgent(ns, svc, name, H) {
    const key = `${ns}/${svc}`;
    const entry = this.charters.get(key);
    const pre = this.precondition(H, entry.version);
    if (pre) return pre;
    const charter = clone(entry.charter);
    if (!(charter.agents || []).some((a) => a.name === name)) return err(404, 'not_found', [`no agent ${name}`]);
    const user = (charter.agents || []).find((a) => (a.tools || []).some((t) => t.type === 'agent' && t.agent === name && !t.service));
    if (user) return err(409, 'in_use', [`${user.name} still calls ${name}`]);
    charter.agents = charter.agents.filter((a) => a.name !== name);
    const g = charter.guardrails || {};
    for (const f of ['allowed_tools', 'allowed_services']) if (g[f]) delete g[f][name];
    if (charter.authz && charter.authz.callers) {
      charter.authz.callers = charter.authz.callers
        .map((r) => ({ ...r, agents: (r.agents || []).filter((a) => a !== name) }))
        .filter((r) => r.agents.length);
    }
    const version = this.commit(ns, svc, charter);
    return ok({ version }, version);
  }

  link(body) {
    const from = parseNodeId(body && body.from);
    const to = parseNodeId(body && body.to);
    if (!from || from.kind !== 'agent' || !to || to.kind !== 'agent') return err(400, 'invalid', ['from and to must be agent node ids']);
    if (from.ns !== to.ns) return err(400, 'invalid', ['links across namespaces are refused']);
    if (body.from === body.to) return err(400, 'invalid', ['an agent cannot call itself']);
    const tool = body.tool || {};
    if (!TOOL_NAME.test(tool.name || '') || tool.name === 'load_skill') return err(400, 'invalid', ['tool.name: must match ^[a-zA-Z0-9_-]{1,64}$']);
    if (!tool.description) return err(400, 'invalid', ['tool.description: required']);
    const srcKey = `${from.ns}/${from.svc}`;
    const tgtKey = `${to.ns}/${to.svc}`;
    const src = this.charters.get(srcKey);
    const tgt = this.charters.get(tgtKey);
    if (!src || !this.inScope(from.ns)) return err(404, 'not_found', [`no charter for ${srcKey}`]);
    if (!tgt) return err(404, 'not_found', [`no charter for ${tgtKey}`]);
    const sa = (src.charter.agents || []).find((a) => a.name === from.agent);
    if (!sa) return err(404, 'not_found', [`no agent ${from.agent} in ${srcKey}`]);
    if (!(tgt.charter.agents || []).some((a) => a.name === to.agent)) return err(404, 'not_found', [`no agent ${to.agent} in ${tgtKey}`]);
    if ((sa.tools || []).some((t) => t.name === tool.name)) return err(400, 'invalid', [`${from.agent} already has a tool named ${tool.name}`]);
    const cross = srcKey !== tgtKey;
    const identity = `spiffe://attache/ns/${from.ns}/svc/${from.svc}`;
    if (cross && !roleAtLeast(this.me.role, 'admin')) {
      return err(403, 'forbidden', [`authz.callers: a rule for ${identity} in ${tgtKey} requires admin`]);
    }
    const ifm = body.if_match || {};
    const applied = [];
    const failed = {};
    const conflict = (key, cur) => ({
      error: 'version_conflict',
      details: [`if_match ${JSON.stringify(ifm[key] ?? null)} does not match the current version`],
      current_version: cur,
    });
    if (cross) {
      if (ifm[tgtKey] !== tgt.version) {
        failed[tgtKey] = conflict(tgtKey, tgt.version);
        return ok({ applied, failed });
      }
      const c = clone(tgt.charter);
      const authz = (c.authz = c.authz || { default: 'deny', callers: [] });
      authz.callers = authz.callers || [];
      const rule = authz.callers.find((r) => r.identity === identity);
      if (rule) {
        if (!(rule.agents || []).includes('*') && !(rule.agents || []).includes(to.agent)) rule.agents = [...(rule.agents || []), to.agent];
        if (Array.isArray(rule.caller_agents) && !rule.caller_agents.includes(from.agent)) rule.caller_agents.push(from.agent);
      } else {
        authz.callers.push({ identity, agents: [to.agent], caller_agents: [from.agent] });
      }
      applied.push({ service: tgtKey, version: this.commit(to.ns, to.svc, c) });
    }
    const cur = this.charters.get(srcKey);
    if (ifm[srcKey] !== cur.version) {
      failed[srcKey] = conflict(srcKey, cur.version);
      return ok({ applied, failed });
    }
    const c = clone(cur.charter);
    const a = c.agents.find((x) => x.name === from.agent);
    a.tools = [...(a.tools || []), { name: tool.name, description: tool.description, type: 'agent', agent: to.agent, ...(cross ? { service: to.svc } : {}) }];
    const g = c.guardrails || {};
    if (g.allowed_tools && Array.isArray(g.allowed_tools[from.agent])) g.allowed_tools[from.agent].push(tool.name);
    if (cross && g.allowed_services && Array.isArray(g.allowed_services[from.agent]) && !g.allowed_services[from.agent].includes(to.svc)) {
      g.allowed_services[from.agent].push(to.svc);
    }
    applied.push({ service: srcKey, version: this.commit(from.ns, from.svc, c) });
    return ok({ applied, failed });
  }

  // ---- memory and proposals --------------------------------------------------------------------

  /** Memory exists only for agents with learning enabled (design §3). */
  learningOn(charter, name) {
    const a = ((charter && charter.agents) || []).find((x) => x.name === name);
    return !!(a && a.learning && a.learning.enabled);
  }

  memoryOf(ns, svc) {
    const key = `${ns}/${svc}`;
    let m = this.memory.get(key);
    if (!m) {
      const s = this.summary(ns, svc);
      m = { version: (s && s.memory_version) || '0', agents: {} };
      this.memory.set(key, m);
    }
    return m;
  }

  bumpMemory(ns, svc) {
    const m = this.memoryOf(ns, svc);
    m.version = String(Number(m.version) + 1);
    const s = this.summary(ns, svc);
    if (s) s.memory_version = m.version;
    this.refreshLearning(ns, svc);
    this.scheduleAcks(ns, svc, 'memory', m.version);
    return m.version;
  }

  putMemory(ns, svc, H, body) {
    const entry = this.charters.get(`${ns}/${svc}`);
    if (!entry) return err(404, 'not_found', [`no charter for ${ns}/${svc}`]);
    const m = this.memoryOf(ns, svc);
    const pre = this.precondition(H, m.version);
    if (pre) return pre;
    const agents = body && body.agents;
    if (!agents || typeof agents !== 'object' || Array.isArray(agents)) return err(400, 'invalid', ['agents: an object']);
    const known = new Set((entry.charter.agents || []).map((a) => a.name));
    const next = {};
    for (const [name, notes] of Object.entries(agents)) {
      if (!known.has(name)) return err(400, 'invalid', [`agents.${name}: not in the stored charter`]);
      if (!Array.isArray(notes)) return err(400, 'invalid', [`agents.${name}: a list of notes`]);
      if (!this.learningOn(entry.charter, name) && notes.some((n) => !n.id)) return err(400, 'invalid', [`agents.${name}: learning is off; there is no memory for this agent`]);
      next[name] = notes.map((n) =>
        n.id
          ? n
          : { id: uuid(), text: String(n.text || ''), source: 'manual', request_id: null, trace_id: null, approved_by: this.me.name, ts: this.iso(), expires_at: null },
      );
      if (!next[name].length) delete next[name];
    }
    m.agents = next;
    const version = this.bumpMemory(ns, svc);
    this.emit('graph', { version: this.graph.version });
    return ok({ version }, version);
  }

  listProposals(q) {
    const status = q.get('status');
    const ns = q.get('namespace');
    const svc = q.get('service');
    return this.proposals.filter(
      (p) => this.inScope(p.namespace) && (!status || p.status === status) && (!ns || p.namespace === ns) && (!svc || p.service === svc),
    );
  }

  decide(id, action, H) {
    const p = this.proposals.find((x) => x.id === id);
    if (!p || !this.inScope(p.namespace)) return err(404, 'not_found', [`no proposal ${id}`]);
    const m = this.memoryOf(p.namespace, p.service);
    const pre = this.precondition(H, m.version);
    if (pre) return pre;
    if (p.status !== 'pending') return err(409, 'version_conflict', [`the proposal is already ${p.status}`], m.version);
    const entry = this.charters.get(`${p.namespace}/${p.service}`);
    if (action === 'approve' && !(entry && this.learningOn(entry.charter, p.agent))) {
      return err(400, 'invalid', [`agents.${p.agent}: learning is off; there is no memory for this agent`]);
    }
    if (action === 'approve') {
      const list = (m.agents[p.agent] = m.agents[p.agent] || []);
      list.push({ id: uuid(), text: p.note, source: 'review', request_id: p.request_id, trace_id: p.trace_id, approved_by: this.me.name, ts: this.iso(), expires_at: null });
      p.status = 'approved';
      this.bumpMemory(p.namespace, p.service);
    } else {
      p.status = 'rejected';
      this.refreshLearning(p.namespace, p.service);
    }
    this.emit('proposal', p);
    this.emit('graph', { version: this.graph.version });
    return ok({ proposal: p, memory_version: m.version }, m.version);
  }

  recent(q) {
    const limitRaw = q.get('limit');
    const limit = limitRaw == null ? 100 : Number(limitRaw);
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) return err(400, 'invalid', ['limit: 1..=1000']);
    const f = {};
    for (const k of ['namespace', 'service', 'agent', 'trace_id', 'request_id', 'kind']) f[k] = q.get(k);
    const out = this.events
      .filter(
        (r) =>
          this.inScope(r.namespace) &&
          (!f.namespace || r.namespace === f.namespace) &&
          (!f.service || r.service === f.service) &&
          (!f.agent || r.agent === f.agent || r.caller_agent === f.agent) &&
          (!f.trace_id || r.trace_id === f.trace_id) &&
          (!f.request_id || r.request_id === f.request_id) &&
          (!f.kind || r.kind === f.kind),
      )
      .slice(0, limit)
      .map((r) => this.redactPayloads(r));
    return ok(out);
  }

  redactPayloads(r) {
    return this.me.payloads ? r : { ...r, input: null, output: null };
  }

  // ---- the graph -------------------------------------------------------------------------------

  agentNode(ns, svc, charter, a, prev) {
    const g = charter.guardrails || {};
    const allowed = hasOwn(g.allowed_tools, a.name) ? g.allowed_tools[a.name] : null;
    const tools = (a.tools || [])
      .map((t) => ({ name: t.name, type: t.type, target: toolTarget(ns, svc, t), allowed: !Array.isArray(allowed) || allowed.includes(t.name) }))
      .filter((t) => t.target);
    const mem = this.memoryOf(ns, svc);
    const pending = this.proposals.filter((p) => p.namespace === ns && p.service === svc && p.agent === a.name && p.status === 'pending').length;
    return {
      id: agentNodeId(ns, svc, a.name),
      type: 'agent',
      parent: svcNodeId(ns, svc),
      label: a.name,
      agent_type: a.type || 'agent',
      model: a.model,
      skills: a.skills || [],
      status: (prev && !prev.placeholder && prev.status) || 'idle',
      ports: { in: ['invoke'], out: [...tools.map((t) => t.name), 'model'] },
      tools,
      learning: {
        enabled: !!(a.learning && a.learning.enabled),
        mode: (a.learning && a.learning.mode) || 'review',
        notes: (hasOwn(mem.agents, a.name) ? mem.agents[a.name] : []).length,
        pending,
      },
      stats: (prev && prev.stats) || zeroAgentStats(),
    };
  }

  syncGraph(ns, svc) {
    const key = `${ns}/${svc}`;
    const entry = this.charters.get(key);
    const g = this.graph;
    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    const sid = svcNodeId(ns, svc);
    const aid = appNodeId(ns, svc);
    const sum = this.summary(ns, svc);
    let s = byId.get(sid);
    if (!s || s.placeholder) s = { id: sid, type: 'service', label: svc, namespace: ns, service: svc, status: 'disconnected', instances: 0, charter_version: null };
    s.instances = sum ? sum.instances.length : 0;
    s.charter_version = entry ? entry.version : null;
    s.status = sum ? sum.status : entry ? 'disconnected' : 'no_charter';
    let app = byId.get(aid);
    if (!app || app.placeholder) app = { id: aid, type: 'app', parent: sid, label: `${svc} app`, port: null, ports: { in: [], out: ['invoke'] }, stats: zeroAppStats() };
    const port = entry && entry.charter.service && entry.charter.service.app_port;
    if (port) app.port = port;
    const charter = entry ? entry.charter : { agents: [] };
    const oldAgents = g.nodes.filter((n) => n.type === 'agent' && n.parent === sid && !n.placeholder).map((n) => n.id);
    const agents = (charter.agents || []).map((a) => this.agentNode(ns, svc, charter, a, byId.get(agentNodeId(ns, svc, a.name))));
    const newIds = new Set(agents.map((a) => a.id));
    const removed = new Set(oldAgents.filter((id) => !newIds.has(id)));
    const own = new Set([...oldAgents, ...newIds]);
    const local = ((charter.authz || {}).callers || []).find((r) => r.identity === 'local');
    const admits = (n) => !!local && ((local.agents || []).includes('*') || (local.agents || []).includes(n));
    const mk = (kind, source, sp, target, tp, suffix = '') => ({
      id: `edge:${kind}:${source}->${target}${suffix}`,
      kind,
      source,
      source_port: sp,
      target,
      target_port: tp,
      declared: true,
      stats: zeroEdgeStats(),
    });
    const declared = [];
    for (const n of agents) {
      if (admits(n.label)) declared.push(mk('invoke', aid, 'invoke', n.id, 'invoke'));
      for (const t of n.tools) declared.push(mk('tool', n.id, t.name, t.target, targetPort(t.type), `#${t.name}`));
      declared.push(mk('model', n.id, 'model', n.model === 'mock' ? 'model:mock' : 'model:anthropic', 'model'));
    }
    const old = new Map(g.edges.map((e) => [e.id, e]));
    const ids = new Set(declared.map((e) => e.id));
    const edges = g.edges.filter(
      (e) =>
        !ids.has(e.id) &&
        !(e.declared && (own.has(e.source) || (e.kind === 'invoke' && e.source === aid))) &&
        !(!e.declared && (removed.has(e.source) || removed.has(e.target))),
    );
    for (const e of declared) {
      const prev = old.get(e.id);
      if (prev) e.stats = prev.stats;
      edges.push(e);
    }
    const nodes = g.nodes.filter((n) => n.id !== sid && n.id !== aid && !own.has(n.id));
    nodes.push(s, app, ...agents);
    g.nodes = nodes;
    g.edges = edges;
    this.tidyGraph();
  }

  placeholderFor(id, nodes, ids) {
    const p = parseNodeId(id);
    if (!p) return;
    const add = (n) => {
      nodes.push(n);
      ids.add(n.id);
    };
    if (p.kind === 'model') {
      add({ id, type: 'model_provider', label: p.provider === 'mock' ? 'Mock model' : 'Anthropic', ports: { in: ['model'], out: [] } });
      return;
    }
    if (p.kind === 'external') {
      add({ id, type: 'external', label: p.origin.replace(/^https?:\/\//, ''), ports: { in: ['http'], out: [] } });
      return;
    }
    const sid = svcNodeId(p.ns, p.svc);
    if (p.kind !== 'svc' && !ids.has(sid)) {
      add({ id: sid, type: 'service', label: p.svc, placeholder: true, status: 'disconnected', ports: { in: [], out: [] } });
    }
    if (p.kind === 'svc') add({ id, type: 'service', label: p.svc, placeholder: true, status: 'disconnected', ports: { in: [], out: [] } });
    if (p.kind === 'app') add({ id, type: 'app', parent: sid, label: `${p.svc} app`, placeholder: true, status: 'disconnected', ports: { in: ['service'], out: [] } });
    if (p.kind === 'agent') add({ id, type: 'agent', parent: sid, label: p.agent, placeholder: true, status: 'disconnected', ports: { in: ['invoke'], out: [] } });
  }

  /** Every edge endpoint exists (placeholders for unknown peers); unused placeholders go. */
  tidyGraph() {
    const g = this.graph;
    const ids = new Set(g.nodes.map((n) => n.id));
    for (const e of g.edges) for (const id of [e.source, e.target]) if (!ids.has(id)) this.placeholderFor(id, g.nodes, ids);
    const used = new Set(g.edges.flatMap((e) => [e.source, e.target]));
    g.nodes = g.nodes.filter((n) => !(n.placeholder && n.type !== 'service' && !used.has(n.id)));
    g.nodes = g.nodes.filter((n) => !(n.placeholder && n.type === 'service' && !g.nodes.some((c) => c.parent === n.id)));
    for (const n of g.nodes) {
      if (n.type === 'app' && !n.placeholder) {
        n.ports = { ...n.ports, in: g.edges.some((e) => e.target === n.id && e.target_port === 'service') ? ['service'] : [] };
      }
    }
    g.version = String(Number(g.version) + 1);
    g.generated_at = this.iso();
  }

  refreshLearning(ns, svc) {
    const entry = this.charters.get(`${ns}/${svc}`);
    if (!entry) return;
    for (const n of this.graph.nodes) {
      if (n.type !== 'agent' || n.placeholder || n.parent !== svcNodeId(ns, svc)) continue;
      const a = (entry.charter.agents || []).find((x) => x.name === n.label);
      if (a) n.learning = this.agentNode(ns, svc, entry.charter, a, n).learning;
    }
    this.graph.version = String(Number(this.graph.version) + 1);
  }

  /** Copies a service's status into its graph node; true when the graph changed. */
  syncServiceNode(ns, svc) {
    const s = this.summary(ns, svc);
    const n = this.graph.nodes.find((x) => x.id === svcNodeId(ns, svc));
    if (!s || !n) return false;
    s.status = this.statusOf(s);
    if (n.status !== s.status || n.instances !== s.instances.length) {
      n.status = s.status;
      n.instances = s.instances.length;
      this.graph.version = String(Number(this.graph.version) + 1);
      return true;
    }
    return false;
  }

  // ---- live events -----------------------------------------------------------------------------

  emit(type, data) {
    this.seq++;
    for (const sub of this.subs) {
      const out = type === 'audit' && data && data.record ? { ...data, record: this.redactPayloads(data.record) } : data;
      sub.onEvent(type, clone(out), String(this.seq));
    }
  }

  scheduleAcks(ns, svc, kind, version) {
    const s = this.summary(ns, svc);
    if (!s) return;
    s.instances.forEach((inst, i) => {
      this.timers.setTimeout(() => {
        const cur = this.summary(ns, svc);
        const live = cur && cur.instances.find((x) => x.instance_id === inst.instance_id);
        if (!live) return;
        const error = kind === 'charter' ? this.failing.get(inst.instance_id) || null : null;
        if (kind === 'charter') {
          live.acked_version = version;
          live.ack_error = error;
        }
        const changed = this.syncServiceNode(ns, svc);
        this.emit('ack', { namespace: ns, service: svc, instance_id: live.instance_id, pod: live.pod, kind, version, applied: !error, error });
        if (changed) this.emit('graph', { version: this.graph.version });
      }, 500 + i * 350);
    });
  }

  applyRegistry(d) {
    const s = this.summary(d.namespace, d.service);
    if (!s) return;
    if (d.status === 'disconnected') {
      const gone = s.instances.find((i) => i.instance_id === d.instance_id);
      if (gone) this.lastSeen = { ...this.lastSeen, [gone.pod]: gone };
      s.instances = s.instances.filter((i) => i.instance_id !== d.instance_id);
    } else if (!s.instances.some((i) => i.instance_id === d.instance_id)) {
      const prev = (this.lastSeen || {})[d.pod];
      s.instances.push({
        instance_id: d.instance_id,
        pod: d.pod,
        sidecar_version: prev ? prev.sidecar_version : '0.2.0',
        connected_at: this.iso(),
        last_heartbeat: this.iso(),
        runtime_ready: true,
        acked_version: s.charter_version,
        ack_error: null,
        cert_expires_in_s: prev ? prev.cert_expires_in_s : 86400,
        audit_dropped: 0,
      });
    }
    return this.syncServiceNode(d.namespace, d.service);
  }

  /** Applies a transcript event to the fixture state, then sends it to the subscribers. */
  deliver(type, data) {
    let graphChanged = false;
    if (type === 'registry') graphChanged = this.applyRegistry(data);
    if (type === 'ack' && data.kind === 'charter') {
      const s = this.summary(data.namespace, data.service);
      const i = s && s.instances.find((x) => x.instance_id === data.instance_id);
      if (i) {
        i.acked_version = data.version;
        i.ack_error = data.error;
      }
    }
    if (type === 'audit' && data.record) {
      this.events.unshift(clone(data.record));
      if (this.events.length > 2000) this.events.length = 2000;
    }
    if (type === 'proposal') {
      const p = this.proposals.find((x) => x.id === data.id);
      if (p) Object.assign(p, data);
      else this.proposals.unshift(clone(data));
      this.refreshLearning(data.namespace, data.service);
    }
    if (type === 'graph') {
      this.graph.version = String(Math.max(Number(this.graph.version) + 1, Number(data.version) || 0));
      data = { version: this.graph.version };
    }
    if (type === 'cp_audit' && this.me.role !== 'admin') return;
    this.emit(type, data);
    if (graphChanged) this.emit('graph', { version: this.graph.version });
  }

  /** The replay plan: transcript events at their natural times after the snapshot. */
  plan() {
    const out = [];
    let prev = this.snapshot + 700;
    for (const ev of this.transcript) {
      let data;
      try {
        data = JSON.parse(ev.data);
      } catch {
        continue;
      }
      let at = prev + 450;
      if (ev.event === 'audit' && data && data.record) at = Date.parse(data.record.ts);
      if (ev.event === 'cp_audit' && data) at = Date.parse(data.ts);
      if (!Number.isFinite(at)) at = prev + 450;
      at = Math.max(at, prev + 40);
      out.push({ at, type: ev.event, data });
      prev = at;
    }
    return out;
  }

  startReplay() {
    if (this.replayStarted || !this.replayEnabled) return;
    this.replayStarted = true;
    const plan = this.plan();
    if (!plan.length) return;
    const span = plan[plan.length - 1].at - this.snapshot;
    const period = Math.max(15000, span + 5000);
    // The replay starts when the first client subscribes (after sign-in, maybe much later).
    const start = this.now();
    const late = start - this.snapshot;
    const schedule = (pass) => {
      const shift = pass ? late + pass * period : 0;
      const remap = new Map();
      const id = (v) => {
        if (!pass || typeof v !== 'string') return v;
        if (!remap.has(v)) remap.set(v, v.includes('-') ? uuid() : uuid().replace(/-/g, ''));
        return remap.get(v);
      };
      for (const step of plan) {
        if (pass && step.type !== 'audit') continue;
        let data = step.data;
        if (pass && data.record) {
          const r = { ...data.record, ts: this.iso(Date.parse(data.record.ts) + shift), request_id: id(data.record.request_id), trace_id: id(data.record.trace_id) };
          if (r.output && typeof r.output === 'object' && r.output.request_id) r.output = { ...r.output, request_id: r.request_id, trace_id: r.trace_id };
          data = { ...data, record: r };
        }
        const wait = Math.max(0, start + (step.at - this.snapshot) + pass * period - this.now());
        this.replayTimers.push(this.timers.setTimeout(() => this.deliver(step.type, clone(data)), wait));
      }
      const next = Math.max(0, start + period * (pass + 1) - this.now());
      this.replayTimers.push(this.timers.setTimeout(() => schedule(pass + 1), next));
    };
    schedule(0);
  }

  stop() {
    for (const t of this.replayTimers) this.timers.clearTimeout(t);
    this.replayTimers = [];
  }

  subscribe({ onEvent, onStatus }) {
    const sub = { onEvent, onStatus };
    this.subs.add(sub);
    if (onStatus) onStatus('connecting');
    const t = this.timers.setTimeout(() => this.subs.has(sub) && onStatus && onStatus('live'), 250);
    this.startReplay();
    return {
      close: () => {
        this.subs.delete(sub);
        this.timers.clearTimeout(t);
        if (onStatus) onStatus('paused');
      },
    };
  }

  // ---- scenario=full ---------------------------------------------------------------------------

  /** Services in every status, placeholder peers, a mock model, a dimmed tool and skills. */
  addScenario() {
    const ns = 'attache-demo';
    const at = (ms) => this.iso(this.snapshot - ms);
    const inst = (id, pod, acked, extra = {}) => ({
      instance_id: id,
      pod,
      sidecar_version: '0.2.0',
      connected_at: at(3600000),
      last_heartbeat: at(4000),
      runtime_ready: true,
      acked_version: acked,
      ack_error: null,
      cert_expires_in_s: 64000,
      audit_dropped: 0,
      ...extra,
    });
    const returns = {
      apiVersion: 'attache.io/v1alpha1',
      kind: 'Charter',
      service: { name: 'returns', namespace: ns, app_port: 8070 },
      skills: [
        {
          name: 'refund-policy',
          description: 'How to decide whether a refund is allowed.',
          instructions: 'Look up the return with lookup_return first. Refunds above 200 EUR need a human.',
          tools: ['lookup_return'],
        },
        { name: 'tone', description: 'Write short, friendly answers.', instructions: 'Two sentences at most.' },
      ],
      agents: [
        {
          name: 'returns-desk',
          type: 'orchestrator',
          model: 'claude-sonnet-5-5',
          system: 'You handle return requests.\n',
          skills: ['refund-policy', 'tone'],
          tools: [
            { name: 'lookup_return', description: 'Look up a return by id.', type: 'service', service: 'returns', method: 'GET', path: '/returns/{id}' },
            { name: 'shipping_eta', description: "Ask the shipping service's ETA agent.", type: 'agent', agent: 'eta-agent', service: 'shipping' },
            { name: 'carrier_status', description: 'Carrier tracking API.', type: 'http', method: 'GET', url: 'https://api.carrier.example:8443/track/{id}' },
            { name: 'policy_check', description: 'Ask the local policy bot.', type: 'agent', agent: 'policy-bot' },
          ],
          budgets: { max_tokens_per_call: 2048, max_steps: 8 },
          harness: { max_retries: 2, request_timeout_seconds: 120, fallback_model: 'claude-haiku-5-5', tool_result_max_chars: 20000 },
          learning: { enabled: true, mode: 'auto', max_notes: 20, max_note_chars: 500, note_ttl_days: 7 },
        },
        { name: 'policy-bot', type: 'agent', model: 'mock', system: 'Answer ALLOW or DENY.\n' },
      ],
      guardrails: { allowed_tools: { 'returns-desk': ['lookup_return', 'shipping_eta', 'carrier_status'] } },
      authz: { default: 'deny', callers: [{ identity: 'local', agents: ['returns-desk'] }] },
      audit: { sink: 'stdout' },
    };
    const legacy = {
      apiVersion: 'attache.io/v1alpha1',
      kind: 'Charter',
      service: { name: 'legacy', namespace: ns, app_port: 9000 },
      agents: [{ name: 'report-bot', model: 'claude-haiku-5-5', system: 'You write the nightly report.\n' }],
      authz: { default: 'deny', callers: [{ identity: 'local', agents: ['*'] }] },
    };
    const add = (svc, charter, version, summary) => {
      this.charters.set(`${ns}/${svc}`, { epoch: uuid(), version, yaml: toYaml(charter), charter });
      this.history.set(`${ns}/${svc}`, [{ version, ts: at(7200000), actor: 'alice', sha256: fakeSha(svc) }]);
      this.services.push({ namespace: ns, service: svc, epoch: this.charters.get(`${ns}/${svc}`).epoch, charter_version: version, memory_version: '0', pending_adoption: null, ...summary });
    };
    add('returns', returns, '5', {
      status: 'degraded',
      instances: [
        inst('6f1c2a90-1d2e-4c3b-9a8f-0e1d2c3b4a59', 'returns-7d9f8c6b5-a1b2c', '5'),
        inst('7a2b3c4d-5e6f-4a1b-8c9d-0e1f2a3b4c5d', 'returns-7d9f8c6b5-d3e4f', '5', {
          ack_error: 'config.invalid: agents[0].tools[1]: peer shipping has no address',
        }),
        inst('8b3c4d5e-6f7a-4b2c-9d0e-1f2a3b4c5d6e', 'returns-7d9f8c6b5-g5h6i', '4', { runtime_ready: false, audit_dropped: 12 }),
      ],
    });
    this.failing.set('7a2b3c4d-5e6f-4a1b-8c9d-0e1f2a3b4c5d', 'config.invalid: agents[0].tools[1]: peer shipping has no address');
    add('legacy', legacy, '2', { status: 'disconnected', instances: [] });
    this.services.push({
      namespace: ns,
      service: 'billing',
      status: 'no_charter',
      epoch: null,
      charter_version: null,
      memory_version: null,
      pending_adoption: { sha256: fakeSha('billing-startup-charter'), pod: 'billing-6c8d7f5b4-x2k9q', ts: at(240000) },
      instances: [inst('9c4d5e6f-7a8b-4c3d-8e9f-2a3b4c5d6e7f', 'billing-6c8d7f5b4-x2k9q', null)],
    });
    this.pendingCharters.set(`${ns}/billing`, {
      apiVersion: 'attache.io/v1alpha1',
      kind: 'Charter',
      service: { name: 'billing', namespace: ns, app_port: 8090 },
      agents: [{ name: 'invoice-helper', model: 'claude-haiku-5-5', system: 'You explain invoices.\n' }],
      authz: { default: 'deny', callers: [{ identity: 'local', agents: ['*'] }] },
    });
    this.services.sort((a, b) => (a.namespace + a.service < b.namespace + b.service ? -1 : 1));
    this.syncGraph(ns, 'returns');
    this.syncGraph(ns, 'legacy');
    this.graph.nodes.push(
      { id: svcNodeId(ns, 'billing'), type: 'service', label: 'billing', namespace: ns, service: 'billing', status: 'no_charter', instances: 1, charter_version: null },
      { id: appNodeId(ns, 'billing'), type: 'app', parent: svcNodeId(ns, 'billing'), label: 'billing app', port: 8090, ports: { in: [], out: ['invoke'] }, stats: zeroAppStats() },
    );
    const set = (id, patch) => Object.assign(this.graph.nodes.find((n) => n.id === id) || {}, patch);
    set(agentNodeId(ns, 'returns', 'returns-desk'), {
      status: 'errors',
      stats: { invocations: 6, denied: 0, errors: 2, p50_ms: 1830, p95_ms: 6120, tokens_in: 9120, tokens_out: 1410, cost_usd: 0.061 },
    });
    const edge = this.graph.edges.find((e) => e.id === `edge:tool:${agentNodeId(ns, 'returns', 'returns-desk')}->${appNodeId(ns, 'returns')}#lookup_return`);
    if (edge) edge.stats = { calls: 6, denied: 0, errors: 2, avg_ms: 41, last_ts: at(52000) };
  }
}
