// Unit tests for the console's pure modules and the fixture-mode backend. Run with
// `node --test ui/tests/` (Node 20+), or through `python3 -I ui/tests/check_ui.py`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { parseSse } from '../js/sse.js';
import {
  roleAtLeast,
  parseNodeId,
  groupByRequest,
  payloadState,
  payloadText,
  instanceChip,
  diffPaths,
  applyPaths,
  overlappingPaths,
  stringChange,
  diffLines,
  diffHunks,
  visibleGraph,
  suggestToolName,
  linkRequirement,
  fmtMs,
  fmtCost,
  fmtCompact,
  relTime,
  fmtSeconds,
  isModelName,
  outcomeOf,
  inputSummary,
  clone,
  setIn,
  getIn,
} from '../js/util.js';
import { G, nodeBox, portPoint, bezier, edgePath, frameRect, rectsOverlap } from '../js/geometry.js';
import { autoLayout, resolvePositions, depths } from '../js/layout.js';
import { createFixtureServer, synthAgentView, toolTarget, validateAgent, judgeCharter } from '../js/fixtures.js';
import { Api, ApiError, parseEtag } from '../js/api.js';
import { viewPayload, normalizeView } from '../js/tab-config.js';
import { targetFor, tabsFor } from '../js/inspector.js';
import { loadPositions, savePositions, clearPositions, POSITIONS_KEY } from '../js/store.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const fixture = (name) => readFileSync(join(FIX, name), 'utf8');
const json = (name) => JSON.parse(fixture(name));
const load = async (name) => {
  try {
    return readFileSync(join(FIX, name), 'utf8');
  } catch {
    return null;
  }
};
const boxOf = (n) => nodeBox(n, { linkPort: true });

/** Fake timers and clock for the fixture server's replay. */
function fakeTime() {
  let now = 0;
  let seq = 0;
  const queue = [];
  return {
    monotonic: () => now,
    timers: {
      setTimeout(fn, ms) {
        const id = ++seq;
        queue.push({ id, at: now + Math.max(0, ms), fn });
        return id;
      },
      clearTimeout(id) {
        const i = queue.findIndex((t) => t.id === id);
        if (i >= 0) queue.splice(i, 1);
      },
    },
    advance(ms) {
      const end = now + ms;
      for (;;) {
        queue.sort((a, b) => a.at - b.at || a.id - b.id);
        const next = queue[0];
        if (!next || next.at > end) break;
        queue.shift();
        now = next.at;
        next.fn();
      }
      now = end;
    },
  };
}

async function server(query = '', opts = {}) {
  const t = fakeTime();
  const s = await createFixtureServer({ load, params: new URLSearchParams(query), timers: t.timers, monotonic: t.monotonic, replay: opts.replay ?? false });
  return { s, t };
}

const W = { 'Content-Type': 'application/json', 'X-Attache-CSRF': '1' };

// ---- sse ------------------------------------------------------------------------------------------

test('parseSse reads the golden transcript', () => {
  const { events, comments } = parseSse(fixture('events.sse'));
  assert.ok(events.length >= 17);
  assert.equal(comments, 1);
  assert.equal(events[0].id, '48211');
  assert.equal(events[0].event, 'registry');
  for (const e of events) JSON.parse(e.data);
  const types = new Set(events.map((e) => e.event));
  for (const t of ['registry', 'ack', 'audit', 'graph', 'proposal', 'cp_audit']) assert.ok(types.has(t), t);
});

test('parseSse joins multi-line data, handles CRLF, ignores comments and unknown fields', () => {
  const { events, comments } = parseSse(': hi\r\nid: 7\r\nevent: x\r\ndata: a\r\ndata:b\r\nretry: 5\r\n\r\ndata: tail');
  assert.deepEqual(events, [
    { id: '7', event: 'x', data: 'a\nb' },
    { id: '7', event: 'message', data: 'tail' },
  ]);
  assert.equal(comments, 1);
});

// ---- util ----------------------------------------------------------------------------------------

test('roles are ordered viewer < editor < admin and unknown roles are never enough', () => {
  assert.ok(roleAtLeast('admin', 'editor'));
  assert.ok(roleAtLeast('editor', 'editor'));
  assert.ok(!roleAtLeast('viewer', 'editor'));
  assert.ok(!roleAtLeast('root', 'viewer'));
  assert.ok(!roleAtLeast('admin', 'superuser'));
});

test('parseNodeId understands every node id form', () => {
  assert.deepEqual(parseNodeId('svc:shop/orders'), { kind: 'svc', ns: 'shop', svc: 'orders' });
  assert.deepEqual(parseNodeId('app:shop/orders'), { kind: 'app', ns: 'shop', svc: 'orders' });
  assert.deepEqual(parseNodeId('agent:shop/orders/ops'), { kind: 'agent', ns: 'shop', svc: 'orders', agent: 'ops' });
  assert.deepEqual(parseNodeId('model:anthropic'), { kind: 'model', provider: 'anthropic' });
  assert.deepEqual(parseNodeId('external:https://api.x.example:8443'), { kind: 'external', origin: 'https://api.x.example:8443' });
  assert.equal(parseNodeId('nope'), null);
  assert.equal(parseNodeId(42), null);
});

test('groupByRequest groups the recent events newest request first, records oldest first', () => {
  const groups = groupByRequest(json('events-recent.json'));
  assert.equal(groups.length, 3);
  assert.equal(groups[0].request_id, 'a6cd1b82-8713-4940-a670-ea20303e6b47');
  assert.equal(groups[0].outcome, 'deny');
  const reset = groups.find((g) => g.request_id.startsWith('6d3e3a28'));
  assert.equal(reset.outcome, 'allow', 'the invocation itself was allowed');
  assert.equal(reset.denied, 3);
  assert.equal(reset.root.kind, 'agent_invocation');
  for (const g of groups) {
    const ts = g.records.map((r) => Date.parse(r.ts));
    assert.deepEqual(ts, [...ts].sort((a, b) => a - b));
  }
  assert.deepEqual(groupByRequest([null, 5, { ts: 'x' }]).map((g) => g.request_id), ['(none)']);
});

test('payload display: hidden without payload rights, absent when only the hash came', () => {
  assert.equal(payloadState({ a: 1 }, 'ab', false), 'hidden');
  assert.equal(payloadState(null, 'ab', true), 'absent');
  assert.equal(payloadState(null, null, true), 'null');
  assert.equal(payloadState('x', null, true), 'value');
  assert.equal(payloadText('line\nbreak'), 'line\nbreak');
  assert.equal(payloadText({ a: [1] }), '{\n  "a": [\n    1\n  ]\n}');
  assert.equal(payloadText('<img src=x onerror=alert(1)>'), '<img src=x onerror=alert(1)>', 'kept as text, shown via textContent');
});

test('instanceChip: pending, ✓ vN, ✗ with the error', () => {
  assert.deepEqual(instanceChip({ acked_version: '3', ack_error: null }, '3').label, '✓ v3');
  assert.equal(instanceChip({ acked_version: '2', ack_error: null }, '3').state, 'pending');
  assert.equal(instanceChip({ acked_version: null, ack_error: null }, null).state, 'pending');
  const e = instanceChip({ acked_version: '3', ack_error: 'config.invalid: x' }, '3');
  assert.equal(e.state, 'error');
  assert.equal(e.label, '✗ v3');
  assert.equal(e.title, 'config.invalid: x');
});

test('diffPaths, applyPaths and overlappingPaths re-apply edits on a newer version', () => {
  const base = { agent: { model: 'a', budgets: { max_steps: 4 }, tools: [{ name: 't', description: 'x' }] } };
  const mine = clone(base);
  mine.agent.model = 'b';
  mine.agent.tools[0].description = 'mine';
  const theirs = clone(base);
  theirs.agent.budgets.max_steps = 9;
  theirs.agent.tools[0].description = 'theirs';
  const m = diffPaths(base, mine);
  const t = diffPaths(base, theirs);
  assert.deepEqual(m.map((x) => x.path).sort(), ['agent.model', 'agent.tools[0].description']);
  assert.deepEqual(overlappingPaths(m, t), ['agent.tools[0].description']);
  const merged = applyPaths(clone(theirs), m);
  assert.equal(merged.agent.model, 'b');
  assert.equal(merged.agent.budgets.max_steps, 9);
  assert.equal(merged.agent.tools[0].description, 'mine');
  const removed = diffPaths({ a: 1, b: 2 }, { a: 1 });
  assert.deepEqual(removed, [{ keys: ['b'], path: 'b', before: 2, after: undefined }]);
  assert.deepEqual(applyPaths({ a: 1, b: 2 }, removed), { a: 1 });
  assert.equal(diffPaths([1, 2], [1, 2, 3])[0].path, '');
});

test('setIn and getIn create and delete along a path', () => {
  const o = {};
  setIn(o, ['a', 'b', 0, 'c'], 1);
  assert.deepEqual(o, { a: { b: [{ c: 1 }] } });
  assert.equal(getIn(o, ['a', 'b', 0, 'c']), 1);
  setIn(o, ['a', 'b', 0, 'c'], undefined);
  assert.deepEqual(o, { a: { b: [{}] } });
  assert.equal(getIn(o, ['x', 'y']), undefined);
});

test('stringChange shows the edited part of a long string', () => {
  const a = `${'x'.repeat(100)}cat${'y'.repeat(100)}`;
  const b = `${'x'.repeat(100)}dog${'y'.repeat(100)}`;
  const c = stringChange(a, b, 5);
  assert.equal(c.before, '…xxxxxcatyyyyy…');
  assert.equal(c.after, '…xxxxxdogyyyyy…');
  assert.deepEqual(stringChange('ab', 'abc', 5), { before: 'ab', after: 'abc' });
});

test('diffLines and diffHunks show a YAML change with context', () => {
  const ops = diffLines('a\nb\nc\nd\ne\nf\ng', 'a\nb\nc\nD\ne\nf\ng');
  assert.deepEqual(
    ops.filter((o) => o.op !== ' '),
    [
      { op: '-', text: 'd' },
      { op: '+', text: 'D' },
    ],
  );
  const h = diffHunks(ops, 1);
  assert.deepEqual(h.map((o) => o.op), ['…', ' ', '-', '+', ' ', '…']);
  assert.equal(diffLines('a', 'b', 1), null, 'too large for the cell budget');
});

test('visibleGraph filters by namespace and service and keeps connected providers', () => {
  const g = json('graph.json');
  assert.equal(visibleGraph(g, {}).nodes.length, g.nodes.length);
  const inv = visibleGraph(g, { ns: 'attache-demo', svc: 'inventory' });
  const ids = inv.nodes.map((n) => n.id);
  assert.ok(ids.includes('svc:attache-demo/inventory'));
  assert.ok(ids.includes('agent:attache-demo/inventory/stock-analyst'));
  assert.ok(ids.includes('model:anthropic'));
  assert.ok(!ids.includes('agent:attache-demo/orders/ops-assistant'));
  assert.ok(!ids.includes('external:https://api.partner.example'));
  for (const e of inv.edges) assert.ok(ids.includes(e.source) && ids.includes(e.target));
  assert.equal(visibleGraph(g, { ns: 'other' }).nodes.length, 0);
});

test('link requirements: same service editor, cross service admin, cross namespace refused', () => {
  assert.equal(linkRequirement('agent:a/s/x', 'agent:a/s/y').level, 'editor');
  assert.equal(linkRequirement('agent:a/s/x', 'agent:a/t/y').level, 'admin');
  assert.equal(linkRequirement('agent:a/s/x', 'agent:b/s/y').level, 'refused');
  assert.equal(linkRequirement('agent:a/s/x', 'agent:a/s/x').level, 'refused');
  assert.equal(linkRequirement('app:a/s', 'agent:a/s/x').level, 'refused');
  assert.equal(suggestToolName('stock-analyst', []), 'stock_analyst');
  assert.equal(suggestToolName('stock-analyst', ['stock_analyst']), 'stock_analyst_2');
});

test('formatting helpers', () => {
  assert.equal(fmtMs(840), '840 ms');
  assert.equal(fmtMs(5247), '5.2 s');
  assert.equal(fmtMs(65000), '1 min 5 s');
  assert.equal(fmtCost(0.099428), '$0.099');
  assert.equal(fmtCost(0.41), '$0.41');
  assert.equal(fmtCost(0.0011), '$0.001');
  assert.equal(fmtCost(0.00042), '$0.0004');
  assert.equal(fmtCost(0), '$0');
  assert.equal(fmtCompact(20405), '20.4k');
  assert.equal(relTime('2026-10-21T09:59:50.000Z', Date.parse('2026-10-21T10:00:00.000Z')), '10 s ago');
  assert.equal(relTime('2026-10-21T10:05:00.000Z', Date.parse('2026-10-21T10:00:00.000Z')), 'in 5 min');
  assert.equal(fmtSeconds(70841), '19 h 41 min');
  assert.equal(fmtSeconds(-7200), 'expired 2 h 0 min ago');
  assert.ok(isModelName('claude-opus-5-5'));
  assert.ok(!isModelName('two words'));
  assert.ok(!isModelName(''));
  assert.equal(outcomeOf({ decision: 'allow', error: 'boom' }), 'error');
  assert.equal(outcomeOf({ decision: 'deny', error: null }), 'deny');
  assert.equal(inputSummary({ input: { input: 'q', context: {} } }), 'q');
  assert.equal(inputSummary({ input: { method: 'GET', path: '/x' } }), 'GET /x');
});

// ---- geometry and layout ---------------------------------------------------------------------------

test('nodeBox places ports in declaration order; unknown ports attach to the border', () => {
  const g = json('graph.json');
  const ops = g.nodes.find((n) => n.id === 'agent:attache-demo/orders/ops-assistant');
  const box = nodeBox(ops, { linkPort: true });
  assert.deepEqual(box.outPorts.map((p) => p.name), ops.ports.out);
  assert.equal(box.inPorts[0].x, 0);
  assert.equal(box.outPorts[0].x, box.w);
  assert.ok(box.linkPort, 'orchestrators get the + port when linking is allowed');
  assert.equal(nodeBox(ops).linkPort, null);
  const pos = { x: 100, y: 50 };
  const known = portPoint(box, pos, 'out', 'stock_analyst');
  assert.ok(known.known);
  assert.equal(known.x, 100 + box.w);
  const border = portPoint(box, pos, 'out', 'partner_eta');
  assert.equal(border.known, false);
  assert.equal(border.x, 100 + box.w);
  const placeholder = nodeBox({ id: 'agent:a/b/c', type: 'agent', placeholder: true, ports: { in: ['invoke'], out: [] } });
  assert.equal(placeholder.type, 'placeholder');
});

test('edges: forward edges are one Bézier, backward edges route around the cards', () => {
  assert.match(bezier({ x: 0, y: 0 }, { x: 100, y: 50 }), /^M0,0 C\S+ \S+ 100,50$/);
  const sr = { x: 300, y: 0, w: 260, h: 200 };
  const tr = { x: 0, y: 0, w: 200, h: 120 };
  const back = edgePath({ x: 560, y: 40 }, { x: 0, y: 40 }, sr, tr);
  assert.ok(back.includes('Q'), back);
  const ys = [...back.matchAll(/[ML](-?[\d.]+),(-?[\d.]+)/g)].map((m) => Number(m[2]));
  assert.ok(Math.max(...ys) > 200, 'runs below both cards');
  const fr = frameRect([
    { x: 10, y: 20, w: 100, h: 50 },
    { x: 200, y: 20, w: 100, h: 80 },
  ]);
  assert.deepEqual(fr, { x: 10 - G.framePad, y: 20 - G.framePad - G.frameTitle, w: 290 + 2 * G.framePad, h: 80 + 2 * G.framePad + G.frameTitle });
});

test('depths: longest path, cycle-safe', () => {
  const d = depths(['a', 'b', 'c'], [
    ['a', 'b'],
    ['b', 'c'],
    ['a', 'c'],
  ]);
  assert.deepEqual([...d.values()], [0, 1, 2]);
  const cyc = depths(['x', 'y'], [
    ['x', 'y'],
    ['y', 'x'],
  ]);
  assert.equal(cyc.size, 2);
});

test('autoLayout: service columns by call depth, app left of agents, providers last, no overlaps', () => {
  const g = json('graph.json');
  const pos = autoLayout(g, boxOf);
  const at = (id) => pos.get(id);
  const orders = ['app:attache-demo/orders', 'agent:attache-demo/orders/ops-assistant', 'agent:attache-demo/orders/order-triage'];
  const inventory = ['app:attache-demo/inventory', 'agent:attache-demo/inventory/stock-analyst'];
  const right = (ids) => Math.max(...ids.map((id) => at(id).x + boxOf(g.nodes.find((n) => n.id === id)).w));
  assert.ok(right(orders) < Math.min(...inventory.map((id) => at(id).x)), 'orders (the caller) comes first');
  assert.ok(at('app:attache-demo/orders').x < at('agent:attache-demo/orders/ops-assistant').x);
  assert.ok(at('agent:attache-demo/orders/ops-assistant').y < at('agent:attache-demo/orders/order-triage').y, 'the caller sits above the agent it calls');
  assert.equal(at('agent:attache-demo/orders/ops-assistant').x, at('agent:attache-demo/orders/order-triage').x);
  for (const id of ['model:anthropic', 'external:https://api.partner.example']) assert.ok(at(id).x > right(inventory));
  const rects = g.nodes.filter((n) => n.type !== 'service').map((n) => ({ ...at(n.id), w: boxOf(n).w, h: boxOf(n).h, id: n.id }));
  for (let i = 0; i < rects.length; i++) for (let j = i + 1; j < rects.length; j++) assert.ok(!rectsOverlap(rects[i], rects[j]), `${rects[i].id} overlaps ${rects[j].id}`);
});

test('resolvePositions keeps saved positions and puts a new agent below its hand-placed siblings', () => {
  const g = json('graph.json');
  const saved = new Map([
    ['agent:attache-demo/orders/ops-assistant', { x: 1000, y: 1000 }],
    ['agent:attache-demo/orders/order-triage', { x: 1000, y: 1400 }],
  ]);
  const g2 = clone(g);
  g2.nodes.push({ ...clone(g.nodes.find((n) => n.id.endsWith('order-triage'))), id: 'agent:attache-demo/orders/new-one', label: 'new-one' });
  const pos = resolvePositions(g2, saved, boxOf);
  assert.deepEqual(pos.get('agent:attache-demo/orders/ops-assistant'), { x: 1000, y: 1000 });
  const triage = g.nodes.find((n) => n.id.endsWith('order-triage'));
  assert.deepEqual(pos.get('agent:attache-demo/orders/new-one'), { x: 1000, y: 1400 + boxOf(triage).h + 40 });
});

// ---- store -------------------------------------------------------------------------------------------

test('positions survive a round trip through storage; malformed entries are dropped', () => {
  const mem = new Map();
  globalThis.localStorage = {
    getItem: (k) => (mem.has(k) ? mem.get(k) : null),
    setItem: (k, v) => mem.set(k, String(v)),
    removeItem: (k) => mem.delete(k),
  };
  try {
    savePositions(new Map([['agent:a/b/c', { x: 1.4, y: -2.6 }]]));
    assert.deepEqual([...loadPositions()], [['agent:a/b/c', { x: 1, y: -3 }]]);
    mem.set(POSITIONS_KEY, JSON.stringify({ ok: [1, 2], bad: ['x', 2], huge: [1e9, 0], arr: 5 }));
    assert.deepEqual([...loadPositions().keys()], ['ok']);
    mem.set(POSITIONS_KEY, '{not json');
    assert.equal(loadPositions().size, 0);
    clearPositions();
    assert.equal(mem.has(POSITIONS_KEY), false);
  } finally {
    delete globalThis.localStorage;
  }
  assert.equal(loadPositions().size, 0, 'no storage at all is fine');
});

// ---- api client ---------------------------------------------------------------------------------------

test('the API client sends CSRF, JSON and quoted If-Match on writes, nothing extra on reads', async () => {
  const calls = [];
  const api = new Api(
    async (method, path, opts) => {
      calls.push({ method, path, ...opts });
      return { status: 200, etag: '"7"', data: { version: '8' } };
    },
    { now: () => 0, subscribe: () => null, fixtures: false },
  );
  const r = await api.putAgent('ns', 'svc', 'a b', { agent: {} }, '7');
  assert.deepEqual(calls[0].headers, { 'Content-Type': 'application/json', 'X-Attache-CSRF': '1', 'If-Match': '"7"' });
  assert.equal(calls[0].path, '/services/ns/svc/agents/a%20b');
  assert.equal(r.version, '7');
  await api.recent({ namespace: 'ns', agent: undefined, limit: 5 });
  assert.equal(calls[1].path, '/events/recent?namespace=ns&limit=5');
  assert.deepEqual(calls[1].headers, {});
  await api.putCharter('ns', 'svc', 'yaml', null);
  assert.equal(calls[2].headers['If-None-Match'], '*');
  assert.equal(calls[2].headers['If-Match'], undefined);
  await api.logout();
  assert.equal(calls[3].headers['X-Attache-CSRF'], '1', 'bodiless writes still carry the headers');
});

test('API errors carry code, details and current_version; 401 signs out', async () => {
  let signedOut = 0;
  const api = new Api(async () => ({ status: 409, data: { error: 'version_conflict', details: ['stale'], current_version: '4' } }), { now: () => 0 });
  await assert.rejects(api.graph(), (e) => e instanceof ApiError && e.status === 409 && e.code === 'version_conflict' && e.currentVersion === '4' && e.details[0] === 'stale');
  const api2 = new Api(async () => ({ status: 401, data: null }), { now: () => 0 });
  api2.onUnauthenticated = () => signedOut++;
  await assert.rejects(api2.graph(), (e) => e.code === 'http_401');
  assert.equal(signedOut, 1);
  await assert.rejects(api2.login('att_x'));
  assert.equal(signedOut, 1, 'a failed login is not a lost session');
  assert.equal(parseEtag('"12"'), '12');
  assert.equal(parseEtag('W/"3"'), '3');
  assert.equal(parseEtag('abc'), null);
});

// ---- config form payload -------------------------------------------------------------------------------

test('viewPayload drops empty sections the original lacked and fields of other tool types', () => {
  const original = normalizeView({ agent: { name: 'a', model: 'm', tools: [{ name: 't', description: 'd', type: 'service', service: 's', method: 'GET', path: '/' }] } });
  const draft = clone(original);
  draft.agent.budgets = {};
  draft.agent.skills = [];
  draft.agent.tools[0].type = 'agent';
  draft.agent.tools[0].agent = 'b';
  const p = viewPayload(draft, original);
  assert.equal(p.agent.budgets, undefined);
  assert.equal(p.agent.skills, undefined);
  assert.deepEqual(p.agent.tools[0], { name: 't', description: 'd', type: 'agent', service: 's', agent: 'b' });
  assert.equal(p.allowed_tools, null);
  assert.deepEqual(p.callers, []);
  const withSkills = normalizeView({ agent: { name: 'a', model: 'm', skills: [] } });
  assert.deepEqual(viewPayload(withSkills, withSkills).agent.skills, [], 'an explicit empty list stays');
});

test('inspector targets and tabs per node kind', () => {
  const g = json('graph.json');
  const t = targetFor(g.nodes.find((n) => n.id === 'agent:attache-demo/orders/ops-assistant'));
  assert.deepEqual(t, { kind: 'agent', id: 'agent:attache-demo/orders/ops-assistant', ns: 'attache-demo', svc: 'orders', agent: 'ops-assistant' });
  assert.deepEqual(tabsFor(t, true), ['config', 'traffic', 'learning', 'yaml', 'instances']);
  assert.deepEqual(tabsFor({ kind: 'service' }, false), ['overview', 'instances']);
  assert.deepEqual(tabsFor(targetFor({ id: 'model:anthropic', type: 'model_provider' }), false), ['overview']);
  assert.equal(targetFor({ id: 'agent:a/b/c', type: 'agent', placeholder: true }).kind, 'node');
});

// ---- fixture backend ---------------------------------------------------------------------------------------

test('fixture agent views are derived from the charter exactly like agent-view.json', async () => {
  const orders = json('charter-orders.json').charter;
  assert.deepEqual(synthAgentView(orders, 'ops-assistant'), json('agent-view.json'));
  const { s } = await server();
  const r = await s.handle('GET', '/services/attache-demo/orders/agents/ops-assistant');
  assert.equal(r.status, 200);
  assert.equal(r.etag, '"3"');
  assert.deepEqual(r.data, json('agent-view.json'));
  assert.equal(toolTarget('ns', 'svc', { type: 'http', url: 'https://x.example:8443/a/{id}' }), 'external:https://x.example:8443');
});

test('fixture graph: every edge endpoint is a node', async () => {
  for (const q of ['', 'scenario=full']) {
    const { s } = await server(q);
    const g = (await s.handle('GET', '/graph')).data;
    const ids = new Set(g.nodes.map((n) => n.id));
    for (const e of g.edges) assert.ok(ids.has(e.source) && ids.has(e.target), `${q}: ${e.id}`);
  }
});

test('fixture writes: CSRF, role, If-Match and 409 with current_version', async () => {
  const { s } = await server();
  const view = json('agent-view.json');
  assert.equal((await s.handle('PUT', '/services/attache-demo/orders/agents/ops-assistant', { headers: { 'If-Match': '"3"' }, body: view })).status, 403, 'no CSRF header');
  assert.equal((await s.handle('PUT', '/services/attache-demo/orders/agents/ops-assistant', { headers: W, body: view })).data.error, 'invalid', 'no If-Match');
  const stale = await s.handle('PUT', '/services/attache-demo/orders/agents/ops-assistant', { headers: { ...W, 'If-Match': '"2"' }, body: view });
  assert.equal(stale.status, 409);
  assert.equal(stale.data.current_version, '3');
  const v0 = Number((await s.handle('GET', '/graph')).data.version);
  view.agent.budgets.max_steps = 9;
  const ok = await s.handle('PUT', '/services/attache-demo/orders/agents/ops-assistant', { headers: { ...W, 'If-Match': '"3"' }, body: view });
  assert.equal(ok.status, 200);
  assert.equal(ok.data.version, '4');
  assert.ok(Number((await s.handle('GET', '/graph')).data.version) > v0);
  const bad = clone(view);
  bad.agent.tools.push({ name: 'load_skill', description: 'x', type: 'agent', agent: 'order-triage' });
  const inv = await s.handle('PUT', '/services/attache-demo/orders/agents/ops-assistant', { headers: { ...W, 'If-Match': '"4"' }, body: bad });
  assert.equal(inv.status, 400);
  assert.ok(inv.data.details.some((d) => d.includes('load_skill')));
});

test('fixture viewer is read-only and conflict=1 simulates a concurrent edit', async () => {
  const { s } = await server('role=viewer');
  assert.equal((await s.handle('GET', '/whoami')).data.role, 'viewer');
  assert.equal((await s.handle('POST', '/services/attache-demo/orders/agents', { headers: { ...W, 'If-Match': '"3"' }, body: { agent: { name: 'x', model: 'm' } } })).status, 403);
  const { s: c } = await server('conflict=1');
  const r = await c.handle('PUT', '/services/attache-demo/orders/agents/ops-assistant', { headers: { ...W, 'If-Match': '"3"' }, body: json('agent-view.json') });
  assert.equal(r.status, 409);
  assert.equal(r.data.current_version, '4');
  const now = (await c.handle('GET', '/services/attache-demo/orders/agents/ops-assistant')).data;
  assert.equal(now.agent.budgets.max_steps, 8);
});

test('fixture POST agent adds the node, the local invoke edge and refuses duplicates', async () => {
  const { s } = await server();
  const body = { agent: { name: 'refund-helper', model: 'claude-opus-5-5' } };
  const r = await s.handle('POST', '/services/attache-demo/orders/agents', { headers: { ...W, 'If-Match': '"3"' }, body });
  assert.equal(r.status, 201);
  const g = (await s.handle('GET', '/graph')).data;
  assert.ok(g.nodes.some((n) => n.id === 'agent:attache-demo/orders/refund-helper'));
  assert.ok(g.edges.some((e) => e.id === 'edge:invoke:app:attache-demo/orders->agent:attache-demo/orders/refund-helper'));
  const dup = await s.handle('POST', '/services/attache-demo/orders/agents', { headers: { ...W, 'If-Match': '"4"' }, body });
  assert.equal(dup.status, 400);
});

test('fixture links: cross-namespace refused, cross-service needs admin, admin applies both charters', async () => {
  const body = (from, to, ifm) => ({ from, to, tool: { name: 'ask_stock', description: 'Ask.' }, if_match: ifm });
  const ops = 'agent:attache-demo/orders/ops-assistant';
  const stock = 'agent:attache-demo/inventory/stock-analyst';
  const { s: editor } = await server('role=editor');
  assert.equal((await editor.handle('POST', '/links', { headers: W, body: body(ops, 'agent:other/inventory/stock-analyst', {}) })).status, 400);
  assert.equal((await editor.handle('POST', '/links', { headers: W, body: body(ops, stock, {}) })).status, 403);
  const same = await editor.handle('POST', '/links', { headers: W, body: body(ops, 'agent:attache-demo/orders/order-triage', { 'attache-demo/orders': '3' }) });
  assert.deepEqual(same.data.applied, [{ service: 'attache-demo/orders', version: '4' }]);
  const { s: admin } = await server();
  const stale = await admin.handle('POST', '/links', { headers: W, body: body(ops, stock, { 'attache-demo/inventory': '0' }) });
  assert.equal(stale.data.failed['attache-demo/inventory'].error, 'version_conflict');
  const r = await admin.handle('POST', '/links', { headers: W, body: body(ops, stock, { 'attache-demo/inventory': '1', 'attache-demo/orders': '3' }) });
  assert.deepEqual(r.data.applied.map((a) => a.service), ['attache-demo/inventory', 'attache-demo/orders']);
  const inv = (await admin.handle('GET', '/services/attache-demo/inventory/charter')).data.charter;
  assert.ok(inv.authz.callers.find((c) => c.identity === 'spiffe://attache/ns/attache-demo/svc/orders').agents.includes('stock-analyst'));
  const view = (await admin.handle('GET', '/services/attache-demo/orders/agents/ops-assistant')).data;
  assert.ok(view.agent.tools.some((t) => t.name === 'ask_stock' && t.service === 'inventory'));
  assert.ok(view.allowed_tools.includes('ask_stock'));
});

test('fixture proposals: approve needs the memory version, stores the note, then refuses again', async () => {
  const { s } = await server();
  const id = '784722e9-e727-4c29-9f39-e116fd9afcd5';
  assert.equal((await s.handle('POST', `/proposals/${id}/approve`, { headers: { ...W, 'If-Match': '"0"' } })).status, 409);
  const r = await s.handle('POST', `/proposals/${id}/approve`, { headers: { ...W, 'If-Match': '"1"' } });
  assert.equal(r.status, 200);
  assert.equal(r.data.memory_version, '2');
  assert.equal(r.data.proposal.status, 'approved');
  const mem = (await s.handle('GET', '/services/attache-demo/orders/memory')).data;
  assert.equal(mem.agents['ops-assistant'].length, 2);
  assert.equal(mem.agents['ops-assistant'][1].approved_by, 'alice');
  assert.equal((await s.handle('POST', `/proposals/${id}/reject`, { headers: { ...W, 'If-Match': '"2"' } })).status, 409);
  const put = await s.handle('PUT', '/services/attache-demo/orders/memory', { headers: { ...W, 'If-Match': '"2"' }, body: { agents: {} } });
  assert.equal(put.data.version, '3');
});

test('fixture events/recent filters (agent matches caller_agent) and hides payloads per token', async () => {
  const { s } = await server();
  const r = (await s.handle('GET', '/events/recent?service=inventory&agent=ops-assistant')).data;
  assert.ok(r.length > 0);
  assert.ok(r.every((x) => x.service === 'inventory' && (x.agent === 'ops-assistant' || x.caller_agent === 'ops-assistant')));
  assert.equal((await s.handle('GET', '/events/recent?limit=0')).status, 400);
  const { s: hidden } = await server('payloads=0');
  const h = (await hidden.handle('GET', '/events/recent')).data;
  assert.ok(h.every((x) => x.input === null && x.output === null));
  assert.ok(h.some((x) => x.input_sha256), 'hashes stay');
});

test('fixture sign-in: 401 until a well-formed token logs in', async () => {
  const { s } = await server('signin=1');
  assert.equal((await s.handle('GET', '/graph')).status, 401);
  assert.equal((await s.handle('POST', '/login', { headers: W, body: { token: 'nope' } })).status, 400);
  assert.equal((await s.handle('POST', '/login', { headers: W, body: { token: `att_${'a'.repeat(43)}` } })).status, 200);
  assert.equal((await s.handle('GET', '/graph')).status, 200);
  assert.equal((await s.handle('POST', '/logout', { headers: W })).status, 204);
  assert.equal((await s.handle('GET', '/whoami')).status, 401);
});

test('fixture scenario=full has every service and agent status, placeholders and a pending adoption', async () => {
  const { s } = await server('scenario=full');
  const g = (await s.handle('GET', '/graph')).data;
  const svcStatus = new Set(g.nodes.filter((n) => n.type === 'service' && !n.placeholder).map((n) => n.status));
  for (const st of ['connected', 'degraded', 'disconnected', 'no_charter']) assert.ok(svcStatus.has(st), st);
  const agentStatus = new Set(g.nodes.filter((n) => n.type === 'agent' && !n.placeholder).map((n) => n.status));
  for (const st of ['ok', 'denied', 'errors', 'idle']) assert.ok(agentStatus.has(st), st);
  assert.ok(g.nodes.some((n) => n.placeholder && n.id === 'agent:attache-demo/shipping/eta-agent'));
  assert.ok(g.nodes.some((n) => n.id === 'model:mock'));
  assert.ok(g.nodes.some((n) => n.id === 'external:https://api.carrier.example:8443'));
  const billing = (await s.handle('GET', '/services')).data.find((x) => x.service === 'billing');
  const r = await s.handle('POST', '/services/attache-demo/billing/adopt', { headers: W, body: { sha256: billing.pending_adoption.sha256 } });
  assert.equal(r.status, 200);
  assert.equal((await s.handle('POST', '/services/attache-demo/billing/adopt', { headers: W, body: { sha256: billing.pending_adoption.sha256 } })).status, 409);
});

test('fixture charter validation reports needs_role and weakened changes', async () => {
  const { s } = await server('role=editor');
  const doc = (await s.handle('GET', '/services/attache-demo/inventory/charter')).data;
  const weak = doc.yaml.replace('default: deny', 'default: allow').replace('pii_redact: true', 'pii_redact: false');
  const v = await s.handle('POST', '/services/attache-demo/inventory/charter/validate', { headers: W, body: { yaml: weak } });
  assert.equal(v.data.needs_role, 'admin');
  assert.deepEqual(v.data.weakened, ['authz.default', 'guardrails.pii_redact']);
  const put = await s.handle('PUT', '/services/attache-demo/inventory/charter', { headers: { ...W, 'If-Match': '"1"' }, body: { yaml: weak } });
  assert.equal(put.status, 403);
  const fine = await s.handle('POST', '/services/attache-demo/inventory/charter/validate', { headers: W, body: { yaml: doc.yaml.replace('Keep it to three sentences.', 'Be brief.') } });
  assert.equal(fine.data.needs_role, 'editor');
  assert.equal((await s.handle('POST', '/services/attache-demo/inventory/charter/validate', { headers: W, body: { yaml: '\tagents: []' } })).status, 400);
  assert.deepEqual(judgeCharter({ authz: { default: 'deny' } }, '', { authz: { default: 'allow' } }, ''), { needs_role: 'admin', weakened: ['authz.default'] });
  assert.ok(validateAgent({ name: 'a', model: 'm', learning: { mode: 'auto' } }, {}).some((d) => d.includes('auto requires enabled')));
});

test('fixture replay delivers the transcript in order and applies it to the state', async () => {
  const { s, t } = await server('', { replay: true });
  const seen = [];
  const statuses = [];
  const sub = s.subscribe({ onEvent: (type, data, id) => seen.push({ type, data, id }), onStatus: (st) => statuses.push(st) });
  t.advance(20000);
  const types = seen.map((e) => e.type);
  assert.deepEqual(types.filter((x) => x !== 'graph').slice(0, 3), ['registry', 'registry', 'ack']);
  assert.ok(types.indexOf('graph') > types.indexOf('registry'), 'state events come before the graph refresh they cause');
  assert.ok(types.filter((x) => x === 'audit').length >= 11);
  assert.ok(types.includes('proposal') && types.includes('cp_audit'));
  const ids = seen.map((e) => Number(e.id));
  assert.deepEqual(ids, [...ids].sort((a, b) => a - b));
  assert.deepEqual(statuses.slice(0, 2), ['connecting', 'live']);
  const inv = (await s.handle('GET', '/services')).data.find((x) => x.service === 'inventory');
  assert.deepEqual(inv.instances.map((i) => i.instance_id), ['f835313f-ef20-4fd6-82b7-cecc5c6a973f']);
  assert.equal(inv.status, 'connected');
  const p = (await s.handle('GET', '/proposals?status=pending')).data;
  assert.equal(p.length, 0, 'the transcript rejects the pending proposal');
  const animated = seen.filter((e) => e.type === 'audit' && e.data.animate).map((e) => e.data.edge_id);
  const g = (await s.handle('GET', '/graph')).data;
  for (const id of animated) assert.ok(g.edges.some((e) => e.id === id), `animated edge ${id} is in the graph`);
  const before = seen.length;
  t.advance(20000);
  const loop = seen.slice(before);
  assert.ok(loop.length > 0 && loop.every((e) => e.type === 'audit'), 'later passes replay traffic only');
  assert.notEqual(loop[0].data.record.request_id, seen.find((e) => e.type === 'audit').data.record.request_id);
  sub.close();
  assert.equal(statuses.at(-1), 'paused');
  s.stop();
});

test('fixture replay hides payloads from a token without them, and cp_audit from non-admins', async () => {
  const { s, t } = await server('payloads=0&role=editor', { replay: true });
  const seen = [];
  s.subscribe({ onEvent: (type, data) => seen.push({ type, data }), onStatus: () => {} });
  t.advance(16000);
  const audits = seen.filter((e) => e.type === 'audit');
  assert.ok(audits.length > 0 && audits.every((e) => e.data.record.input === null && e.data.record.output === null));
  assert.ok(!seen.some((e) => e.type === 'cp_audit'));
  s.stop();
});
