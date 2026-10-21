// Unit tests for the console's pure modules. Run with `node --test ui/tests/*.test.mjs`
// (Node 22.7+), or through `python3 -I ui/tests/check_ui.py`. Every input is written inline
// below: the console has no fixture data.

import { test } from 'node:test';
import assert from 'node:assert/strict';

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
import { G, nodeBox, portPoint, bezier, edgePath, frameRect, emptyFrameRect, rectsOverlap } from '../js/geometry.js';
import { autoLayout, resolvePositions, depths } from '../js/layout.js';
import { Api, ApiError, apiUrl, isUnreachable, parseEtag } from '../js/api.js';
import { viewPayload, normalizeView } from '../js/tab-config.js';
import { targetFor, tabsFor } from '../js/inspector.js';
import { learningTurnedOff } from '../js/tab-yaml.js';
import { loadPositions, savePositions, clearPositions, POSITIONS_KEY } from '../js/store.js';
import { ApiSource, createTimelineSource } from '../js/timeline/data.js';

const boxOf = (n) => nodeBox(n, { linkPort: true });

// ---- inline inputs -------------------------------------------------------------------------------
//
// A small graph in the GET /graph shape (design §10.1): service `front` (an app, the orchestrator
// `lead` and the agent `assist` that `lead` calls) calls service `back` (an app and `worker`).
// Both use one model provider; `lead` also reached an external origin through a tool it does not
// declare (an undeclared edge on a port the card does not have).

const NS = 'ns';
const svcId = (s) => `svc:${NS}/${s}`;
const appId = (s) => `app:${NS}/${s}`;
const agentId = (s, a) => `agent:${NS}/${s}/${a}`;
const MODEL = 'model:anthropic';
const ORIGIN = 'external:https://api.example.com';

function serviceNode(s, extra = {}) {
  return { id: svcId(s), type: 'service', label: s, namespace: NS, service: s, status: 'connected', instances: 1, charter_version: '1', ...extra };
}

function appNode(s) {
  return { id: appId(s), type: 'app', parent: svcId(s), label: `${s} app`, port: 8080, ports: { in: ['service'], out: ['invoke'] } };
}

function agentNode(s, a, tools = [], extra = {}) {
  return {
    id: agentId(s, a),
    type: 'agent',
    parent: svcId(s),
    label: a,
    agent_type: 'agent',
    model: 'model-a',
    skills: [],
    status: 'ok',
    ports: { in: ['invoke'], out: [...tools.map((t) => t.name), 'model'] },
    tools: tools.map((t) => ({ ...t, allowed: true })),
    learning: { enabled: false, mode: 'review', notes: 0, pending: 0 },
    ...extra,
  };
}

function edge(kind, source, sourcePort, target, targetPort, declared = true) {
  return { id: `edge:${kind}:${source}->${target}${kind === 'tool' ? `#${sourcePort}` : ''}`, kind, source, source_port: sourcePort, target, target_port: targetPort, declared };
}

function sampleGraph() {
  const leadTools = [
    { name: 'lookup', type: 'service', target: appId('front') },
    { name: 'ask_worker', type: 'agent', target: agentId('back', 'worker') },
    { name: 'ask_assist', type: 'agent', target: agentId('front', 'assist') },
  ];
  const lead = agentId('front', 'lead');
  const assist = agentId('front', 'assist');
  const worker = agentId('back', 'worker');
  return {
    version: '1',
    nodes: [
      serviceNode('front'),
      appNode('front'),
      agentNode('front', 'lead', leadTools, { agent_type: 'orchestrator' }),
      agentNode('front', 'assist'),
      serviceNode('back'),
      appNode('back'),
      agentNode('back', 'worker', [{ name: 'read', type: 'service', target: appId('back') }]),
      { id: MODEL, type: 'model_provider', label: 'Anthropic', ports: { in: ['model'], out: [] } },
      { id: ORIGIN, type: 'external', label: 'api.example.com', ports: { in: ['http'], out: [] } },
    ],
    edges: [
      edge('invoke', appId('front'), 'invoke', lead, 'invoke'),
      edge('invoke', appId('front'), 'invoke', assist, 'invoke'),
      edge('tool', lead, 'lookup', appId('front'), 'service'),
      edge('tool', lead, 'ask_worker', worker, 'invoke'),
      edge('tool', lead, 'ask_assist', assist, 'invoke'),
      edge('model', lead, 'model', MODEL, 'model'),
      edge('model', assist, 'model', MODEL, 'model'),
      edge('invoke', appId('back'), 'invoke', worker, 'invoke'),
      edge('tool', worker, 'read', appId('back'), 'service'),
      edge('model', worker, 'model', MODEL, 'model'),
      edge('tool', lead, 'call_out', ORIGIN, 'http', false),
    ],
  };
}

const nodeOf = (g, id) => g.nodes.find((n) => n.id === id);

/** An audit record as GET /events/recent returns it (only the fields the grouping reads). */
function record(request_id, ts, kind, decision = 'allow', extra = {}) {
  return { ts, kind, request_id, parent_span_id: null, decision, error: null, ...extra };
}

// ---- util ----------------------------------------------------------------------------------------

test('roles are ordered viewer < editor < admin and unknown roles are never enough', () => {
  assert.ok(roleAtLeast('admin', 'editor'));
  assert.ok(roleAtLeast('editor', 'editor'));
  assert.ok(!roleAtLeast('viewer', 'editor'));
  assert.ok(!roleAtLeast('root', 'viewer'));
  assert.ok(!roleAtLeast('admin', 'superuser'));
});

test('parseNodeId understands every node id form', () => {
  assert.deepEqual(parseNodeId('svc:ns-a/svc-a'), { kind: 'svc', ns: 'ns-a', svc: 'svc-a' });
  assert.deepEqual(parseNodeId('app:ns-a/svc-a'), { kind: 'app', ns: 'ns-a', svc: 'svc-a' });
  assert.deepEqual(parseNodeId('agent:ns-a/svc-a/agent-a'), { kind: 'agent', ns: 'ns-a', svc: 'svc-a', agent: 'agent-a' });
  assert.deepEqual(parseNodeId('model:anthropic'), { kind: 'model', provider: 'anthropic' });
  assert.deepEqual(parseNodeId('external:https://api.x.example:8443'), { kind: 'external', origin: 'https://api.x.example:8443' });
  assert.equal(parseNodeId('nope'), null);
  assert.equal(parseNodeId(42), null);
});

test('groupByRequest groups the recent events newest request first, records oldest first', () => {
  // Newest first, as GET /events/recent returns them.
  const recent = [
    record('req-c', '2026-01-01T00:00:30.000Z', 'agent_invocation', 'deny'),
    record('req-c', '2026-01-01T00:00:30.000Z', 'guardrail', 'deny'),
    record('req-b', '2026-01-01T00:00:20.000Z', 'agent_invocation'),
    record('req-b', '2026-01-01T00:00:19.000Z', 'model_call'),
    record('req-b', '2026-01-01T00:00:18.000Z', 'service_call', 'deny'),
    record('req-b', '2026-01-01T00:00:18.000Z', 'tool_call', 'deny'),
    record('req-b', '2026-01-01T00:00:17.000Z', 'http_call', 'deny'),
    record('req-b', '2026-01-01T00:00:16.000Z', 'model_call'),
    record('req-a', '2026-01-01T00:00:10.000Z', 'agent_invocation'),
    record('req-a', '2026-01-01T00:00:09.000Z', 'agent_invocation', 'allow', { parent_span_id: 'aaaaaaaaaaaaaaaa' }),
    record('req-a', '2026-01-01T00:00:08.000Z', 'model_call', 'allow', { error: 'timeout' }),
  ];
  const groups = groupByRequest(recent);
  assert.deepEqual(
    groups.map((g) => g.request_id),
    ['req-c', 'req-b', 'req-a'],
  );
  assert.equal(groups[0].outcome, 'deny');
  const b = groups[1];
  assert.equal(b.outcome, 'allow', 'the invocation itself was allowed');
  assert.equal(b.denied, 3);
  assert.equal(b.root.kind, 'agent_invocation');
  assert.equal(b.first, '2026-01-01T00:00:16.000Z');
  assert.equal(b.last, '2026-01-01T00:00:20.000Z');
  const a = groups[2];
  assert.equal(a.root.parent_span_id, null, 'the root is the invocation without a parent span');
  assert.equal(a.errors, 1);
  assert.equal(a.outcome, 'allow', 'a failed model call inside an allowed run');
  for (const g of groups) {
    const ts = g.records.map((r) => Date.parse(r.ts));
    assert.deepEqual(ts, [...ts].sort((x, y) => x - y));
  }
  assert.deepEqual(groupByRequest([null, 5, { ts: 'x' }]).map((g) => g.request_id), ['(none)']);
  assert.deepEqual(groupByRequest([]), []);
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
  const g = sampleGraph();
  assert.equal(visibleGraph(g, {}).nodes.length, g.nodes.length);
  const back = visibleGraph(g, { ns: NS, svc: 'back' });
  const ids = back.nodes.map((n) => n.id);
  assert.deepEqual(ids.sort(), [appId('back'), agentId('back', 'worker'), MODEL, svcId('back')].sort());
  assert.ok(!ids.includes(agentId('front', 'lead')), 'the calling agent of another service is filtered out');
  assert.ok(!ids.includes(ORIGIN), 'an origin only the other service reaches is filtered out');
  assert.ok(back.edges.length > 0);
  for (const e of back.edges) assert.ok(ids.includes(e.source) && ids.includes(e.target));
  const front = visibleGraph(g, { ns: NS, svc: 'front' }).nodes.map((n) => n.id);
  assert.ok(front.includes(ORIGIN) && front.includes(MODEL));
  assert.ok(!front.includes(agentId('back', 'worker')));
  assert.equal(visibleGraph(g, { ns: 'other' }).nodes.length, 0);
  assert.deepEqual(visibleGraph({ nodes: [], edges: [] }, { ns: NS }), { nodes: [], edges: [] });
});

test('link requirements: same service editor, cross service admin, cross namespace refused', () => {
  assert.equal(linkRequirement('agent:a/s/x', 'agent:a/s/y').level, 'editor');
  assert.equal(linkRequirement('agent:a/s/x', 'agent:a/t/y').level, 'admin');
  assert.equal(linkRequirement('agent:a/s/x', 'agent:b/s/y').level, 'refused');
  assert.equal(linkRequirement('agent:a/s/x', 'agent:a/s/x').level, 'refused');
  assert.equal(linkRequirement('app:a/s', 'agent:a/s/x').level, 'refused');
  assert.equal(suggestToolName('my-agent', []), 'my_agent');
  assert.equal(suggestToolName('my-agent', ['my_agent']), 'my_agent_2');
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
  const g = sampleGraph();
  const lead = nodeOf(g, agentId('front', 'lead'));
  const box = nodeBox(lead, { linkPort: true });
  assert.deepEqual(box.outPorts.map((p) => p.name), ['lookup', 'ask_worker', 'ask_assist', 'model']);
  assert.equal(box.inPorts[0].x, 0);
  assert.equal(box.outPorts[0].x, box.w);
  assert.ok(box.linkPort, 'orchestrators get the + port when linking is allowed');
  assert.equal(nodeBox(lead).linkPort, null);
  assert.equal(nodeBox(nodeOf(g, agentId('front', 'assist')), { linkPort: true }).linkPort, null, 'plain agents never do');
  const pos = { x: 100, y: 50 };
  const known = portPoint(box, pos, 'out', 'ask_worker');
  assert.ok(known.known);
  assert.equal(known.x, 100 + box.w);
  assert.ok(known.y > portPoint(box, pos, 'out', 'lookup').y, 'declaration order, top to bottom');
  const border = portPoint(box, pos, 'out', 'call_out');
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
  const g = sampleGraph();
  const pos = autoLayout(g, boxOf);
  const at = (id) => pos.get(id);
  const front = [appId('front'), agentId('front', 'lead'), agentId('front', 'assist')];
  const back = [appId('back'), agentId('back', 'worker')];
  const right = (ids) => Math.max(...ids.map((id) => at(id).x + boxOf(nodeOf(g, id)).w));
  // `back` sorts before `front` by name: only the call depth puts the caller first.
  assert.ok(right(front) < Math.min(...back.map((id) => at(id).x)), 'front (the caller) comes first');
  assert.ok(at(appId('front')).x < at(agentId('front', 'lead')).x);
  assert.ok(at(agentId('front', 'lead')).y < at(agentId('front', 'assist')).y, 'the caller sits above the agent it calls');
  assert.equal(at(agentId('front', 'lead')).x, at(agentId('front', 'assist')).x);
  for (const id of [MODEL, ORIGIN]) assert.ok(at(id).x > right(back));
  const rects = g.nodes.filter((n) => n.type !== 'service').map((n) => ({ ...at(n.id), w: boxOf(n).w, h: boxOf(n).h, id: n.id }));
  for (let i = 0; i < rects.length; i++) for (let j = i + 1; j < rects.length; j++) assert.ok(!rectsOverlap(rects[i], rects[j]), `${rects[i].id} overlaps ${rects[j].id}`);
  assert.equal(autoLayout({ nodes: [], edges: [] }, boxOf).size, 0, 'an empty graph has nothing to place');
});

test('resolvePositions keeps saved positions and puts a new agent below its hand-placed siblings', () => {
  const g = sampleGraph();
  const saved = new Map([
    [agentId('front', 'lead'), { x: 1000, y: 1000 }],
    [agentId('front', 'assist'), { x: 1000, y: 1400 }],
  ]);
  const g2 = clone(g);
  const assist = nodeOf(g, agentId('front', 'assist'));
  g2.nodes.push({ ...clone(assist), id: agentId('front', 'extra'), label: 'extra' });
  const pos = resolvePositions(g2, saved, boxOf);
  assert.deepEqual(pos.get(agentId('front', 'lead')), { x: 1000, y: 1000 });
  assert.deepEqual(pos.get(agentId('front', 'extra')), { x: 1000, y: 1400 + boxOf(assist).h + 40 });
});

/** Every card and frame of `g` at `pos`; a frame may only contain its own cards. */
function overlapsIn(g, pos) {
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const rects = [];
  const kids = new Map();
  for (const n of g.nodes) {
    if (n.type === 'service') continue;
    const p = pos.get(n.id);
    const r = { id: n.id, x: p.x, y: p.y, w: boxOf(n).w, h: boxOf(n).h };
    rects.push(r);
    if (n.parent) kids.set(n.parent, [...(kids.get(n.parent) || []), r]);
  }
  for (const n of g.nodes) {
    if (n.type !== 'service') continue;
    const k = kids.get(n.id);
    rects.push({ id: `frame ${n.id}`, frame: n.id, ...(k ? frameRect(k) : emptyFrameRect(pos.get(n.id))) });
  }
  const bad = [];
  for (let i = 0; i < rects.length; i++) {
    for (let j = i + 1; j < rects.length; j++) {
      const [a, b] = [rects[i], rects[j]];
      const own = (a.frame && byId.get(b.id)?.parent === a.frame) || (b.frame && byId.get(a.id)?.parent === b.frame);
      if (!own && rectsOverlap(a, b)) bad.push(`${a.id} / ${b.id}`);
    }
  }
  return bad;
}

test('resolvePositions: nothing saved is exactly the auto-layout', () => {
  const g = sampleGraph();
  assert.deepEqual([...resolvePositions(g, new Map(), boxOf)], [...autoLayout(g, boxOf)]);
});

test('resolvePositions: services, providers and origins that appear later do not cover placed cards', () => {
  const g = sampleGraph();
  const before = resolvePositions(g, new Map(), boxOf);
  const g2 = clone(g);
  // Sorts first among the services and the externals, so its auto-layout slot is taken.
  g2.nodes.push(
    serviceNode('aaa'),
    { ...appNode('aaa'), ports: { in: [], out: ['invoke'] } },
    agentNode('aaa', 'bot'),
    serviceNode('idle', { status: 'no_charter', charter_version: null }),
    { id: 'external:https://aaa.example', type: 'external', label: 'aaa.example', ports: { in: ['http'], out: [] } },
    { id: 'model:mock', type: 'model_provider', label: 'Mock', ports: { in: ['model'], out: [] } },
  );
  const pos = resolvePositions(g2, before, boxOf);
  for (const [id, p] of before) assert.deepEqual(pos.get(id), p, `${id} stays where it was`);
  assert.deepEqual(overlapsIn(g2, pos), []);
  const column = before.get(ORIGIN).x;
  for (const id of ['external:https://aaa.example', 'model:mock']) {
    assert.equal(pos.get(id).x, column, `${id} joins the final column`);
    assert.ok(pos.get(id).y > before.get(ORIGIN).y, `${id} goes below it`);
  }
  assert.ok(pos.get(appId('aaa')).x < column, 'a new service stays left of the final column');

  // The same with hand-placed cards: the user stacked everything in one column.
  const stacked = new Map();
  let y = 0;
  for (const id of before.keys()) {
    const n = nodeOf(g, id);
    stacked.set(id, { x: 0, y });
    y += boxOf(n).h + 120;
  }
  const pos2 = resolvePositions(g2, stacked, boxOf);
  assert.deepEqual(overlapsIn(g2, pos2), []);

  // A service whose frame was empty keeps the frame's place when its first agent arrives: here
  // the empty frame was dragged to free space right of everything, away from its auto slot.
  const g3 = clone(g2);
  g3.nodes.push(agentNode('idle', 'first'));
  const moved = new Map(pos);
  const dropped = { x: column + 800, y: 0 };
  moved.set(svcId('idle'), dropped);
  const pos3 = resolvePositions(g3, moved, boxOf);
  const frame = frameRect([{ ...pos3.get(agentId('idle', 'first')), ...boxOf(g3.nodes.at(-1)) }]);
  assert.deepEqual({ x: frame.x, y: frame.y }, dropped);
  assert.deepEqual(overlapsIn(g3, pos3), []);
  // Where the grown frame would cover cards it moves instead, still without overlaps.
  assert.deepEqual(overlapsIn(g3, resolvePositions(g3, pos, boxOf)), []);
});

test('resolvePositions: a new card next to hand-placed cards of the other kind keeps its offset', () => {
  const g = sampleGraph();
  const auto = autoLayout(g, boxOf);
  const worker = agentId('back', 'worker');
  const saved = new Map([...auto].filter(([id]) => id !== worker));
  saved.set(appId('back'), { x: auto.get(appId('back')).x + 500, y: 900 });
  const pos = resolvePositions(g, saved, boxOf);
  const app = pos.get(appId('back'));
  const agent = pos.get(worker);
  const a = auto.get(appId('back'));
  const b = auto.get(worker);
  assert.deepEqual({ dx: agent.x - app.x, dy: agent.y - app.y }, { dx: b.x - a.x, dy: b.y - a.y });
  assert.deepEqual(overlapsIn(g, pos), []);
});

test('learningTurnedOff names the agents a charter change takes learning away from', () => {
  const before = { agents: [{ name: 'a', learning: { enabled: true } }, { name: 'b', learning: { enabled: true } }, { name: 'c' }, { name: 'gone', learning: { enabled: true } }] };
  const after = { agents: [{ name: 'a', learning: { enabled: true, mode: 'auto' } }, { name: 'b', learning: { enabled: false } }, { name: 'c', learning: { enabled: true } }] };
  assert.deepEqual(learningTurnedOff(before, after), ['b']);
  assert.deepEqual(learningTurnedOff(null, after), []);
  assert.deepEqual(learningTurnedOff(before, { agents: [{ name: 'a' }] }), ['a']);
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
    { now: () => 0, subscribe: () => null },
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

test('no control plane: network errors, 404s, proxy errors and non-API replies are "unreachable"', async () => {
  for (const status of [404, 405, 502, 503]) {
    const api = new Api(async () => ({ status, data: null }), { now: () => 0 });
    await assert.rejects(api.whoami(), (e) => isUnreachable(e), `HTTP ${status}`);
  }
  assert.ok(isUnreachable(new ApiError(0, { error: 'network', details: ['Failed to fetch'] })));
  assert.ok(isUnreachable(new ApiError(200, { error: 'not_the_api' })));
  assert.ok(isUnreachable(null));
  for (const status of [400, 401, 403, 409, 429]) assert.ok(!isUnreachable(new ApiError(status, null)), `HTTP ${status} came from the API`);
  assert.equal(new Api(async () => ({}), {}).baseUrl, 'api/v1');
  globalThis.location = { href: 'http://127.0.0.1:7070/console/index.html#timeline' };
  try {
    assert.equal(apiUrl(), 'http://127.0.0.1:7070/console/api/v1');
    assert.equal(apiUrl('/api/v1'), 'http://127.0.0.1:7070/api/v1');
  } finally {
    delete globalThis.location;
  }
  assert.equal(apiUrl(), 'api/v1', 'without a page the relative base is kept');
});

// ---- timeline source -------------------------------------------------------------------------------------

/** A fetch stand-in: `routes` maps a path to {status, type, body} or an Error to throw. */
function stubFetch(routes) {
  const seen = [];
  const fn = async (url, init) => {
    seen.push({ url, init });
    const r = routes[url];
    if (!r || r instanceof Error) throw r || new TypeError('Failed to fetch');
    return {
      status: r.status,
      ok: r.status >= 200 && r.status < 300,
      headers: { get: (k) => (k.toLowerCase() === 'content-type' ? r.type ?? 'application/json' : null) },
      json: async () => (typeof r.body === 'string' ? JSON.parse(r.body) : r.body),
    };
  };
  return { fn, seen };
}

test('the timeline reads runs from the control plane: GET /traces and /traces/{id}', async () => {
  const run = { trace_id: '0'.repeat(32), title: null, root_agent: agentId('front', 'lead'), status: 'running' };
  const { fn, seen } = stubFetch({
    '/api/v1/traces?limit=50&namespace=ns': { status: 200, body: [run] },
    [`/api/v1/traces/${run.trace_id}`]: { status: 200, body: { trace_id: run.trace_id, spans: [] } },
    '/api/v1/traces?limit=50': { status: 200, body: [] },
  });
  const src = new ApiSource({ fetchImpl: fn });
  assert.deepEqual(await src.listTraces({ namespace: 'ns' }), [run]);
  assert.deepEqual(await src.getTrace(run.trace_id), { trace_id: run.trace_id, spans: [] });
  assert.deepEqual(await src.listTraces(), [], 'no runs is an empty list, not an error');
  assert.equal(seen[0].init.credentials, 'same-origin');
  assert.equal(createTimelineSource(undefined).base, '/api/v1');
  assert.equal(createTimelineSource({ baseUrl: 'api/v1/' }).base, 'api/v1');
  const own = { listTraces: async () => [], getTrace: async () => ({}) };
  assert.equal(createTimelineSource(own), own, "the console's own source is used as it is");
});

test('the timeline says when no control plane answers, and when a run is gone', async () => {
  const unreachable = /^Cannot reach the control plane at \S*api\/v1 — start embassy serve\.$/;
  const cases = [
    { route: new TypeError('Failed to fetch'), why: 'network error' },
    { route: { status: 404, type: 'text/html', body: '' }, why: 'a static server' },
    { route: { status: 502, type: 'text/plain', body: '' }, why: 'a proxy error' },
    { route: { status: 200, type: 'text/html', body: '' }, why: 'a page that is not the API' },
    { route: { status: 200, body: { nodes: [] } }, why: 'JSON that is not a run list' },
  ];
  for (const { route, why } of cases) {
    const src = new ApiSource({ fetchImpl: stubFetch({ '/api/v1/traces?limit=50': route }).fn });
    await assert.rejects(src.listTraces(), (e) => unreachable.test(e.message), why);
  }
  const signin = new ApiSource({ fetchImpl: stubFetch({ '/api/v1/traces?limit=50': { status: 401, body: { error: 'unauthenticated' } } }).fn });
  await assert.rejects(signin.listTraces(), (e) => e.status === 401 && e.message === 'Sign in to see runs.');
  const gone = new ApiSource({ fetchImpl: stubFetch({ '/api/v1/traces/abc': { status: 404, body: { error: 'not_found' } } }).fn });
  await assert.rejects(gone.getTrace('abc'), (e) => e.status === 404 && e.message === 'This run is no longer available.');
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
  const g = sampleGraph();
  const t = targetFor(nodeOf(g, agentId('front', 'lead')));
  assert.deepEqual(t, { kind: 'agent', id: agentId('front', 'lead'), ns: NS, svc: 'front', agent: 'lead' });
  assert.deepEqual(tabsFor(t, true), ['config', 'traffic', 'learning', 'yaml', 'instances']);
  assert.deepEqual(targetFor(nodeOf(g, svcId('back'))), { kind: 'service', id: svcId('back'), ns: NS, svc: 'back' });
  assert.deepEqual(tabsFor({ kind: 'service' }, false), ['overview', 'instances']);
  assert.deepEqual(tabsFor(targetFor(nodeOf(g, appId('back'))), true), ['overview', 'traffic', 'yaml', 'instances']);
  assert.deepEqual(tabsFor(targetFor(nodeOf(g, MODEL)), false), ['overview']);
  assert.equal(targetFor({ id: 'agent:a/b/c', type: 'agent', placeholder: true }).kind, 'node');
});
