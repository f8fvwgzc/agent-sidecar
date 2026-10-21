// Auto-layout (design §11): one column per service, ordered by the topological depth of
// cross-service agent calls; inside a frame the app on the left and the agents stacked to its
// right by local agent-call depth (callers above the agents they call); model providers,
// external origins and loose nodes in a final column. Pure, so the node tests can check it.

import { G } from './geometry.js';

export const LAYOUT = Object.freeze({
  colGap: 120, // between service frames
  subColGap: 80, // between the app and the agent stack inside a frame
  rowGap: 40, // between stacked cards (backward edges run through this gap)
  finalGap: 32,
});

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Longest-path depth of every id over the directed edges [[from, to], ...]. Cycles do not
 * hang it: when only cycles are left, the node with the fewest open in-edges is released.
 */
export function depths(ids, edges) {
  const set = new Set(ids);
  const indeg = new Map(ids.map((i) => [i, 0]));
  const out = new Map(ids.map((i) => [i, []]));
  const seen = new Set();
  for (const [a, b] of edges) {
    if (!set.has(a) || !set.has(b) || a === b) continue;
    const k = `${a}\n${b}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.get(a).push(b);
    indeg.set(b, indeg.get(b) + 1);
  }
  const depth = new Map(ids.map((i) => [i, 0]));
  const done = new Set();
  const queue = ids.filter((i) => indeg.get(i) === 0);
  while (done.size < ids.length) {
    if (!queue.length) {
      const rest = ids.filter((i) => !done.has(i)).sort((a, b) => indeg.get(a) - indeg.get(b));
      indeg.set(rest[0], 0);
      queue.push(rest[0]);
    }
    const n = queue.shift();
    if (done.has(n)) continue;
    done.add(n);
    for (const m of out.get(n)) {
      if (done.has(m)) continue;
      depth.set(m, Math.max(depth.get(m), depth.get(n) + 1));
      indeg.set(m, indeg.get(m) - 1);
      if (indeg.get(m) === 0) queue.push(m);
    }
  }
  return depth;
}

function nsOf(node) {
  const m = /^svc:([^/]+)\//.exec(node.id);
  return m ? m[1] : '';
}

function looseRank(n) {
  if (n.type === 'model_provider') return 0;
  if (n.type === 'external') return 1;
  return 2;
}

/**
 * Positions (top-left corners) for every card, plus every service without children (its
 * empty frame). `boxOf(node)` gives the card size (geometry.nodeBox).
 */
export function autoLayout(graph, boxOf) {
  const nodes = (graph && graph.nodes) || [];
  const edges = (graph && graph.edges) || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const services = nodes.filter((n) => n.type === 'service');
  const children = new Map(services.map((s) => [s.id, []]));
  const loose = [];
  for (const n of nodes) {
    if (n.type === 'service') continue;
    if (n.parent && children.has(n.parent)) children.get(n.parent).push(n);
    else loose.push(n);
  }

  const svcEdges = [];
  const localEdges = [];
  for (const e of edges) {
    const s = byId.get(e.source);
    const t = byId.get(e.target);
    if (!s || !t || s.type !== 'agent' || t.type !== 'agent') continue;
    if (!children.has(s.parent) || !children.has(t.parent)) continue;
    if (s.parent === t.parent) localEdges.push([s.id, t.id]);
    else svcEdges.push([s.parent, t.parent]);
  }
  const svcDepth = depths(
    services.map((s) => s.id),
    svcEdges,
  );
  const ordered = [...services].sort(
    (a, b) =>
      svcDepth.get(a.id) - svcDepth.get(b.id) ||
      cmp(nsOf(a), nsOf(b)) ||
      cmp(a.label || '', b.label || '') ||
      cmp(a.id, b.id),
  );

  const pos = new Map();
  const top = G.frameTitle + G.framePad; // the first card's y in a frame whose top is 0
  let x = 0;
  let maxBottom = top;
  for (const s of ordered) {
    const kids = children.get(s.id);
    if (!kids.length) {
      pos.set(s.id, { x, y: 0 });
      x += 240 + LAYOUT.colGap;
      continue;
    }
    const apps = kids.filter((k) => k.type === 'app');
    const agents = kids.filter((k) => k.type !== 'app');
    const ids = agents.map((a) => a.id);
    const idSet = new Set(ids);
    const local = depths(
      ids,
      localEdges.filter(([a, b]) => idSet.has(a) && idSet.has(b)),
    );
    // Callers above the agents they call: local call depth, then orchestrators first.
    agents.sort(
      (a, b) =>
        local.get(a.id) - local.get(b.id) ||
        (b.agent_type === 'orchestrator') - (a.agent_type === 'orchestrator') ||
        cmp(a.label || '', b.label || '') ||
        cmp(a.id, b.id),
    );
    apps.sort((a, b) => cmp(a.label || '', b.label || '') || cmp(a.id, b.id));
    let cx = x + G.framePad;
    let any = false;
    for (const col of [apps, agents]) {
      if (!col.length) continue;
      let cy = top;
      let cw = 0;
      for (const n of col) {
        const b = boxOf(n);
        pos.set(n.id, { x: cx, y: cy });
        cy += b.h + LAYOUT.rowGap;
        cw = Math.max(cw, b.w);
      }
      maxBottom = Math.max(maxBottom, cy - LAYOUT.rowGap);
      cx += cw + LAYOUT.subColGap;
      any = true;
    }
    const right = any ? cx - LAYOUT.subColGap + G.framePad : x + 240;
    x = right + LAYOUT.colGap;
  }

  loose.sort((a, b) => looseRank(a) - looseRank(b) || cmp(a.label || '', b.label || '') || cmp(a.id, b.id));
  const total = loose.reduce((acc, n, i) => acc + boxOf(n).h + (i ? LAYOUT.finalGap : 0), 0);
  let y = Math.max(top, Math.round(top + (maxBottom - top - total) / 2));
  for (const n of loose) {
    pos.set(n.id, { x, y });
    y += boxOf(n).h + LAYOUT.finalGap;
  }
  return pos;
}

/**
 * Saved positions win; a new card inside a frame whose other cards of the same kind (app or
 * agent) were placed before goes below the lowest of them, so it does not land on top of the
 * existing arrangement.
 */
export function resolvePositions(graph, saved, boxOf) {
  const auto = autoLayout(graph, boxOf);
  const nodes = (graph && graph.nodes) || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const out = new Map();
  for (const id of auto.keys()) {
    const s = saved.get(id);
    if (s) out.set(id, { x: s.x, y: s.y });
  }
  for (const [id, p] of auto) {
    if (out.has(id)) continue;
    const n = byId.get(id);
    // Placed cards of the same kind (app or agent) in the same frame.
    const same = n && n.parent ? nodes.filter((m) => m.parent === n.parent && m.id !== id && out.has(m.id) && (m.type === 'app') === (n.type === 'app')) : [];
    if (same.some((m) => saved.has(m.id))) {
      const x = Math.min(...same.map((m) => out.get(m.id).x));
      const y = Math.max(...same.map((m) => out.get(m.id).y + boxOf(m).h)) + LAYOUT.rowGap;
      out.set(id, { x, y });
    } else {
      out.set(id, { x: p.x, y: p.y });
    }
  }
  return out;
}
