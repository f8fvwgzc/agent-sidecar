// Auto-layout (design §11): one column per service, ordered by the topological depth of
// cross-service agent calls; inside a frame the app on the left and the agents stacked to its
// right by local agent-call depth (callers above the agents they call); model providers,
// external origins and loose nodes in a final column. Pure, so the node tests can check it.

import { G, frameRect, emptyFrameRect, rectsOverlap } from './geometry.js';

export const LAYOUT = Object.freeze({
  colGap: 120, // between service frames
  subColGap: 80, // between the app and the agent stack inside a frame
  rowGap: 40, // between stacked cards (backward edges run through this gap)
  finalGap: 32,
  frameRowGap: 64, // above a new service frame placed under the existing ones
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

const SPACE = 16; // free room kept around a card or frame placed next to existing ones

function grow(r, m) {
  return { x: r.x - m, y: r.y - m, w: r.w + 2 * m, h: r.h + 2 * m };
}

function shift(positions, dx, dy) {
  for (const p of positions.values()) {
    p.x += dx;
    p.y += dy;
  }
}

/**
 * Moves `rect` (and `positions`, its cards) down until it keeps SPACE from every obstacle.
 * Each step lands below the obstacle it hit, so it ends after at most one step per obstacle.
 */
function settle(rect, positions, obstacles) {
  for (let i = 0; i <= obstacles.length; i++) {
    const g = grow(rect, SPACE);
    const hit = obstacles.find((o) => rectsOverlap(g, o));
    if (!hit) return;
    const dy = hit.y + hit.h + SPACE - rect.y;
    rect.y += dy;
    shift(positions, 0, dy);
  }
}

/**
 * Positions for the graph given the ones the viewer already has (`saved`: the last persisted
 * or currently drawn positions). Saved positions win. Everything else lands where it does not
 * cover what is already on the canvas:
 * - a new card in a frame with placed cards of the same kind (app or agent) goes below the
 *   lowest of them; with only cards of the other kind placed, it keeps its auto-layout offset
 *   from them; either way it then moves down past any card or other frame it would cover;
 * - a new model provider, external origin or loose placeholder joins the final column below
 *   its lowest card (its auto-layout slot, or right of everything, when the column is empty);
 * - a new frame (a new service, or one whose cards are all new) takes its auto-layout slot
 *   when that is free, else it starts a row under the existing frames;
 * - and each then moves down past anything it would still cover.
 * With nothing saved this is exactly autoLayout.
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
  if (out.size === auto.size) return out;

  const kids = new Map(nodes.filter((n) => n.type === 'service').map((s) => [s.id, []]));
  const loose = [];
  for (const id of auto.keys()) {
    const n = byId.get(id);
    if (n.type === 'service') continue;
    if (n.parent && kids.has(n.parent)) kids.get(n.parent).push(id);
    else loose.push(id);
  }
  const rectOf = (id, p = out.get(id)) => {
    const b = boxOf(byId.get(id));
    return { x: p.x, y: p.y, w: b.w, h: b.h };
  };
  const frameOf = (sid) => {
    const placed = kids.get(sid).filter((id) => out.has(id));
    if (placed.length) return frameRect(placed.map((id) => rectOf(id)));
    return !kids.get(sid).length && out.has(sid) ? emptyFrameRect(out.get(sid)) : null;
  };
  /** Every placed card, and the frame of every service with placed cards except `skip`. */
  const obstacles = (skip) => {
    const list = [];
    for (const [id] of out) if (byId.get(id).type !== 'service') list.push(rectOf(id));
    for (const sid of kids.keys()) {
      if (sid === skip) continue;
      const f = frameOf(sid);
      if (f) list.push(f);
    }
    return list;
  };

  // 1. New cards in frames that already have placed cards, in auto-layout order.
  for (const [sid, list] of kids) {
    if (!list.some((id) => out.has(id))) continue;
    for (const id of list) {
      if (out.has(id)) continue;
      const n = byId.get(id);
      const isApp = n.type === 'app';
      const same = list.filter((m) => m !== id && out.has(m) && (byId.get(m).type === 'app') === isApp);
      let p;
      if (same.length) {
        p = {
          x: Math.min(...same.map((m) => out.get(m).x)),
          y: Math.max(...same.map((m) => out.get(m).y + boxOf(byId.get(m)).h)) + LAYOUT.rowGap,
        };
      } else {
        const anchor = list.find((m) => out.has(m));
        const a = out.get(anchor);
        const aa = auto.get(anchor);
        const own = auto.get(id);
        p = { x: own.x + a.x - aa.x, y: own.y + a.y - aa.y };
      }
      const r = rectOf(id, p);
      settle(r, new Map([[id, p]]), obstacles(sid));
      out.set(id, p);
    }
  }

  // 2. New frames and new loose cards, as units in auto-layout order.
  const units = [];
  for (const [sid, list] of kids) {
    if (list.length && list.some((id) => out.has(id))) continue;
    if (!list.length && out.has(sid)) continue;
    const ids = list.length ? list : [sid];
    const positions = new Map(ids.map((id) => [id, { ...auto.get(id) }]));
    const rect = list.length ? frameRect(ids.map((id) => rectOf(id, positions.get(id)))) : emptyFrameRect(positions.get(sid));
    // A service that had an empty frame keeps that frame's place when its first cards arrive.
    const was = list.length ? saved.get(sid) : null;
    if (was) {
      shift(positions, was.x - rect.x, was.y - rect.y);
      rect.x = was.x;
      rect.y = was.y;
    }
    units.push({ frame: true, positions, rect });
  }
  for (const id of loose) {
    if (out.has(id)) continue;
    const p = { ...auto.get(id) };
    units.push({ frame: false, positions: new Map([[id, p]]), rect: rectOf(id, p) });
  }
  units.sort((a, b) => a.rect.x - b.rect.x || a.rect.y - b.rect.y);
  for (const u of units) {
    const obs = obstacles(null);
    const placedLoose = loose.filter((id) => out.has(id)).map((id) => rectOf(id));
    const frames = [...kids.keys()].map(frameOf).filter(Boolean);
    const free = !obs.some((o) => rectsOverlap(grow(u.rect, SPACE), o));
    let to = null;
    if (!u.frame && placedLoose.length) {
      // The final column: below its lowest card, whatever the auto-layout slot.
      const low = placedLoose.reduce((a, b) => (b.y + b.h > a.y + a.h ? b : a));
      to = { x: low.x, y: low.y + low.h + LAYOUT.finalGap };
    } else if (free) {
      to = null;
    } else if (u.frame && frames.length) {
      // A new row under the frames, so the final column stays on the right.
      to = { x: Math.min(...frames.map((f) => f.x)), y: Math.max(...frames.map((f) => f.y + f.h)) + LAYOUT.frameRowGap };
    } else {
      to = { x: Math.max(...obs.map((o) => o.x + o.w)) + LAYOUT.colGap, y: u.rect.y };
    }
    if (to) {
      shift(u.positions, to.x - u.rect.x, to.y - u.rect.y);
      u.rect.x = to.x;
      u.rect.y = to.y;
      settle(u.rect, u.positions, obs);
    }
    for (const [id, p] of u.positions) out.set(id, p);
  }
  return out;
}
