// Node card geometry, port positions and edge curves. Pure: the canvas (graph.js), the
// auto-layout (layout.js) and the node tests share it, so a port is drawn exactly where its
// edges end.

export const G = Object.freeze({
  header: 32, // title bar
  row: 22, // one port or widget row
  pad: 8,
  portR: 5,
  framePad: 24, // a service frame is the bounding box of its children + 24 px
  frameTitle: 26, // plus room for its title above the children
});

const WIDTH = Object.freeze({
  agent: 268,
  app: 212,
  model_provider: 196,
  external: 236,
  placeholder: 212,
  service: 240,
});

const WIDGET_ROWS = Object.freeze({
  agent: 4, // model, skills, learning, stats
  app: 2, // port, stats
  model_provider: 1,
  external: 1,
  placeholder: 1,
  service: 1,
});

/** The card type a node is drawn as. */
export function cardType(node) {
  if (node && node.placeholder) return 'placeholder';
  return node && WIDTH[node.type] ? node.type : 'placeholder';
}

/**
 * The box of one node card at the origin: width, height, and its ports (`x`/`y` relative to
 * the card's top-left). `opts.linkPort` adds the "+" drag-to-link port of orchestrators.
 */
export function nodeBox(node, opts = {}) {
  const type = cardType(node);
  const w = WIDTH[type];
  const ins = Array.isArray(node?.ports?.in) ? node.ports.in : [];
  const outs = Array.isArray(node?.ports?.out) ? node.ports.out : [];
  const link = !!opts.linkPort && type === 'agent' && node.agent_type === 'orchestrator';
  const portRows = Math.max(ins.length, outs.length + (link ? 1 : 0), 1);
  const portsTop = G.header + G.pad / 2;
  const widgetsTop = portsTop + portRows * G.row + 8;
  const widgetRows = WIDGET_ROWS[type];
  const h = widgetsTop + widgetRows * G.row + G.pad;
  const rowY = (i) => portsTop + i * G.row + G.row / 2;
  return {
    type,
    w,
    h,
    portsTop,
    widgetsTop,
    widgetRows,
    inPorts: ins.map((name, i) => ({ name, x: 0, y: rowY(i) })),
    outPorts: outs.map((name, i) => ({ name, x: w, y: rowY(i) })),
    linkPort: link ? { x: w, y: rowY(outs.length) } : null,
  };
}

/**
 * The canvas point of a port. A port the node does not declare (an undeclared edge naming a
 * tool the node no longer has) agentscs to the node's border instead.
 */
export function portPoint(box, pos, side, name) {
  const list = side === 'in' ? box.inPorts : box.outPorts;
  const p = list.find((q) => q.name === name);
  if (p) return { x: pos.x + p.x, y: pos.y + p.y, known: true };
  if (side === 'in') return { x: pos.x, y: pos.y + G.header / 2, known: false };
  return { x: pos.x + box.w, y: pos.y + box.h - 14, known: false };
}

/** A horizontal cubic Bézier from an output port to an input port. */
export function bezier(s, t) {
  const dx = Math.max(60, Math.min(260, Math.abs(t.x - s.x) * 0.5));
  const f = (n) => Math.round(n * 10) / 10;
  return `M${f(s.x)},${f(s.y)} C${f(s.x + dx)},${f(s.y)} ${f(t.x - dx)},${f(t.y)} ${f(t.x)},${f(t.y)}`;
}

/**
 * The path of an edge between two cards. Forward edges (target to the right) are one cubic
 * Bézier; backward edges (target left of or under the source port) leave to the right, run
 * through the gap between the cards (or below both when they sit side by side) and enter the
 * target port from the left, so they never cut through a card.
 */
export function edgePath(s, t, sr, tr) {
  if (!sr || !tr || t.x >= s.x + 40) return bezier(s, t);
  const f = (n) => Math.round(n * 10) / 10;
  const k = 36;
  let ym;
  if (tr.y >= sr.y + sr.h + 12) ym = (sr.y + sr.h + tr.y) / 2;
  else if (sr.y >= tr.y + tr.h + 12) ym = (tr.y + tr.h + sr.y) / 2;
  else ym = Math.max(sr.y + sr.h, tr.y + tr.h) + 26;
  const r = Math.min(k, Math.abs(ym - s.y) / 2, Math.abs(ym - t.y) / 2);
  const dirS = ym >= s.y ? 1 : -1;
  const dirT = t.y >= ym ? 1 : -1;
  const xs = s.x + k;
  const xt = t.x - k;
  return [
    `M${f(s.x)},${f(s.y)}`,
    `L${f(xs - r)},${f(s.y)}`,
    `Q${f(xs)},${f(s.y)} ${f(xs)},${f(s.y + dirS * r)}`,
    `L${f(xs)},${f(ym - dirS * r)}`,
    `Q${f(xs)},${f(ym)} ${f(xs - r)},${f(ym)}`,
    `L${f(xt + r)},${f(ym)}`,
    `Q${f(xt)},${f(ym)} ${f(xt)},${f(ym + dirT * r)}`,
    `L${f(xt)},${f(t.y - dirT * r)}`,
    `Q${f(xt)},${f(t.y)} ${f(xt + r)},${f(t.y)}`,
    `L${f(t.x)},${f(t.y)}`,
  ].join(' ');
}

/** Bounding box of rectangles, grown by the frame padding (and the title room on top). */
export function frameRect(rects) {
  if (!rects.length) return null;
  const x0 = Math.min(...rects.map((r) => r.x));
  const y0 = Math.min(...rects.map((r) => r.y));
  const x1 = Math.max(...rects.map((r) => r.x + r.w));
  const y1 = Math.max(...rects.map((r) => r.y + r.h));
  return {
    x: x0 - G.framePad,
    y: y0 - G.framePad - G.frameTitle,
    w: x1 - x0 + 2 * G.framePad,
    h: y1 - y0 + 2 * G.framePad + G.frameTitle,
  };
}

/** The frame of a service without children: a fixed-size box at its own position. */
export function emptyFrameRect(pos) {
  return { x: pos.x, y: pos.y, w: WIDTH.service, h: G.frameTitle + 2 * G.framePad + G.row };
}

export function rectsOverlap(a, b) {
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

export function rectContains(r, p, margin = 0) {
  return p.x >= r.x - margin && p.x <= r.x + r.w + margin && p.y >= r.y - margin && p.y <= r.y + r.h + margin;
}
