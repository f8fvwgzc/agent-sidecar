// Small helpers for the timeline: DOM builders, formatting and agent colours.
//
// Security (design §11): text only ever goes in through textContent; attributes are set one by
// one and inline event handler attributes are refused; styles are set through the CSSOM.

const SVG_NS = "http://www.w3.org/2000/svg";

function setAttrs(node, attrs) {
  for (const [name, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (/^on/i.test(name) || name === "style") {
      throw new Error(`timeline: attribute ${name} is not allowed`);
    }
    if (name === "text") {
      node.textContent = String(value);
    } else {
      node.setAttribute(name, value === true ? "" : String(value));
    }
  }
  return node;
}

function append(node, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

/** An HTML element. `attrs.text` sets textContent; string children become text nodes. */
export function el(tag, attrs = {}, ...children) {
  return append(setAttrs(document.createElement(tag), attrs), children);
}

/** An SVG element. */
export function svgEl(tag, attrs = {}, ...children) {
  return append(setAttrs(document.createElementNS(SVG_NS, tag), attrs), children);
}

// ---- icons (drawn, no fonts or images) -------------------------------------------------------

function icon(size, ...children) {
  return svgEl(
    "svg",
    { viewBox: "0 0 16 16", width: size, height: size, "aria-hidden": "true", focusable: "false", class: "tl-ico" },
    ...children,
  );
}

export const icons = {
  play: () => icon(16, svgEl("path", { d: "M5 3.2v9.6c0 .5.5.8.9.5l7.2-4.8a.6.6 0 0 0 0-1L5.9 2.7c-.4-.3-.9 0-.9.5z", fill: "currentColor" })),
  pause: () =>
    icon(
      16,
      svgEl("rect", { x: 4, y: 3, width: 2.6, height: 10, rx: 1, fill: "currentColor" }),
      svgEl("rect", { x: 9.4, y: 3, width: 2.6, height: 10, rx: 1, fill: "currentColor" }),
    ),
  restart: () =>
    icon(
      16,
      svgEl("path", {
        d: "M3.2 8a4.8 4.8 0 1 0 1.5-3.5",
        fill: "none",
        stroke: "currentColor",
        "stroke-width": 1.6,
        "stroke-linecap": "round",
      }),
      svgEl("path", { d: "M4.2 1.9v3h3", fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linecap": "round", "stroke-linejoin": "round" }),
    ),
  fit: () =>
    icon(
      14,
      svgEl("path", {
        d: "M2 5V2h3M11 2h3v3M14 11v3h-3M5 14H2v-3",
        fill: "none",
        stroke: "currentColor",
        "stroke-width": 1.5,
        "stroke-linecap": "round",
        "stroke-linejoin": "round",
      }),
    ),
  handoff: () =>
    icon(
      14,
      svgEl("path", { d: "M4 2.5v6.5a2 2 0 0 0 2 2h7", fill: "none", stroke: "currentColor", "stroke-width": 1.5, "stroke-linecap": "round" }),
      svgEl("path", { d: "M10.5 8.5 13 11l-2.5 2.5", fill: "none", stroke: "currentColor", "stroke-width": 1.5, "stroke-linecap": "round", "stroke-linejoin": "round" }),
    ),
  failed: () =>
    icon(
      14,
      svgEl("circle", { cx: 8, cy: 8, r: 6, fill: "none", stroke: "currentColor", "stroke-width": 1.5 }),
      svgEl("path", { d: "M5.9 5.9l4.2 4.2M10.1 5.9l-4.2 4.2", stroke: "currentColor", "stroke-width": 1.5, "stroke-linecap": "round" }),
    ),
};

/** Provider glyph for a lane label: a drawn spark for Claude models, a grey square for mock, a dot otherwise. */
export function providerGlyph(model) {
  if (typeof model === "string" && model.startsWith("claude-")) {
    const rays = [];
    for (let i = 0; i < 6; i += 1) {
      const a = (Math.PI / 6) * i * 2 + Math.PI / 12;
      const r = i % 2 === 0 ? 5.2 : 4.4;
      rays.push(`M6 6L${(6 + Math.cos(a) * r).toFixed(2)} ${(6 + Math.sin(a) * r).toFixed(2)}`);
      const b = a + Math.PI / 6;
      rays.push(`M6 6L${(6 + Math.cos(b) * 3.6).toFixed(2)} ${(6 + Math.sin(b) * 3.6).toFixed(2)}`);
    }
    return svgEl(
      "svg",
      { viewBox: "0 0 12 12", width: 12, height: 12, class: "tl-glyph tl-glyph-spark", "aria-hidden": "true", focusable: "false" },
      svgEl("path", { d: rays.join(""), stroke: "currentColor", "stroke-width": 1.4, "stroke-linecap": "round", fill: "none" }),
    );
  }
  if (model === "mock") {
    return svgEl(
      "svg",
      { viewBox: "0 0 12 12", width: 12, height: 12, class: "tl-glyph tl-glyph-mock", "aria-hidden": "true", focusable: "false" },
      svgEl("rect", { x: 2.5, y: 2.5, width: 7, height: 7, rx: 1.5, fill: "currentColor" }),
    );
  }
  return svgEl(
    "svg",
    { viewBox: "0 0 12 12", width: 12, height: 12, class: "tl-glyph tl-glyph-dot", "aria-hidden": "true", focusable: "false" },
    svgEl("circle", { cx: 6, cy: 6, r: 2.5, fill: "currentColor" }),
  );
}

// ---- formatting ------------------------------------------------------------------------------

/** "9.0s", "2m 5s"; with `precise`, a duration under 0.1 s in milliseconds ("1ms"). */
export function fmtSeconds(ms, precise = false) {
  const v = Math.max(0, ms || 0);
  if (precise && v < 100) return `${Math.round(v)}ms`;
  if (v < 60_000) return `${(v / 1000).toFixed(1)}s`;
  const total = Math.round(v / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h}h ${m}m` : `${m}m ${s}s`;
}

/** Precise duration for tooltips: ms below one second. */
export function fmtLatency(ms) {
  if (ms === null || ms === undefined) return "–";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

export function fmtInt(n) {
  return Math.round(n || 0).toLocaleString("en-US");
}

export function fmtCompact(n) {
  const v = Math.round(n || 0);
  if (v < 1000) return String(v);
  if (v < 1_000_000) return `${(v / 1000).toFixed(v < 10_000 ? 1 : 0).replace(/\.0$/, "")}k`;
  return `${(v / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
}

export function fmtCost(usd) {
  const v = usd || 0;
  if (v === 0) return "$0";
  if (v < 0.01) return `$${v.toFixed(4).replace(/0+$/, "")}`;
  return `$${v.toFixed(2)}`;
}

/** Axis tick label: seconds (minutes once the run is long), milliseconds for sub-0.1 s steps. */
export function fmtTick(sec, step) {
  if (sec >= 60 && step >= 1) {
    const m = Math.floor(sec / 60);
    const s = Math.round(sec - m * 60);
    return s === 0 ? `${m}m` : `${m}m${s}s`;
  }
  if (step < 0.1) {
    const msStep = step * 1000;
    const decimals = msStep >= 1 ? 0 : Math.min(3, Math.ceil(-Math.log10(msStep) - 1e-9));
    return `${Number((sec * 1000).toFixed(decimals))}ms`;
  }
  const decimals = step >= 1 ? 0 : Math.min(3, Math.ceil(-Math.log10(step) - 1e-9));
  return `${Number(sec.toFixed(decimals))}s`;
}

export const STATUS_LABEL = { running: "Running", ok: "Done", denied: "Denied", error: "Failed" };

export function statusLabel(status) {
  return STATUS_LABEL[status] || String(status || "Unknown");
}

/** Short agent name from a node id (`agent:<ns>/<svc>/<agent>`). */
export function agentName(nodeId) {
  if (typeof nodeId !== "string") return "unknown";
  const i = nodeId.lastIndexOf("/");
  return i >= 0 ? nodeId.slice(i + 1) : nodeId.replace(/^agent:/, "");
}

/** Display name of an agent for lane labels and tooltips: "stock-analyst" → "Stock analyst". */
export function displayName(nodeIdOrName) {
  const raw = agentName(nodeIdOrName).replace(/[-_]+/g, " ").trim();
  return raw ? raw.charAt(0).toUpperCase() + raw.slice(1) : "Unknown";
}

// ---- colours ---------------------------------------------------------------------------------

export const CARD_BG = "#161618";
export const ROOT_GREY = "#8e8e93";
export const FAIL_RED = "#e5484d";

// Fixed palette, indexed by hash of the node id (design §11.1). Order matters: it decides which
// colour an id gets. Red is kept out of it; it means "failed".
export const PALETTE = [
  "#5b8def", // blue
  "#36b3bd", // teal
  "#dc6ea7", // pink
  "#d6b04a", // yellow
  "#94c159", // lime
  "#ee8a3e", // orange
  "#44b97c", // green
  "#a073f0", // purple
];

export function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function hexToRgb(hex) {
  const v = parseInt(hex.slice(1), 16);
  return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
}

/** Mix colour `a` over `b` with weight `t` (0..1), as a hex string. */
export function mix(a, b, t) {
  const ca = hexToRgb(a);
  const cb = hexToRgb(b);
  const out = ca.map((c, i) => Math.round(c * t + cb[i] * (1 - t)));
  return `#${out.map((c) => c.toString(16).padStart(2, "0")).join("")}`;
}

function shades(base) {
  return {
    base,
    think: mix(base, CARD_BG, 0.3),
    thinkStroke: mix(base, CARD_BG, 0.42),
    tool: mix(base, "#ffffff", 0.94),
    stripe: mix(base, CARD_BG, 0.4),
    waitStroke: mix(base, CARD_BG, 0.55),
    track: mix(base, CARD_BG, 0.055),
  };
}

/**
 * A stable colour per lane (design §11.1): the root orchestrator is neutral grey, every other
 * agent gets the palette entry its node id hashes to, the same in every run. Two agents of one run
 * can share a colour when their ids hash to the same entry.
 */
export function colorFor(id) {
  const idx = fnv1a(String(id)) % PALETTE.length;
  return { index: idx, ...shades(PALETTE[idx]) };
}

const ROOT_SHADES = { index: -1, ...shades(ROOT_GREY), think: "#38383d", thinkStroke: "#45454b", tool: "#a9a9af", stripe: "#4a4a50", waitStroke: "#5c5c63" };

export function assignColors(laneIds, rootId) {
  const out = new Map();
  for (const id of laneIds) out.set(id, id === rootId ? ROOT_SHADES : colorFor(id));
  return out;
}

export function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, v));
}
