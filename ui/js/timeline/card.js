// The run card (design §11.1): header, lane labels, the SVG plot with segments, handoffs and the
// playhead, the time axis, and the player footer. Rendering is driven by the controller on
// requestAnimationFrame; this module only draws and reports interactions through callbacks.

import { openThinking } from "./model.js";
import { CARD_BG, FAIL_RED, clamp, displayName, el, fmtCost, fmtInt, fmtLatency, fmtTick, icons, providerGlyph, svgEl } from "./util.js";

export const LANE_H = 60;
const BLOCK_H = 28;
const ROW_GAP = 2;
const PAD_L = 12;
const PAD_R = 20;
const AXIS_H = 36;
const AXIS_Y = 9;
const INSET = 1.25;
const MIN_W = 3;
const FADE_PX = 46;
const VIRTUAL_LANES = 30;
const VISIBLE_LANES_WHEN_VIRTUAL = 12;
const LANE_OVERSCAN = 3;
// A failed block narrower than this has no room for its ⊗ inside; it gets a marker above the band.
const FAIL_ICON_MIN_W = 15;
const BAND_TOP = (LANE_H - BLOCK_H) / 2;
const NAV_KEYS = new Set(["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End", "Enter", "Escape", "+", "=", "-", "_", "0"]);

let uidCounter = 0;

const TYPE_LABEL = { thinking: "Thinking", tool: "Tool call", waiting: "Waiting", invocation: "Invocation" };

function d3() {
  const lib = globalThis.d3;
  if (!lib) throw new Error("timeline: d3 is not loaded (ui/vendor/d3.v7.9.0.min.js must load before the module)");
  return lib;
}

function relSec(t, start) {
  return (t - start) / 1000;
}

/** Handoff connector: down (or up) from the caller's dot, then into the callee; never past xMax (the playhead). */
function elbow(x0, y0, x1, y1, xMax = Infinity) {
  const dy = y1 - y0;
  const room = Math.max(0, xMax - x0);
  if (Math.abs(dy) < 1) return `M${x0},${y0}H${x0 + Math.min(Math.max(x1 - x0, 6), room)}`;
  const dir = dy > 0 ? 1 : -1;
  const r = Math.min(8, Math.abs(dy) / 2, room);
  const xEnd = x0 + Math.max(r, Math.min(Math.max(x1 - x0, r + 4), room));
  return `M${x0},${y0}V${y1 - dir * r}Q${x0},${y1} ${x0 + r},${y1}H${xEnd}`;
}

/** The ⊗ glyph, centred on 0,0; with `halo`, on a card-coloured disc so it reads over anything. */
function failGlyph(r, halo = false) {
  const g = svgEl("g", { class: "tl-ico-fail" });
  if (halo) g.append(svgEl("circle", { r: r + 2.25, fill: CARD_BG }));
  const a = r * 0.45;
  g.append(
    svgEl("circle", { r, fill: halo ? "#3a1719" : "none", stroke: FAIL_RED, "stroke-width": 1.4 }),
    svgEl("path", { d: `M${-a},${-a}L${a},${a}M${a},${-a}L${-a},${a}`, stroke: FAIL_RED, "stroke-width": 1.4, "stroke-linecap": "round" }),
  );
  return g;
}

/**
 * ⊗ markers for failed blocks too narrow to hold one: above the lane's band, so neighbouring
 * blocks, handoff dots and the playhead never cover them. A sliver right next to a failed block
 * that shows its own ⊗ (a failed call and the instant failure of the model call after it) and
 * slivers close together share one marker. A refused handoff's own wait needs none: its dot says it.
 */
function failMarks(blocks, laneTop, markedCalls) {
  const byLane = new Map();
  for (const d of blocks) {
    if (!d.failed || (d.item.span && markedCalls.has(d.item.span.key))) continue;
    const list = byLane.get(d.item.laneIndex) || [];
    list.push(d);
    byLane.set(d.item.laneIndex, list);
  }
  const gap = (a, b) => Math.max(a.g.x - (b.g.x + b.g.w), b.g.x - (a.g.x + a.g.w));
  const marks = [];
  for (const [lane, list] of byLane) {
    list.sort((a, b) => a.g.x - b.g.x);
    let lastX = -Infinity;
    for (const d of list) {
      if (d.g.w >= FAIL_ICON_MIN_W) continue;
      if (list.some((o) => o !== d && o.g.w >= FAIL_ICON_MIN_W && gap(o, d) <= 6)) continue;
      const x = d.g.x + d.g.w / 2;
      if (x - lastX < 12) continue;
      lastX = x;
      marks.push({ key: `m:${d.key}`, x, y: laneTop(lane) + BAND_TOP - 8 });
    }
  }
  return marks;
}

export class RunCard {
  constructor(callbacks) {
    this.cb = callbacks;
    this.uid = `tl${(uidCounter += 1)}`;
    this.transform = d3().zoomIdentity;
    this.plotW = 0;
    this.sizeDirty = true;
    this.hatches = new Map();
    this.tipItem = null;
    this.dragging = false;
    this.scrollable = false;
    this.lastState = null;
    this._build();
  }

  // ---- DOM ---------------------------------------------------------------------------------
  _build() {
    this.titleEl = el("h2", { class: "tl-title", id: `${this.uid}-title` });
    this.statusEl = el("p", { class: "tl-status" });
    this.liveBtn = el("button", { type: "button", class: "tl-pill tl-live", "aria-label": "Jump to live", hidden: true }, el("span", { class: "tl-live-dot", "aria-hidden": "true" }), el("span", { class: "tl-live-text", text: "Go live" }));
    this.fitBtn = el("button", { type: "button", class: "tl-pill tl-fit", "aria-label": "Fit the whole run", hidden: true }, icons.fit(), el("span", { text: "Fit" }));
    const head = el(
      "header",
      { class: "tl-head" },
      el("div", { class: "tl-head-text" }, this.titleEl, this.statusEl),
      el("div", { class: "tl-head-actions" }, this.liveBtn, this.fitBtn),
    );

    this.labelsEl = el("div", { class: "tl-labels" });
    this.navHint = el("p", {
      class: "tl-sr",
      id: `${this.uid}-hint`,
      text: "Arrow keys move between segments and handoffs, Enter opens the selected one in Traffic, plus and minus zoom, 0 fits. Ctrl or Command and the mouse wheel zoom; Shift and the wheel pan.",
    });
    this.navLive = el("p", { class: "tl-sr", "aria-live": "polite" });
    this.plot = svgEl("svg", {
      class: "tl-plot",
      role: "application",
      "aria-roledescription": "run timeline",
      tabindex: 0,
      "aria-labelledby": `${this.uid}-title`,
      "aria-describedby": `${this.uid}-hint`,
    });
    this.plotWrap = el("div", { class: "tl-plotwrap" }, this.plot);
    this.lanesEl = el("div", { class: "tl-lanes" }, this.labelsEl, this.plotWrap);
    this.scrollEl = el("div", { class: "tl-scroll" }, this.lanesEl);
    this.axis = svgEl("svg", { class: "tl-axis", height: AXIS_H });
    this.axisRow = el("div", { class: "tl-axisrow" }, el("div", { class: "tl-axis-spacer" }), el("div", { class: "tl-axiswrap" }, this.axis));
    this.msgEl = el("div", { class: "tl-msg", hidden: true });
    this.body = el("div", { class: "tl-body" }, this.scrollEl, this.axisRow, this.msgEl);

    this.playBtn = el("button", { type: "button", class: "tl-btn tl-play", "aria-label": "Pause" }, icons.pause());
    this.restartBtn = el("button", { type: "button", class: "tl-btn tl-icon", "aria-label": "Restart" }, icons.restart());
    this.speedBtns = [1, 2, 4].map((s) => el("button", { type: "button", class: "tl-speed-btn", "aria-pressed": s === 1 ? "true" : "false", "aria-label": `Speed ${s}x`, "data-speed": s, text: `${s}x` }));
    const speed = el("div", { class: "tl-speed", role: "group", "aria-label": "Playback speed" }, ...this.speedBtns);
    const legend = el(
      "ul",
      { class: "tl-legend", "aria-label": "Legend" },
      el("li", {}, el("span", { class: "tl-key tl-key-think", "aria-hidden": "true" }), "Thinking"),
      el("li", {}, el("span", { class: "tl-key tl-key-tool", "aria-hidden": "true" }), "Tool call"),
      el("li", {}, el("span", { class: "tl-key tl-key-wait", "aria-hidden": "true" }), "Waiting"),
      el("li", {}, el("span", { class: "tl-key-ico", "aria-hidden": "true" }, icons.handoff()), "Handoff"),
      el("li", {}, el("span", { class: "tl-key-ico tl-key-fail", "aria-hidden": "true" }, icons.failed()), "Failed"),
    );
    const foot = el("footer", { class: "tl-foot" }, el("div", { class: "tl-ctrls" }, this.playBtn, this.restartBtn, speed), legend);

    this.tip = el("div", { class: "tl-tip", role: "tooltip", hidden: true });
    this.el = el("section", { class: "tl-card", "aria-label": "Run" }, head, this.body, foot, this.tip, this.navHint, this.navLive);

    this._buildSvg();
    this._wire();
  }

  _buildSvg() {
    const id = this.uid;
    this.defs = svgEl("defs");
    this.fadeGrad = svgEl(
      "linearGradient",
      { id: `${id}-fade-g`, gradientUnits: "userSpaceOnUse", x1: 0, y1: 0, x2: 1, y2: 0 },
      svgEl("stop", { offset: 0, "stop-color": "#fff", "stop-opacity": 1 }),
      svgEl("stop", { offset: 1, "stop-color": "#fff", "stop-opacity": 0 }),
    );
    this.fadeRect = svgEl("rect", { x: -20, y: 0, width: 10, height: 10, fill: `url(#${id}-fade-g)` });
    this.fadeMask = svgEl("mask", { id: `${id}-fade`, maskUnits: "userSpaceOnUse", x: -20, y: 0, width: 10, height: 10 }, this.fadeRect);
    this.clipRect = svgEl("rect", { x: 0, y: 0, width: 10, height: 10 });
    this.defs.append(this.fadeGrad, this.fadeMask, svgEl("clipPath", { id: `${id}-clip` }, this.clipRect));

    const g = (cls, extra = {}, ...kids) => svgEl("g", { class: cls, ...extra }, ...kids);
    this.gGrid = g("tl-grid");
    this.gTracks = g("tl-tracks");
    this.gTracksRun = g("tl-tracks", { mask: `url(#${id}-fade)` });
    this.gConns = g("tl-conns");
    this.gBlocks = g("tl-blocks");
    this.gBlocksRun = g("tl-blocks", { mask: `url(#${id}-fade)` });
    this.gDots = g("tl-dots");
    const content = g("tl-content", { "clip-path": `url(#${id}-clip)` }, this.gTracks, this.gTracksRun, this.gConns, this.gBlocks, this.gBlocksRun, this.gDots);
    this.phLine = svgEl("line", { class: "tl-ph-line", y1: 0 });
    this.phHit = svgEl("rect", { class: "tl-ph-hit", y: 0, width: 14 });
    this.gPh = g("tl-ph", {}, this.phLine, this.phHit);
    // On top of everything: ⊗ markers of failed blocks too narrow to hold one, and the keyboard ring.
    this.gMarks = g("tl-marks", { "clip-path": `url(#${id}-clip)` });
    this.navRing = svgEl("rect", { class: "tl-navring", rx: 10 });
    this.navRing.style.display = "none";
    this.plot.append(this.defs, this.gGrid, content, this.gPh, this.gMarks, this.navRing);

    this.axGrid = g("tl-ax-grid");
    this.axBase = svgEl("line", { class: "tl-ax-base", y1: AXIS_Y, y2: AXIS_Y, x1: 0 });
    this.axTicks = g("tl-ax-ticks");
    this.axPhLine = svgEl("line", { class: "tl-ph-line", y1: 0, y2: AXIS_Y });
    this.axFocus = svgEl("circle", { class: "tl-ph-focus", r: 9, cy: AXIS_Y });
    this.axDot = svgEl("circle", { class: "tl-ph-dot", r: 5.5, cy: AXIS_Y });
    this.axHandle = svgEl("circle", {
      class: "tl-ph-handle",
      r: 13,
      cy: AXIS_Y,
      tabindex: 0,
      role: "slider",
      "aria-label": "Playhead",
      "aria-valuemin": 0,
    });
    this.axis.append(this.axGrid, this.axBase, this.axTicks, this.axPhLine, this.axFocus, this.axDot, this.axHandle);
  }

  _wire() {
    const lib = d3();
    this.playBtn.addEventListener("click", () => this.cb.onPlayPause());
    this.restartBtn.addEventListener("click", () => this.cb.onRestart());
    for (const b of this.speedBtns) b.addEventListener("click", () => this.cb.onSpeed(Number(b.dataset.speed)));
    this.liveBtn.addEventListener("click", () => this.cb.onLive());
    this.fitBtn.addEventListener("click", () => this.fit());

    // Zoom and pan on the time axis only (x of the transform; y is ignored).
    this.zoom = lib
      .zoom()
      .scaleExtent([1, 400])
      // A click that moves a few pixels is still a click (else d3-zoom swallows it as a pan).
      .clickDistance(4)
      .filter((ev) => ev.type !== "wheel" && ev.type !== "dblclick" && !ev.ctrlKey && !ev.button)
      .on("start", () => {
        this.dragging = true;
        if (this.tipSource !== "key") this._hideTip();
      })
      .on("zoom", (ev) => {
        this.transform = ev.transform;
        this.cb.onZoom();
      })
      .on("end", () => {
        this.dragging = false;
      });
    lib.select(this.plot).call(this.zoom).on("dblclick.zoom", null);
    this._onWheel = (e) => this._wheel(e);
    this.plot.addEventListener("wheel", this._onWheel, { passive: false });
    this.axis.addEventListener("wheel", this._onWheel, { passive: false });
    this.plot.addEventListener("dblclick", (e) => {
      // Over a segment the first click already opened it; fitting there too would surprise.
      if (e.target.closest && e.target.closest("[data-open]")) return;
      this.fit();
    });

    // Scrub: drag the playhead (or anywhere on the axis).
    const seek = (phase) => (ev) => {
      if (!this.x) return;
      this.dragging = phase !== "end";
      this.cb.onSeek(this.x.invert(ev.x) * 1000, phase);
    };
    const scrub = () => lib.drag().on("start", seek("start")).on("drag", seek("drag")).on("end", seek("end"));
    lib.select(this.axis).call(scrub().container(this.axis));
    lib.select(this.phHit).call(scrub().container(this.plot));
    this.axHandle.addEventListener("keydown", (e) => {
      const step = e.shiftKey ? 5000 : 500;
      const map = { ArrowLeft: -step, ArrowDown: -step, ArrowRight: step, ArrowUp: step, PageDown: -10_000, PageUp: 10_000 };
      if (e.key in map) {
        e.preventDefault();
        this.cb.onSeekBy(map[e.key]);
      } else if (e.key === "Home") {
        e.preventDefault();
        this.cb.onSeek(0, "key");
      } else if (e.key === "End") {
        e.preventDefault();
        this.cb.onSeek(Infinity, "key");
      }
    });
    this.axHandle.addEventListener("focus", () => this.axFocus.classList.add("is-on"));
    this.axHandle.addEventListener("blur", () => this.axFocus.classList.remove("is-on"));

    // Hover and click on segments, connectors and dots (event delegation).
    this.plot.addEventListener("pointermove", (e) => {
      const n = e.target.closest && e.target.closest("[data-tip]");
      if (!n || this.dragging || !n.__data__) {
        if (this.tipSource !== "key") this._hideTip();
        return;
      }
      this._showTip(n.__data__, e);
      this.tipSource = "pointer";
    });
    this.plot.addEventListener("pointerleave", () => {
      if (this.tipSource !== "key") this._hideTip();
    });
    this.plot.addEventListener("click", (e) => {
      if (e.detail > 1) return; // the second click of a double-click
      const n = e.target.closest && e.target.closest("[data-open]");
      if (!n || !n.__data__) return;
      const span = this._spanAt(n.__data__, e);
      if (span) this.cb.onOpenTraffic(span);
    });

    // Keyboard: segments, waits and handoff dots are reachable with the arrow keys.
    this.nav = [];
    this.navKey = null;
    this.plot.addEventListener("keydown", (e) => this._navKeydown(e));
    this.plot.addEventListener("focus", () => {
      let visible = true;
      try {
        visible = this.plot.matches(":focus-visible");
      } catch {
        // older engines: treat every focus as keyboard focus
      }
      if (visible) this._navMove(this._navCurrent() || this._navStart(), true);
    });
    this.plot.addEventListener("blur", () => {
      this.navRing.style.display = "none";
      if (this.tipSource === "key") this._hideTip();
    });

    this.scrollEl.addEventListener("scroll", () => this.cb.onZoom(), { passive: true });
    this.resizeObserver = new ResizeObserver(() => {
      this.sizeDirty = true;
      this.cb.onZoom();
    });
    this.resizeObserver.observe(this.plotWrap);
  }

  destroy() {
    this.resizeObserver.disconnect();
    this.plot.removeEventListener("wheel", this._onWheel);
    this.axis.removeEventListener("wheel", this._onWheel);
    d3().select(this.plot).on(".zoom", null);
  }

  // Ctrl/Cmd + wheel (and a trackpad pinch) zooms; a horizontal wheel or Shift + wheel pans. A plain
  // vertical wheel is left to the page (or to the lanes when they scroll), so the view never traps it.
  _wheel(e) {
    const lib = d3();
    const sel = lib.select(this.plot);
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      const unit = e.deltaMode === 1 ? 0.05 : e.deltaMode ? 1 : 0.002;
      const k = 2 ** (-e.deltaY * unit * (e.ctrlKey ? 5 : 1));
      const [px] = lib.pointer(e, this.plot);
      this.zoom.scaleBy(sel, k, [px, 0]);
      return;
    }
    const horizontal = Math.abs(e.deltaX) > Math.abs(e.deltaY);
    if ((horizontal || e.shiftKey) && this.zoomed) {
      e.preventDefault();
      this.zoom.translateBy(sel, -(horizontal ? e.deltaX : e.deltaY) / this.transform.k, 0);
    }
  }

  _zoomBy(k) {
    const item = this._navCurrent();
    const cx = item ? item.x + item.w / 2 : this.lastXP ?? this.plotW / 2;
    this.zoom.scaleBy(d3().select(this.plot), k, [cx, 0]);
  }

  fit() {
    d3().select(this.plot).call(this.zoom.transform, d3().zoomIdentity);
  }

  resetZoom() {
    this.transform = d3().zoomIdentity;
    d3().select(this.plot).property("__zoom", this.transform);
  }

  get zoomed() {
    return this.transform.k > 1.001;
  }

  // ---- messages ----------------------------------------------------------------------------
  setMessage(text) {
    this.msgEl.textContent = text || "";
    this.msgEl.hidden = !text;
    this.body.classList.toggle("has-msg", Boolean(text));
  }

  // ---- rendering ---------------------------------------------------------------------------
  /** Header only, no run drawn (loading, empty or failed to load). */
  renderIdle(title, statusText) {
    this.lastState = null;
    this.titleEl.textContent = title || "";
    this.statusEl.textContent = statusText || "";
    this.liveBtn.hidden = true;
    this.fitBtn.hidden = true;
    for (const g of [this.gGrid, this.gTracks, this.gTracksRun, this.gConns, this.gBlocks, this.gBlocksRun, this.gDots, this.axGrid, this.axTicks]) g.replaceChildren();
    this.labelsEl.replaceChildren();
    this.lanesEl.style.height = `${LANE_H * 3}px`;
    this.gPh.style.display = "none";
    this.axPhLine.style.display = "none";
    this.axDot.style.display = "none";
    this._hideTip();
  }

  /**
   * state: { derived, title, P (ms from run start), maxP, baseEndMs, playing, live, running,
   *          speed, now (absolute ms) }
   */
  render(state) {
    const lib = d3();
    this.lastState = state;
    const { derived } = state;
    const lanes = derived.lanes;

    // Header.
    this.titleEl.textContent = state.title;
    this.titleEl.title = state.title;
    this.statusEl.textContent = state.statusText;
    // "Go live" only when a running run is shown away from now; "Fit" only when zoomed.
    this.liveBtn.hidden = !state.running || !state.liveAvailable || state.live;
    this.fitBtn.hidden = !this.zoomed;

    // Footer.
    const showPause = state.playing;
    if (this.playBtn.dataset.mode !== (showPause ? "pause" : "play")) {
      this.playBtn.dataset.mode = showPause ? "pause" : "play";
      this.playBtn.replaceChildren(showPause ? icons.pause() : icons.play());
      this.playBtn.setAttribute("aria-label", showPause ? "Pause" : "Play");
    }
    for (const b of this.speedBtns) b.setAttribute("aria-pressed", Number(b.dataset.speed) === state.speed ? "true" : "false");

    // Sizes and lane window (virtualised beyond 30 lanes).
    const laneCount = Math.max(1, lanes.length);
    const H = laneCount * LANE_H;
    this.scrollable = lanes.length > VIRTUAL_LANES;
    this.scrollEl.classList.toggle("is-virtual", this.scrollable);
    if (this.scrollable) this.scrollEl.style.maxHeight = `${VISIBLE_LANES_WHEN_VIRTUAL * LANE_H}px`;
    else this.scrollEl.style.removeProperty("max-height");
    this.lanesEl.style.height = `${H}px`;
    if (this.sizeDirty || !this.plotW) {
      this.plotW = Math.max(120, Math.floor(this.plotWrap.clientWidth));
      this.sizeDirty = false;
    }
    const W = this.plotW;
    let firstLane = 0;
    let lastLane = lanes.length - 1;
    if (this.scrollable) {
      const top = this.scrollEl.scrollTop;
      const vh = this.scrollEl.clientHeight || VISIBLE_LANES_WHEN_VIRTUAL * LANE_H;
      firstLane = Math.max(0, Math.floor(top / LANE_H) - LANE_OVERSCAN);
      lastLane = Math.min(lanes.length - 1, Math.ceil((top + vh) / LANE_H) + LANE_OVERSCAN);
    }
    const laneVisible = (i) => i >= firstLane && i <= lastLane;
    const yTop = firstLane * LANE_H;
    const yBottom = (lastLane + 1) * LANE_H;

    this.plot.setAttribute("width", W);
    this.plot.setAttribute("height", H);
    this.axis.setAttribute("width", W);
    this.clipRect.setAttribute("width", W);
    this.clipRect.setAttribute("height", H);
    this.zoom.extent([[0, 0], [W, H]]).translateExtent([[0, 0], [W, H]]);

    // Scales: seconds from the run start.
    const base = lib.scaleLinear().domain([0, state.baseEndMs / 1000]).range([PAD_L, W - PAD_R]);
    let x = this.transform.rescaleX(base);
    const Psec = state.P / 1000;
    if (state.live && this.zoomed) {
      const xp = x(Psec);
      if (xp > W * 0.92 || xp < PAD_L) {
        const k = this.transform.k;
        const t = lib.zoomIdentity.translate(W * 0.75 - k * base(Psec), 0).scale(k);
        lib.select(this.plot).call(this.zoom.transform, t);
        x = this.transform.rescaleX(base);
      }
    }
    this.x = x;
    const runStart = derived.runStart;
    const at = runStart + state.P;
    const X = (t) => x(relSec(t, runStart));
    const xP = x(Psec);
    const visLo = -60;
    const visHi = W + 60;

    // Grid and axis.
    const ticks = x.ticks(Math.max(2, Math.floor(W / 110)));
    const step = ticks.length > 1 ? ticks[1] - ticks[0] : 1;
    const shown = ticks.filter((t) => t >= 0 && x(t) >= 0 && x(t) <= W);
    lib.select(this.gGrid)
      .selectAll("line")
      .data(shown, (t) => t)
      .join("line")
      .attr("x1", (t) => x(t))
      .attr("x2", (t) => x(t))
      .attr("y1", 0)
      .attr("y2", H);
    lib.select(this.axGrid)
      .selectAll("line")
      .data(shown, (t) => t)
      .join("line")
      .attr("x1", (t) => x(t))
      .attr("x2", (t) => x(t))
      .attr("y1", 0)
      .attr("y2", AXIS_Y);
    this.axBase.setAttribute("x2", W);
    lib.select(this.axTicks)
      .selectAll("text")
      .data(shown, (t) => t)
      .join("text")
      .attr("x", (t) => x(t))
      .attr("y", AXIS_Y + 20)
      .text((t) => fmtTick(t, step));

    // Lane geometry.
    const laneTop = (i) => i * LANE_H;
    const laneMid = (i) => laneTop(i) + LANE_H / 2;
    const colors = derived.colors;
    const color = (lane) => colors.get(lane) || colors.values().next().value;
    const rowsOf = (lane) => derived.laneRows.get(lane) || 1;
    const geom = (item, s, e, running) => {
      const rows = item.type === "waiting" || item.type === "invocation-track" ? 1 : rowsOf(item.lane);
      const h = rows === 1 ? BLOCK_H : (BLOCK_H - (rows - 1) * ROW_GAP) / rows;
      const y = laneTop(item.laneIndex) + (LANE_H - BLOCK_H) / 2 + (item.row || 0) * (h + ROW_GAP);
      const x0 = X(s);
      const x1 = X(e);
      let w = running ? x1 - x0 - INSET : x1 - x0 - 2 * INSET;
      if (w < MIN_W) w = MIN_W;
      return { x: x0 + INSET, y, w, h };
    };

    // Items visible at the playhead. A span is only drawn failed once the playhead passed its end.
    const visibleSpan = (s) => s.start <= at;
    const cut = (s) => {
      const done = s.end !== null && s.end <= at;
      return { end: done ? s.end : at, running: !done };
    };
    const tracksDone = [];
    const tracksRun = [];
    for (const t of derived.tracks) {
      if (!visibleSpan(t.span) || !laneVisible(t.laneIndex) || t.empty) continue;
      const c = cut(t.span);
      const g = geom({ ...t, type: "invocation-track" }, t.span.start, c.end, c.running);
      if (g.x + g.w < visLo || g.x > visHi) continue;
      const d = { key: t.key, item: t, g: { x: g.x - 2, y: g.y - 3, w: g.w + 4, h: g.h + 6 }, c: color(t.lane), failed: t.failed && !c.running };
      (c.running ? tracksRun : tracksDone).push(d);
    }

    const blocksDone = [];
    const blocksRun = [];
    const pushBlock = (d, running) => (running ? blocksRun : blocksDone).push(d);
    // Waiting: the caller's waits on its sub-agents, merged where they overlap.
    const waitsByLane = new Map();
    for (const w of derived.waits) {
      if (!visibleSpan(w.span) || !laneVisible(w.laneIndex)) continue;
      const list = waitsByLane.get(w.lane) || [];
      list.push(w);
      waitsByLane.set(w.lane, list);
    }
    for (const [lane, list] of waitsByLane) {
      list.sort((a, b) => a.span.start - b.span.start);
      let cur = null;
      const flush = () => {
        if (!cur) return;
        const g = geom(cur, cur.start, cur.end, cur.running);
        if (g.x + g.w >= visLo && g.x <= visHi) pushBlock({ key: `w:${cur.members[0].key}`, item: cur, g, c: color(lane), type: "waiting", failed: false, running: cur.running }, cur.running);
      };
      for (const w of list) {
        const c = cut(w.span);
        if (cur && w.span.start <= cur.end + 1) {
          cur.members.push(w);
          if (c.end >= cur.end) {
            cur.end = c.end;
            cur.running = c.running;
          }
        } else {
          flush();
          cur = { lane, laneIndex: w.laneIndex, type: "waiting", members: [w], start: w.span.start, end: c.end, running: c.running, row: 0 };
        }
      }
      flush();
    }
    for (const b of derived.blocks) {
      if (!visibleSpan(b.span) || !laneVisible(b.laneIndex)) continue;
      const c = cut(b.span);
      const g = geom(b, b.span.start, c.end, c.running);
      if (g.x + g.w < visLo || g.x > visHi) continue;
      pushBlock({ key: b.key, item: b, g, c: color(b.lane), type: b.type, failed: b.failed && !c.running, running: c.running }, c.running);
    }
    for (const o of openThinking(derived, at)) {
      if (!laneVisible(o.laneIndex) || o.start > at) continue;
      const g = geom(o, o.start, at, true);
      if (g.x + g.w < visLo || g.x > visHi) continue;
      blocksRun.push({ key: o.key, item: o, g, c: color(o.lane), type: "thinking", failed: false, running: true, open: true });
    }

    // Handoffs: elbow from a dot on the caller lane down (or up) into the callee's invocation.
    const conns = [];
    for (const h of derived.handoffs) {
      const s = h.call;
      if (s.start > at) continue;
      const fi = derived.laneIndex.get(h.from);
      const ti = derived.laneIndex.get(h.to);
      if (fi === undefined || ti === undefined) continue;
      const y0 = laneMid(fi);
      const y1 = laneMid(ti);
      if (Math.max(y0, y1) < yTop || Math.min(y0, y1) > yBottom) continue;
      const x0 = X(s.start);
      if (x0 < visLo - 400 || x0 > visHi) continue;
      const childStarted = h.child && h.child.start <= at;
      const x1 = childStarted ? X(h.child.start) : x0;
      const ended = s.end !== null && s.end <= at;
      conns.push({ key: h.key, h, x0, y0, x1, y1, xMax: xP, c: color(h.to), failed: ended && (s.status === "error" || s.status === "denied"), childStarted });
    }

    this._drawTracks(this.gTracks, tracksDone);
    this._drawTracks(this.gTracksRun, tracksRun);
    this._drawConns(conns);
    this._drawBlocks(this.gBlocks, blocksDone);
    this._drawBlocks(this.gBlocksRun, blocksRun);
    this._drawDots(conns);
    this._drawMarks(failMarks(blocksDone, laneTop, new Set(conns.filter((c) => c.failed).map((c) => c.h.call.key))));

    // Keyboard navigation targets, by lane and then time.
    const nav = [];
    for (const d of blocksDone.concat(blocksRun)) nav.push({ key: d.key, lane: d.item.laneIndex, x: d.g.x, y: d.g.y, w: d.g.w, h: d.g.h, d });
    for (const c of conns) nav.push({ key: c.key, lane: derived.laneIndex.get(c.h.from), x: c.x0 - 5, y: c.y0 - 5, w: 10, h: 10, d: c, dot: true });
    nav.sort((a, b) => a.lane - b.lane || a.x - b.x || a.y - b.y);
    this.nav = nav;

    // Fade at the playhead for running work.
    this.fadeGrad.setAttribute("x1", xP - FADE_PX);
    this.fadeGrad.setAttribute("x2", xP);
    for (const n of [this.fadeMask, this.fadeRect]) {
      n.setAttribute("width", W + 40);
      n.setAttribute("height", H);
    }

    // Playhead.
    this.lastXP = xP;
    const phVisible = xP >= 0 && xP <= W;
    this.gPh.style.display = phVisible ? "" : "none";
    this.phLine.setAttribute("x1", xP);
    this.phLine.setAttribute("x2", xP);
    this.phLine.setAttribute("y2", H);
    this.phHit.setAttribute("x", xP - 7);
    this.phHit.setAttribute("height", H);
    this.axPhLine.setAttribute("x1", xP);
    this.axPhLine.setAttribute("x2", xP);
    for (const n of [this.axDot, this.axHandle, this.axFocus]) n.setAttribute("cx", clamp(xP, -20, W + 20));
    this.axPhLine.style.display = phVisible ? "" : "none";
    this.axDot.style.display = phVisible ? "" : "none";
    this.axHandle.setAttribute("aria-valuemax", (state.maxP / 1000).toFixed(1));
    this.axHandle.setAttribute("aria-valuenow", Psec.toFixed(1));
    this.axHandle.setAttribute("aria-valuetext", `${Psec.toFixed(1)} seconds`);

    this._drawLabels(lanes, laneVisible, colors, state.running);

    // Keep an open tooltip (and the keyboard ring) current while the run plays.
    if (document.activeElement === this.plot && this.navKey) this._navSync(false, this.tipSource === "key");
    if (this.tipSource !== "key" && this.tipItem && this.tipEvent) this._showTip(this.tipItem, this.tipEvent, true);
  }

  _hatch(c) {
    const key = c.stripe;
    if (this.hatches.has(key)) return this.hatches.get(key);
    const id = `${this.uid}-hatch-${this.hatches.size}`;
    const pat = svgEl(
      "pattern",
      { id, patternUnits: "userSpaceOnUse", width: 7, height: 7, patternTransform: "rotate(45)" },
      svgEl("rect", { width: 7, height: 7, fill: CARD_BG }),
      svgEl("line", { x1: 1.5, y1: 0, x2: 1.5, y2: 7, stroke: c.stripe, "stroke-width": 2.2 }),
    );
    this.defs.append(pat);
    const ref = `url(#${id})`;
    this.hatches.set(key, ref);
    return ref;
  }

  _drawTracks(group, data) {
    d3()
      .select(group)
      .selectAll("rect")
      .data(data, (d) => d.key)
      .join((enter) => enter.append("rect").attr("class", "tl-track"))
      .attr("x", (d) => d.g.x)
      .attr("y", (d) => d.g.y)
      .attr("width", (d) => Math.max(0, d.g.w))
      .attr("height", (d) => d.g.h)
      .attr("rx", 9)
      .attr("fill", (d) => d.c.track)
      .attr("stroke", (d) => (d.failed ? FAIL_RED : "none"))
      .attr("stroke-opacity", (d) => (d.failed ? 0.45 : 0));
  }

  _drawConns(data) {
    d3()
      .select(this.gConns)
      .selectAll("g.tl-conn")
      .data(data, (d) => d.key)
      .join((enter) => {
        const g = enter.append("g").attr("class", "tl-conn").attr("data-tip", "").attr("data-open", "");
        g.append("path").attr("class", "tl-conn-line");
        g.append("path").attr("class", "tl-conn-hit");
        return g;
      })
      .each(function draw(d) {
        // A refused or failed handoff stops at the edge of the callee's band (nothing started there
        // worth pointing into, and a stub would cross that lane's blocks).
        const dir = d.y1 > d.y0 ? 1 : -1;
        const path =
          d.failed && Math.abs(d.y1 - d.y0) >= 1
            ? `M${d.x0},${d.y0}V${d.y1 - dir * (BLOCK_H / 2 + 3)}`
            : elbow(d.x0, d.y0, d.childStarted ? d.x1 : d.x0, d.y1, d.xMax);
        const [line, hit] = this.childNodes;
        line.setAttribute("d", path);
        line.setAttribute("stroke", d.c.base);
        line.setAttribute("stroke-dasharray", d.failed ? "4 3" : "");
        hit.setAttribute("d", path);
      });
  }

  _drawDots(data) {
    d3()
      .select(this.gDots)
      .selectAll("circle")
      .data(data, (d) => d.key)
      .join((enter) => enter.append("circle").attr("class", "tl-dot").attr("r", 4).attr("data-tip", "").attr("data-open", ""))
      .attr("cx", (d) => d.x0)
      .attr("cy", (d) => d.y0)
      .attr("fill", (d) => d.c.base)
      .classed("is-failed", (d) => d.failed);
  }

  _drawMarks(data) {
    d3()
      .select(this.gMarks)
      .selectAll("g.tl-mark")
      .data(data, (d) => d.key)
      .join((enter) =>
        enter.append((d) => {
          const g = failGlyph(4.5, true);
          g.setAttribute("class", "tl-mark");
          return g;
        }),
      )
      .attr("transform", (d) => `translate(${d.x.toFixed(2)},${d.y.toFixed(2)})`);
  }

  _drawBlocks(group, data) {
    const card = this;
    d3()
      .select(group)
      .selectAll("g.tl-block")
      .data(data, (d) => d.key)
      .join((enter) => {
        const g = enter.append("g").attr("class", "tl-block").attr("data-tip", "").attr("data-open", "");
        g.append("rect");
        return g;
      })
      .each(function draw(d) {
        card._drawBlock(this, d);
      });
  }

  _drawBlock(node, d) {
    const { g, c } = d;
    node.setAttribute("transform", `translate(${g.x.toFixed(2)},${g.y.toFixed(2)})`);
    const rect = node.firstChild;
    rect.setAttribute("width", Math.max(0, g.w).toFixed(2));
    rect.setAttribute("height", g.h);
    rect.setAttribute("rx", Math.min(8, g.h / 2, Math.max(1.5, g.w / 2)));
    let fill;
    let stroke = "none";
    let sw = 0;
    if (d.failed) {
      fill = "#3a1719";
      stroke = FAIL_RED;
      sw = 1.25;
    } else if (d.type === "waiting") {
      fill = this._hatch(c);
      stroke = c.waitStroke;
      sw = 1;
    } else if (d.type === "thinking") {
      fill = c.think;
      stroke = c.thinkStroke;
      sw = 0.75;
    } else {
      fill = c.tool;
    }
    rect.setAttribute("fill", fill);
    rect.setAttribute("stroke", stroke);
    rect.setAttribute("stroke-width", sw);

    // Decorations: ⊗ for failed, ↻ for retried model calls, a "fallback" tag.
    const span = d.item.span;
    const wide = g.w >= 22;
    const retry = d.type === "thinking" && span && span.attempt > 1 && (d.failed ? g.w >= 38 : wide);
    const fallback = !d.failed && d.type === "thinking" && span && span.fallback;
    // ⊗ inside wide failed blocks (left) and mid-size ones (centred); narrower ones get a marker
    // above the band (failMarks), drawn on top of everything.
    const failIcon = d.failed && g.w >= FAIL_ICON_MIN_W;
    const sig = `${failIcon ? "f" : ""}${retry ? "r" : ""}${fallback && g.w >= 76 ? "b" : ""}${wide ? "w" : "n"}${g.h}`;
    const cy = g.h / 2;
    const failAt = `translate(${wide ? 11 : (g.w / 2).toFixed(2)},${cy})`;
    if (node.__sig === sig) {
      const ico = node.querySelector(".tl-ico-fail");
      if (ico && !wide && ico.getAttribute("transform") !== failAt) ico.setAttribute("transform", failAt);
      return;
    }
    node.__sig = sig;
    while (node.childNodes.length > 1) node.lastChild.remove();
    if (failIcon) {
      const grp = failGlyph(Math.min(5, g.h / 2 - 1.5));
      grp.setAttribute("transform", failAt);
      node.append(grp);
    }
    if (retry) {
      const s = Math.min(1, g.h / 20);
      const rx = d.failed ? 26 : 11;
      node.append(
        svgEl(
          "g",
          { class: "tl-ico-retry", transform: `translate(${rx - 6 * s},${cy - 6 * s}) scale(${0.75 * s})` },
          svgEl("path", { d: "M3.2 8a4.8 4.8 0 1 0 1.5-3.5", fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round" }),
          svgEl("path", { d: "M4.2 1.9v3h3", fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round" }),
        ),
      );
    }
    if (fallback && g.w >= 76) {
      node.append(svgEl("text", { class: "tl-tag", x: retry ? 22 : 9, y: cy + 3.5, text: "fallback" }));
    }
  }

  _drawLabels(lanes, laneVisible, colors, running) {
    const lib = d3();
    const cb = this.cb;
    const data = lanes.filter((l) => laneVisible(l.index));
    lib.select(this.labelsEl)
      .selectAll("button.tl-lane")
      .data(data, (d) => d.id)
      .join((enter) =>
        enter.append((d) => {
          const btn = el(
            "button",
            { type: "button", class: "tl-lane" },
            el("span", { class: "tl-lane-row" }, el("span", { class: "tl-lane-dot", "aria-hidden": "true" }), el("span", { class: "tl-lane-name" })),
            el("span", { class: "tl-lane-model" }),
          );
          btn.addEventListener("click", () => cb.onSelectNode(btn.__data__ ? btn.__data__.id : d.id));
          return btn;
        }),
      )
      .each(function update(d) {
        this.style.top = `${d.index * LANE_H}px`;
        this.style.height = `${LANE_H}px`;
        const c = colors.get(d.id);
        const dot = this.querySelector(".tl-lane-dot");
        dot.style.background = c ? c.base : "#888";
        const name = this.querySelector(".tl-lane-name");
        if (name.textContent !== d.name) name.textContent = d.name;
        const modelEl = this.querySelector(".tl-lane-model");
        const modelText = d.model || (running ? "model pending" : "no model call");
        if (modelEl.dataset.model !== modelText) {
          modelEl.dataset.model = modelText;
          modelEl.replaceChildren(providerGlyph(d.model), el("span", { text: modelText }));
          modelEl.classList.toggle("is-pending", !d.model);
        }
        this.title = d.id;
        this.setAttribute("aria-label", `${d.name}${d.model ? `, ${d.model}` : ""}. Select ${d.short} in the graph`);
      });
  }

  // ---- keyboard navigation -----------------------------------------------------------------
  _navCurrent() {
    return this.navKey ? this.nav.find((n) => n.key === this.navKey) || null : null;
  }

  /** First stop: the item of the first lane nearest the playhead. */
  _navStart() {
    if (!this.nav.length) return null;
    const xP = this.lastXP ?? 0;
    const lane = this.nav[0].lane;
    let best = null;
    for (const n of this.nav) {
      if (n.lane !== lane) break;
      if (!best || Math.abs(n.x + n.w / 2 - xP) < Math.abs(best.x + best.w / 2 - xP)) best = n;
    }
    return best;
  }

  _navKeydown(e) {
    if (!NAV_KEYS.has(e.key) || e.ctrlKey || e.metaKey || e.altKey) return;
    e.preventDefault();
    const k = e.key;
    if (k === "+" || k === "=") return this._zoomBy(1.6);
    if (k === "-" || k === "_") return this._zoomBy(1 / 1.6);
    if (k === "0") return this.fit();
    if (k === "Escape") {
      this.navKey = null;
      this.navRing.style.display = "none";
      this._hideTip();
      return undefined;
    }
    const cur = this._navCurrent();
    if (k === "Enter") {
      const span = cur ? this._spanAt(cur.d, this._navEvent(cur)) : null;
      if (span) this.cb.onOpenTraffic(span);
      return undefined;
    }
    if (!cur) return this._navMove(this._navStart(), true);
    const inLane = this.nav.filter((n) => n.lane === cur.lane);
    const i = inLane.indexOf(cur);
    let next = null;
    if (k === "ArrowRight") next = inLane[Math.min(inLane.length - 1, i + 1)];
    else if (k === "ArrowLeft") next = inLane[Math.max(0, i - 1)];
    else if (k === "Home") next = inLane[0];
    else if (k === "End") next = inLane[inLane.length - 1];
    else {
      const lanes = [...new Set(this.nav.map((n) => n.lane))];
      const target = lanes[lanes.indexOf(cur.lane) + (k === "ArrowDown" ? 1 : -1)];
      const cx = cur.x + cur.w / 2;
      const dist = (n) => Math.abs(n.x + n.w / 2 - cx);
      for (const n of this.nav) if (n.lane === target && (!next || dist(n) < dist(next))) next = n;
    }
    return this._navMove(next || cur, true);
  }

  _navEvent(item) {
    const box = this.plot.getBoundingClientRect();
    return { clientX: box.left + item.x + item.w / 2, clientY: box.top + item.y + item.h, target: this.plot };
  }

  _navMove(item, announce) {
    if (!item) return;
    this.navKey = item.key;
    this.tipSource = "key";
    this._navSync(announce, true);
  }

  /** Ring around the selected item; its tooltip; with `announce`, a summary for screen readers. */
  _navSync(announce = false, withTip = true) {
    const item = this._navCurrent();
    if (!item) {
      this.navRing.style.display = "none";
      if (this.tipSource === "key") this._hideTip();
      return;
    }
    const pad = item.dot ? 2 : 3;
    this.navRing.setAttribute("x", (item.x - pad).toFixed(2));
    this.navRing.setAttribute("y", (item.y - pad).toFixed(2));
    this.navRing.setAttribute("width", Math.max(0, item.w + 2 * pad).toFixed(2));
    this.navRing.setAttribute("height", (item.h + 2 * pad).toFixed(2));
    this.navRing.setAttribute("rx", item.dot ? item.w / 2 + pad : 10);
    this.navRing.style.display = "";
    if (!withTip) return;
    const info = this._showTip(item.d, this._navEvent(item), !announce);
    this.tipSource = "key";
    if (announce && info) {
      const keep = new Set(["On", "Kind", "Callee", "Start", "Duration", "Status", "Attempt", "Error"]);
      const rows = info.rows.filter(([k]) => keep.has(k)).map(([k, v]) => `${k} ${v}`);
      this.navLive.textContent = `${info.title}. ${rows.join(", ")}. Enter opens it in Traffic.`;
    }
  }

  // ---- tooltip -----------------------------------------------------------------------------
  /** The span behind an item; for merged waits, the call that covers the pointer time. */
  _spanAt(d, e) {
    if (d.h) return d.h.call;
    const item = d.item;
    if (!item) return null;
    if (item.members) {
      const t = this._timeAt(e);
      let best = item.members[0].span;
      for (const m of item.members) {
        const s = m.span;
        if (s.start <= t && (s.end === null || s.end >= t)) best = s;
      }
      return best;
    }
    if (item.open) return item.inv;
    return item.span || null;
  }

  _timeAt(e) {
    const st = this.lastState;
    if (!st || !this.x) return 0;
    const [px] = d3().pointer(e, this.plot);
    return st.derived.runStart + this.x.invert(px) * 1000;
  }

  _showTip(d, e, refresh = false) {
    const st = this.lastState;
    if (!st) return null;
    const span = this._spanAt(d, e);
    if (!span) return null;
    const runStart = st.derived.runStart;
    const at = runStart + st.P;
    const rows = [];
    let title;
    if (d.h) {
      const idx = d.h.call.call_index;
      title = `Handoff → ${displayName(d.h.to)}${idx > 1 ? ` #${idx}` : ""}`;
      rows.push(["From", displayName(d.h.from)], ["To", d.h.to]);
    } else if (d.open) {
      title = `Thinking · ${displayName(d.item.lane)}`;
      rows.push(["Since", `+${((d.item.start - runStart) / 1000).toFixed(3)}s`], ["So far", fmtLatency(at - d.item.start)], ["Note", "The model call is reported when it ends."]);
    } else {
      const type = d.type === "invocation" ? "Invocation" : TYPE_LABEL[d.type] || span.kind;
      title = `${type} · ${displayName(span.agent)}${d.failed ? " · failed" : ""}`;
      if (d.type === "waiting" && span.callee) {
        const others = d.item.members ? d.item.members.length - 1 : 0;
        rows.push(["On", `${span.callee}${span.call_index > 1 ? ` #${span.call_index}` : ""}${others > 0 ? ` (+${others} more)` : ""}`]);
      }
    }
    if (!d.open) {
      const running = span.end === null || span.end > at;
      rows.push(["Kind", span.kind]);
      if (span.callee && !(d.type === "waiting" && !d.h)) rows.push(["Callee", span.callee]);
      rows.push(["Start", `+${((span.start - runStart) / 1000).toFixed(3)}s`]);
      rows.push(["Duration", running ? `${fmtLatency(at - span.start)} (running)` : fmtLatency(span.latency_ms ?? span.end - span.start)]);
      rows.push(["Status", running ? "running" : span.status]);
      if (span.decision && !running) rows.push(["Decision", span.decision]);
      if (span.rule && !running) rows.push(["Rule", span.rule]);
      if (span.tokens_in !== null || span.tokens_out !== null) rows.push(["Tokens", `${fmtInt(span.tokens_in)} in · ${fmtInt(span.tokens_out)} out`]);
      if (span.cost_usd) rows.push(["Cost", fmtCost(span.cost_usd)]);
      if (span.kind === "model_call") rows.push(["Attempt", `${span.attempt}${span.fallback ? " (fallback model)" : ""}`]);
      if (span.call_index > 1 && !d.h && d.type !== "waiting") rows.push(["Call", `#${span.call_index}`]);
      if (span.merged > 1) rows.push(["Merged", `${span.merged} model calls`]);
      if (span.error) rows.push(["Error", span.error]);
      if (span.events && span.events.length) rows.push(["Events", span.events.map((ev) => `${ev.kind} ${ev.rule || ""} (${ev.decision || "-"})`).join(", ")]);
    }
    if (!refresh || this.tipKey !== `${title}|${rows.length}|${rows.map((r) => r[1]).join("|")}`) {
      this.tipKey = `${title}|${rows.length}|${rows.map((r) => r[1]).join("|")}`;
      const dl = el("dl", {});
      for (const [k, v] of rows) dl.append(el("dt", { text: k }), el("dd", { text: v }));
      this.tip.replaceChildren(el("div", { class: "tl-tip-title", text: title }), dl);
    }
    this.tip.hidden = false;
    this.tipItem = d;
    this.tipEvent = { clientX: e.clientX, clientY: e.clientY, target: e.target };
    // Below and right of the pointer; flipped when it would leave the window (it may overflow the card).
    const box = this.el.getBoundingClientRect();
    const tw = this.tip.offsetWidth;
    const th = this.tip.offsetHeight;
    const vw = document.documentElement.clientWidth;
    const vh = document.documentElement.clientHeight;
    let x = e.clientX + 14;
    let y = e.clientY + 16;
    if (x + tw > vw - 8) x = e.clientX - tw - 14;
    if (y + th > vh - 8) y = e.clientY - th - 12;
    this.tip.style.left = `${Math.max(8, x) - box.left}px`;
    this.tip.style.top = `${Math.max(8, y) - box.top}px`;
    return { title, rows };
  }

  _hideTip() {
    this.tip.hidden = true;
    this.tipItem = null;
    this.tipEvent = null;
    this.tipSource = null;
  }
}
