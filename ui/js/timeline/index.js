// Agent timeline view (design §11.1): a run list and a run card that plays one run (trace).
//
//   const view = mountTimeline(container, { api, live });
//   view.unmount();                    // or unmountTimeline(container)
//
// `api` is either a source object with listTraces/getTrace/subscribe (see data.js; the console can
// pass one that shares its EventSource) or options for the built-in source ({fixtures, baseUrl,
// fixturesUrl}); without it the source follows the page URL (`?fixtures=1` uses ui/fixtures).
// `live` (default true) subscribes to SSE `span_start` and `audit` events.
//
// The view dispatches, on `container` (bubbling):
//   CustomEvent("attache:open-traffic", {detail: {request_id, trace_id, span_id, kind, agent}})
//     when a segment is clicked (the console opens the inspector Traffic tab for request_id);
//   CustomEvent("attache:select-node", {detail: {node_id}}) when a lane label is clicked.
//
// Keyboard while the view is visible: Space play/pause, R restart; arrows on the playhead.

import { RunCard } from "./card.js";
import { createTimelineSource } from "./data.js";
import {
  TraceModel,
  applyEventToSummary,
  isRootStart,
  normaliseSummary,
  parseTime,
  summaryFromRootStart,
  summaryTitle,
  totalsAt,
} from "./model.js";
import { RunList } from "./runlist.js";
import { agentName, clamp, el, fmtCost, fmtInt, fmtSeconds, statusLabel } from "./util.js";

// A live run's axis starts at about 25 s (plus a margin so the 25 s tick shows) and grows in 10 s
// steps once the run gets longer.
const LIVE_MIN_WINDOW_MS = 26_000;
const FOLLOW_KEY = "attache.timeline.follow.v1";
const MAX_RUNS = 100;

const mounted = new WeakMap();

function readFollow() {
  try {
    return globalThis.localStorage.getItem(FOLLOW_KEY) !== "0";
  } catch {
    return true;
  }
}

function writeFollow(on) {
  try {
    globalThis.localStorage.setItem(FOLLOW_KEY, on ? "1" : "0");
  } catch {
    // storage unavailable: the toggle still works for this page
  }
}

class TimelineView {
  constructor(container, { api, live = true, traceId = null, at = null } = {}) {
    this.container = container;
    this.source = createTimelineSource(api);
    this.live = live !== false;
    this.filter = {};
    this.runs = new Map();
    this.selectedId = null;
    this.initialTrace = traceId;
    this.pendingAt = typeof at === "number" && Number.isFinite(at) ? at : null;
    this.follow = this.initialTrace ? false : readFollow();
    this.model = null;
    this.buffer = null;
    this.loadToken = 0;
    this.pb = { mode: "replay", playing: false, speed: 1, P: 0, lastTs: 0 };
    this.skew = 0;
    this.raf = 0;
    this.destroyed = false;

    this.list = new RunList({
      onSelect: (id) => this.userSelect(id),
      onFollow: (on) => this.setFollow(on),
      follow: this.follow,
    });
    this.card = new RunCard({
      onPlayPause: () => this.playPause(),
      onRestart: () => this.restart(),
      onSpeed: (s) => {
        this.pb.speed = s;
        this.invalidate();
      },
      onSeek: (ms, phase) => this.seek(ms, phase),
      onSeekBy: (delta) => this.seek(this.pb.P + delta, "key"),
      onLive: () => this.goLive(),
      onZoom: () => this.invalidate(),
      onOpenTraffic: (span) => this.emit("attache:open-traffic", { request_id: span.request_id, trace_id: this.selectedId, span_id: span.span_id, kind: span.kind, agent: span.agent }),
      onSelectNode: (nodeId) => this.emit("attache:select-node", { node_id: nodeId }),
    });
    this.root = el("div", { class: "tl-root" }, this.list.el, el("div", { class: "tl-main" }, this.card.el));
    container.append(this.root);

    this.onKey = (e) => this.key(e);
    document.addEventListener("keydown", this.onKey);
    this.listTimer = setInterval(() => {
      for (const r of this.runs.values()) {
        if (r.status === "running") {
          this.renderList();
          break;
        }
      }
    }, 1000);

    const view = this;
    this.handle = {
      unmount: () => this.destroy(),
      selectRun: (id) => this.userSelect(id),
      setFilter: (f) => this.setFilter(f),
      refresh: () => this.refreshList(),
      get selectedRun() {
        return view.selectedId;
      },
    };

    this.card.setMessage("Loading runs…");
    this.refreshList();
    if (this.live && typeof this.source.subscribe === "function") {
      this.unsubscribe = this.source.subscribe((ev) => this.onEvent(ev), { namespace: this.filter.namespace });
    }
  }

  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    cancelAnimationFrame(this.raf);
    clearInterval(this.listTimer);
    clearTimeout(this.refreshTimer);
    if (this.unsubscribe) this.unsubscribe();
    document.removeEventListener("keydown", this.onKey);
    this.card.destroy();
    this.root.remove();
    mounted.delete(this.container);
  }

  emit(name, detail) {
    this.container.dispatchEvent(new CustomEvent(name, { detail, bubbles: true }));
  }

  now() {
    return Date.now() + this.skew;
  }

  observeClock(ts) {
    const d = ts - Date.now();
    if (d > this.skew && d < 300_000) this.skew = d;
  }

  // ---- runs ----------------------------------------------------------------------------------
  async refreshList() {
    let list;
    try {
      list = await this.source.listTraces({ limit: 50, ...this.filter });
    } catch (err) {
      if (this.destroyed) return;
      if (!this.selectedId) this.card.setMessage(err && err.message ? err.message : "Could not load runs.");
      return;
    }
    if (this.destroyed) return;
    const next = new Map();
    for (const s of Array.isArray(list) ? list : []) {
      if (!s || typeof s.trace_id !== "string") continue;
      const prev = this.runs.get(s.trace_id);
      const sum = normaliseSummary(s);
      if (prev) sum.seen = prev.seen;
      next.set(s.trace_id, sum);
    }
    // Keep runs seen live that the list does not have yet.
    const oldest = Math.min(...[...next.values()].map((r) => r.started || Infinity));
    for (const [id, r] of this.runs) if (!next.has(id) && (r.started || 0) >= oldest) next.set(id, r);
    this.runs = next;
    this.trimRuns();
    this.renderList();
    if (!this.selectedId || !this.runs.has(this.selectedId)) {
      const sorted = this.sortedRuns();
      const pick =
        (this.initialTrace && this.runs.has(this.initialTrace) && this.initialTrace) ||
        (sorted.find((r) => r.status === "running") || sorted[0] || {}).trace_id;
      if (pick) this.select(pick);
      else if (!this.selectedId) {
        this.card.setMessage("No runs yet. Runs appear here when an agent is invoked.");
        this.invalidate();
      }
    }
  }

  scheduleListRefresh() {
    clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(() => this.refreshList(), 1500);
  }

  sortedRuns() {
    return [...this.runs.values()].sort((a, b) => (b.started || 0) - (a.started || 0));
  }

  trimRuns() {
    if (this.runs.size <= MAX_RUNS) return;
    for (const r of this.sortedRuns().slice(MAX_RUNS)) if (r.trace_id !== this.selectedId) this.runs.delete(r.trace_id);
  }

  renderList() {
    this.list.render(this.sortedRuns(), this.selectedId, this.follow, this.now());
  }

  setFollow(on) {
    this.follow = on;
    writeFollow(on);
    if (on) {
      const running = this.sortedRuns().find((r) => r.status === "running");
      if (running && running.trace_id !== this.selectedId) this.select(running.trace_id);
    }
    this.renderList();
  }

  setFilter(f) {
    this.filter = { namespace: f && f.namespace, service: f && f.service, agent: f && f.agent };
    this.refreshList();
  }

  matchesFilter(nodeId) {
    const parts = String(nodeId || "").replace(/^agent:/, "").split("/");
    const { namespace, service, agent } = this.filter;
    return (!namespace || parts[0] === namespace) && (!service || parts[1] === service) && (!agent || parts[2] === agent);
  }

  userSelect(id) {
    const newestRunning = this.sortedRuns().find((r) => r.status === "running");
    if (this.follow && (!newestRunning || newestRunning.trace_id !== id)) {
      this.follow = false;
      writeFollow(false);
    }
    this.select(id);
  }

  async select(id) {
    if (!id) return;
    if (id === this.selectedId && (this.model || this.buffer)) return;
    this.selectedId = id;
    const token = (this.loadToken += 1);
    this.model = null;
    this.buffer = [];
    this.card.resetZoom();
    this.card.setMessage("Loading run…");
    this.renderList();
    this.invalidate();
    let doc;
    try {
      doc = await this.source.getTrace(id);
    } catch (err) {
      if (token !== this.loadToken || this.destroyed) return;
      this.buffer = null;
      this.card.setMessage(err && err.message ? err.message : "Could not load the run.");
      this.invalidate();
      return;
    }
    if (token !== this.loadToken || this.destroyed) return;
    const model = new TraceModel(id);
    model.loadSpans(doc && doc.spans);
    for (const ev of this.buffer || []) this.applyToModel(model, ev);
    this.buffer = null;
    this.model = model;
    const d = model.derive();
    this.card.setMessage(d.runStart === null ? "This run has no spans yet." : "");
    if (d.runStart !== null) {
      for (const s of d.spans) this.observeClock(s.end ?? s.start);
      const pb = this.pb;
      pb.lastTs = 0;
      if (d.runEnd === null && this.live) {
        pb.mode = "live";
        pb.playing = true;
      } else {
        pb.mode = "replay";
        pb.playing = false;
        pb.P = d.runEnd !== null ? d.runEnd - d.runStart : Math.max(0, d.lastKnownAt - d.runStart);
      }
      if (this.pendingAt !== null) {
        pb.mode = "replay";
        pb.playing = false;
        pb.P = Math.max(0, this.pendingAt * 1000);
        this.pendingAt = null;
      }
    }
    this.invalidate();
  }

  applyToModel(model, ev) {
    if (ev.type === "span_start") model.applySpanStart(ev.data);
    else if (ev.type === "audit") model.applyAudit(ev.data.record);
  }

  // ---- live events ----------------------------------------------------------------------------
  onEvent(ev) {
    if (this.destroyed || !ev) return;
    if (ev.type === "reset") {
      this.refreshList();
      if (this.selectedId) {
        const id = this.selectedId;
        this.selectedId = null;
        this.select(id);
      }
      return;
    }
    if (ev.type !== "span_start" && ev.type !== "audit") return;
    const data = ev.data;
    const rec = ev.type === "audit" ? data && data.record : data;
    if (!rec || typeof rec.trace_id !== "string") return;
    const ts = parseTime(rec.ts);
    if (ts !== null) this.observeClock(ts);

    let listChanged = false;
    let newRoot = false;
    let sum = this.runs.get(rec.trace_id);
    if (!sum && ev.type === "span_start" && isRootStart(data)) {
      const root = summaryFromRootStart(data);
      if (this.matchesFilter(root.root_agent)) {
        sum = root;
        this.runs.set(rec.trace_id, sum);
        this.trimRuns();
        newRoot = true;
        listChanged = true;
        this.scheduleListRefresh();
      }
    }
    if (sum && applyEventToSummary(sum, ev.type, data)) listChanged = true;

    if (rec.trace_id === this.selectedId) {
      if (this.buffer) this.buffer.push(ev);
      else if (this.model) {
        this.applyToModel(this.model, ev);
        this.invalidate();
      }
    }
    if (newRoot && this.follow) this.select(rec.trace_id);
    if (listChanged) this.renderList();
  }

  // ---- playback -------------------------------------------------------------------------------
  derived() {
    const d = this.model ? this.model.derive() : null;
    return d && d.runStart !== null ? d : null;
  }

  goLive() {
    const d = this.derived();
    if (!d || d.runEnd !== null || !this.live) return;
    this.pb.mode = "live";
    this.pb.playing = true;
    this.invalidate();
  }

  playPause() {
    const d = this.derived();
    if (!d) return;
    const pb = this.pb;
    if (d.runEnd === null) {
      // A running run: Pause freezes the view while data keeps arriving; Play jumps back to live.
      if (pb.mode === "live" || pb.playing) {
        pb.mode = "replay";
        pb.playing = false;
      } else if (this.live) {
        this.goLive();
        return;
      } else {
        pb.playing = true;
        pb.lastTs = 0;
      }
    } else if (pb.playing) {
      pb.playing = false;
    } else {
      if (pb.P >= d.runEnd - d.runStart - 1) pb.P = 0;
      pb.playing = true;
      pb.lastTs = 0;
    }
    this.invalidate();
  }

  restart() {
    if (!this.derived()) return;
    Object.assign(this.pb, { mode: "replay", playing: true, P: 0, lastTs: 0 });
    this.invalidate();
  }

  seek(ms, phase) {
    const d = this.derived();
    if (!d) return;
    const maxP = d.runEnd !== null ? d.runEnd - d.runStart : Math.max(0, this.now() - d.runStart);
    const pb = this.pb;
    pb.P = clamp(ms === Infinity ? maxP : ms, 0, maxP);
    pb.mode = "replay";
    pb.playing = false;
    pb.lastTs = 0;
    if (d.runEnd === null && this.live && (phase === "end" || phase === "key") && pb.P >= maxP - 150) {
      pb.mode = "live";
      pb.playing = true;
    }
    this.invalidate();
  }

  key(e) {
    if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return;
    if (!this.root.isConnected || !this.root.getClientRects().length) return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName || ""))) return;
    if (e.key === " " || e.code === "Space") {
      if (t && t.closest && t.closest("button, a, [role=button], [role=switch], [role=slider]")) return;
      e.preventDefault();
      this.playPause();
    } else if (e.key === "r" || e.key === "R") {
      e.preventDefault();
      this.restart();
    }
  }

  // ---- frames ---------------------------------------------------------------------------------
  invalidate() {
    if (!this.raf && !this.destroyed) this.raf = requestAnimationFrame((ts) => this.frame(ts));
  }

  frame(ts) {
    this.raf = 0;
    if (this.destroyed) return;
    const d = this.derived();
    const sum = this.selectedId ? this.runs.get(this.selectedId) : null;
    if (!d) {
      this.card.renderIdle(sum ? summaryTitle(sum) : "", "");
      return;
    }
    const pb = this.pb;
    const now = this.now();
    const finished = d.runEnd !== null;
    const dur = finished ? d.runEnd - d.runStart : null;
    const liveP = Math.max(0, now - d.runStart);
    const maxP = finished ? dur : liveP;
    if (pb.mode === "live") {
      if (finished) {
        // The run ended while we watched it: show all of it, playhead at the end.
        pb.mode = "replay";
        pb.playing = false;
        pb.P = dur;
        this.card.resetZoom();
      } else {
        pb.P = liveP;
      }
    } else if (pb.playing) {
      // Real time between frames (capped at 1 s, so a tab that was in the background does not jump).
      const dt = pb.lastTs ? Math.min(ts - pb.lastTs, 1000) : 0;
      pb.P += dt * pb.speed;
      if (finished && pb.P >= dur) {
        pb.P = dur;
        pb.playing = false;
      } else if (!finished && pb.P >= liveP) {
        pb.P = liveP;
        if (this.live) pb.mode = "live";
        else pb.playing = false;
      }
    }
    pb.lastTs = pb.playing && pb.mode !== "live" ? ts : 0;
    pb.P = clamp(pb.P, 0, maxP);

    const baseEndMs = finished ? Math.max(1000, dur * 1.04) : Math.max(LIVE_MIN_WINDOW_MS, Math.ceil((liveP * 1.15) / 10_000) * 10_000);
    const totals = totalsAt(d, d.runStart + pb.P);
    const ended = finished && pb.P >= dur - 0.5;
    const title = sum ? summaryTitle(sum) : `${agentName(d.rootLane)} · ${String(this.selectedId).slice(0, 8)}`;
    const statusText = `${statusLabel(ended ? d.status : "running")} · ${fmtSeconds(ended ? dur : pb.P)} · ${fmtInt(totals.tokens)} tokens · ${fmtCost(totals.cost)}`;
    this.card.render({
      derived: d,
      title,
      statusText,
      P: pb.P,
      maxP,
      baseEndMs,
      playing: pb.mode === "live" || pb.playing,
      live: pb.mode === "live",
      running: !finished,
      liveAvailable: this.live,
      speed: pb.speed,
    });
    if (pb.mode === "live" || pb.playing) this.invalidate();
  }
}

/** Mount the timeline view into `container`. Returns {unmount, selectRun, setFilter, refresh, selectedRun}. */
export function mountTimeline(container, options = {}) {
  if (!container) throw new Error("mountTimeline: a container element is required");
  if (mounted.has(container)) mounted.get(container).unmount();
  const view = new TimelineView(container, options);
  mounted.set(container, view.handle);
  return view.handle;
}

export function unmountTimeline(container) {
  const h = mounted.get(container);
  if (h) h.unmount();
}
