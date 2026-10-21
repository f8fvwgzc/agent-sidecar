// The run list (design §11.1): recent runs, newest first, updated live, with "Follow latest".

import { summaryTitle } from "./model.js";
import { el, fmtCompact, fmtSeconds, statusLabel } from "./util.js";

export class RunList {
  constructor({ onSelect, onFollow, follow = true }) {
    this.onSelect = onSelect;
    this.countEl = el("span", { class: "tl-runs-count" });
    this.followBtn = el(
      "button",
      { type: "button", class: "tl-follow", role: "switch", "aria-checked": follow ? "true" : "false" },
      el("span", { class: "tl-switch", "aria-hidden": "true" }, el("span", { class: "tl-switch-knob" })),
      el("span", { text: "Follow latest" }),
    );
    this.followBtn.addEventListener("click", () => onFollow(this.followBtn.getAttribute("aria-checked") !== "true"));
    this.listEl = el("ul", { class: "tl-runlist", "aria-label": "Runs" });
    this.emptyEl = el("p", { class: "tl-runs-empty", text: "No runs yet. A run appears here when an agent is invoked." });
    this.el = el(
      "aside",
      { class: "tl-runs", "aria-label": "Runs" },
      el("div", { class: "tl-runs-head" }, el("h2", { class: "tl-runs-title" }, "Runs ", this.countEl), this.followBtn),
      this.listEl,
      this.emptyEl,
    );
    this.rows = new Map();
  }

  render(runs, selectedId, follow, now) {
    this.followBtn.setAttribute("aria-checked", follow ? "true" : "false");
    this.countEl.textContent = runs.length ? String(runs.length) : "";
    this.emptyEl.hidden = runs.length > 0;
    const keep = new Set();
    let prev = null;
    for (const run of runs) {
      keep.add(run.trace_id);
      let row = this.rows.get(run.trace_id);
      if (!row) {
        row = this._row(run.trace_id);
        this.rows.set(run.trace_id, row);
      }
      this._update(row, run, run.trace_id === selectedId, now);
      const expected = prev ? prev.li.nextSibling : this.listEl.firstChild;
      if (expected !== row.li) {
        if (prev) prev.li.after(row.li);
        else this.listEl.prepend(row.li);
      }
      prev = row;
    }
    for (const [id, row] of this.rows) {
      if (!keep.has(id)) {
        row.li.remove();
        this.rows.delete(id);
      }
    }
  }

  _row(traceId) {
    const dot = el("span", { class: "tl-run-dot", "aria-hidden": "true" });
    const title = el("span", { class: "tl-run-title" });
    const meta = el("span", { class: "tl-run-meta" });
    const btn = el("button", { type: "button", class: "tl-run" }, dot, el("span", { class: "tl-run-body" }, title, meta));
    btn.addEventListener("click", () => this.onSelect(traceId));
    const li = el("li", {}, btn);
    return { li, btn, dot, title, meta, sig: "" };
  }

  _update(row, run, selected, now) {
    const tokens = run.tokens_in + run.tokens_out;
    const elapsed = run.status === "running" ? Math.max(0, now - (run.started || now)) : run.duration_ms || 0;
    const title = summaryTitle(run);
    const meta = `${statusLabel(run.status)} · ${fmtSeconds(elapsed)} · ${fmtCompact(tokens)} tokens`;
    const sig = `${title}|${meta}|${run.status}|${selected}`;
    if (row.sig === sig) return;
    row.sig = sig;
    row.title.textContent = title;
    row.meta.textContent = meta;
    row.btn.title = title;
    row.dot.className = `tl-run-dot is-${run.status}`;
    row.btn.classList.toggle("is-selected", selected);
    if (selected) row.btn.setAttribute("aria-current", "true");
    else row.btn.removeAttribute("aria-current");
    row.btn.setAttribute("aria-label", `${title}. ${meta}`);
  }
}
