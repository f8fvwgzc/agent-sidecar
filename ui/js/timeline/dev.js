// Bootstrap for ui/timeline.html, the standalone development page of the timeline view.
//   timeline.html?fixtures=1             golden fixtures, the running run replayed live
//   &trace=<trace id>&t=<seconds>       open one run with the playhead at t (paused)
//   &live=0                             no live events; &loop=0 replays the live run only once

import { mountTimeline } from "./index.js";

const params = new URLSearchParams(globalThis.location.search);
const host = document.getElementById("timeline");
const log = document.getElementById("timeline-events");
const t = params.has("t") ? Number(params.get("t")) : null;

const view = mountTimeline(host, {
  api: params.get("fixtures") === "1" ? { fixtures: true, loop: params.get("loop") !== "0" } : undefined,
  live: params.get("live") !== "0",
  traceId: params.get("trace"),
  at: Number.isFinite(t) ? t : null,
});

for (const name of ["attache:open-traffic", "attache:select-node"]) {
  host.addEventListener(name, (e) => {
    console.info(name, e.detail);
    if (log) log.textContent = `${name} ${JSON.stringify(e.detail)}`;
  });
}

globalThis.attacheTimeline = view;
