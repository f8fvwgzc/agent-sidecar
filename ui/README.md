# agentsc console (`ui/`)

The node-graph console of design §11 (`docs/design/agent-platform.md`). Static files, no build step.
The console only shows what a real control plane returns: it talks to the REST/SSE API under
`api/v1` (`docs/api/openapi.yaml`) of the `embassy serve` that serves the page. There is no demo,
offline or sample-data mode.

## Serving it

`embassy serve` embeds these files and serves them with the `ui` component, next to the `api`
component, on `--http-addr` (default `127.0.0.1:8080`). During development, serve them from disk
instead of the embedded copy, so an edit here shows on reload, against a real control plane:

```bash
embassy serve --ui-dir ui --dev ...   # plus your --store, --ca-dir/--tls-dir and --config flags (design §8.1)
```

then open `http://127.0.0.1:8080/` and sign in with a token (`embassy token create`; with `--dev`
a one-time admin token is written to a 0600 file).

Opened anywhere else (a plain static server, a stopped control plane), the console says
**Cannot reach the control plane at `<origin>/api/v1` — start embassy serve** and offers Retry;
when the API answers 401 it shows the sign-in screen. With a control plane and nothing connected
yet, the graph says **No services connected yet**; the timeline's run list says **No runs yet**.

| Path | What it is |
| --- | --- |
| `index.html`, `styles.css`, `favicon.svg` | the page; no inline script or style (CSP `script-src 'self'; style-src 'self'`) |
| `vendor/d3.v7.9.0.min.js` | d3, a classic script loaded before `js/main.js`; modules use `globalThis.d3`; pinned in `vendor/SHA256SUMS` |
| `js/main.js` | boot, sign-in, toolbar, filters, adoption banner, live stream |
| `js/api.js` | API client (CSRF header, JSON, quoted `If-Match`, session cookie) and the SSE stream (`EventSource api/v1/events`) |
| `js/graph.js` | canvas: zoom/pan, frames, node cards, ports, edges, live dots, drag-to-link |
| `js/geometry.js`, `js/layout.js` | card and port geometry, edge routing, auto-layout (pure) |
| `js/inspector.js`, `js/tab-*.js` | the inspector drawer: Config, Traffic, Learning, YAML, Instances, Overview |
| `js/dialogs.js` | + Agent, link and adoption dialogs |
| `js/timeline/`, `timeline.css` | the agent timeline view (design §11.1, `mountTimeline`): `GET /traces`, `GET /traces/{id}`, SSE `span_start` and `audit`; the toolbar's Graph \| Timeline switch that mounts it is not wired yet |
| `js/util.js`, `js/dom.js`, `js/forms.js`, `js/store.js` | helpers; `dom.js` builds DOM with text nodes only |

Untrusted text only reaches the page through `textContent` / d3 `.text()`; JSON payloads are
`JSON.stringify`-ed into `<pre>`. `tests/check_ui.py` enforces this (and the vendor hashes).

`#node=<node id>&tab=<tab>` opens the inspector on a node.

## Accepted deviations from §11

- **Backward edges.** An edge whose target port is left of its source port (a call back to an
  agent stacked above or to an earlier column) is not one cubic Bézier: a single curve between
  those ports always cuts through the two cards. It leaves the source port to the right, runs
  through the gap between the cards (or below both) and enters the target port from the left,
  with rounded corners (`geometry.edgePath`). Forward edges are the cubic Bézier of §11.
- **Frame title room.** A service frame is the bounding box of its cards plus 24 px on the left,
  right and bottom, and 24 + 26 px on top, so the service name, status and version never sit on a
  card (`geometry.frameRect`).

## Tests

```bash
python3 -I ui/tests/check_ui.py            # forbidden APIs, markup, imports, vendor hashes; then the node tests
python3 -I ui/tests/check_ui.py --no-node  # static checks only
python3 -I ui/tests/check_timeline.py      # security grep over ui/js/timeline
node --test ui/tests/*.test.mjs            # unit tests of the pure modules, inputs inline (Node 22.7+)
```
