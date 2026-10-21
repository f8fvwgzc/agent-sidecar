# attache console (`ui/`)

The node-graph console of design §11 (`docs/design/agent-platform.md`). Static files, no build step:
`embassy serve` embeds and serves them (or serves `--ui-dir`), and the console talks to the
REST/SSE API under `api/v1` (`docs/api/openapi.yaml`).

| Path | What it is |
| --- | --- |
| `index.html`, `styles.css`, `favicon.svg` | the page; no inline script or style (CSP `script-src 'self'; style-src 'self'`) |
| `vendor/d3.v7.9.0.min.js` | d3, a classic script loaded before `js/main.js`; modules use `globalThis.d3`; pinned in `vendor/SHA256SUMS` |
| `js/main.js` | boot, sign-in, toolbar, filters, adoption banner, live stream |
| `js/api.js` | API client (CSRF header, JSON, quoted `If-Match`, session cookie) and the SSE stream |
| `js/graph.js` | canvas: zoom/pan, frames, node cards, ports, edges, live dots, drag-to-link |
| `js/geometry.js`, `js/layout.js` | card and port geometry, edge routing, auto-layout (pure) |
| `js/inspector.js`, `js/tab-*.js` | the inspector drawer: Config, Traffic, Learning, YAML, Instances, Overview |
| `js/dialogs.js` | + Agent, link and adoption dialogs |
| `js/fixtures.js`, `js/sse.js` | fixture mode (below) |
| `js/util.js`, `js/dom.js`, `js/forms.js`, `js/store.js` | helpers; `dom.js` builds DOM with text nodes only |

Untrusted text only reaches the page through `textContent` / d3 `.text()`; JSON payloads are
`JSON.stringify`-ed into `<pre>`. `tests/check_ui.py` enforces this (and the vendor hashes).

## Fixture mode

Open `index.html?fixtures=1` from any static server (for example
`python3 -m http.server 8000 --directory ui`). The API answers from `fixtures/`, writes stay in
the tab, and `fixtures/events.sse` is replayed as the live stream (the whole transcript once,
then its traffic every 15 s). Like the control plane (design §3), it keeps memory only for
agents with learning on: approving for an agent without learning is refused, and a save that
turns learning off drops that agent's notes. Extra parameters:

| Parameter | Effect |
| --- | --- |
| `role=viewer\|editor\|admin` | act as that role |
| `payloads=0` | a token without payload visibility |
| `signin=1` | start at the sign-in screen (any well-formed `att_` token signs in) |
| `conflict=1` | the first agent or charter save meets a concurrent edit (409) |
| `scenario=full` | add services in every status, placeholder peers, a mock model, a pending adoption |

`#node=<node id>&tab=<tab>` opens the inspector on a node (in fixture mode and live).

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
node --test ui/tests/logic.test.mjs        # unit tests of the pure modules and the fixture backend (Node 22.7+)
```
