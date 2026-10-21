# Performance and flamegraphs

How to profile the sidecar under load, what the first profile found, and what to look at next.

## Profile it yourself

```bash
brew install oha                      # load generator
PROFILE_TAG=mine scripts/profile.sh   # DURATION=30s CONCURRENCY=32 by default
python3 -I scripts/flame-summary.py .local/profile/mine/orders.folded
```

`scripts/profile.sh` builds `agentscd` with the `profiling` cargo feature (the `profiling` build profile: release code with symbols), starts the platform demo (`scripts/local-platform.sh`) with high budgets so nothing is rate limited, and sends load to the orders sidecar's app API. Every request runs `ops-assistant`, which hands off to `inventory/stock-analyst` over mTLS, so both sidecars, the mesh, the runtime and the control-plane stream are on the path. At shutdown each sidecar writes:

| File | What it is |
| --- | --- |
| `.local/profile/<tag>/orders.svg`, `inventory.svg` | flamegraphs (open in a browser; click to zoom) |
| `.local/profile/<tag>/orders.folded`, `inventory.folded` | folded stacks, read by `scripts/flame-summary.py` |
| `.local/profile/<tag>/load.txt` | oha's throughput and latency summary |

The profiler is `pprof` sampling at 997 Hz. It is compiled in only with `--features profiling` and starts only when `AGENTSC_PROFILE=<prefix>` is set, so release builds carry none of it.

`flame-summary.py` prints the share of samples per subsystem (TLS, gRPC framing, JSON, allocation, regex, the sidecar's own code, …), the hottest frames by self time, and the hottest agent-sidecar functions by inclusive time. `--compare` puts two profiles side by side.

## First profile (22 October 2026)

Setup: Apple silicon Mac (10 cores), the `profiling` build (release code with line tables), mock model, 32 concurrent clients for 30 s, both sidecars on the same machine.

**Finding.** 79% of the orders sidecar's CPU and 76% of the inventory sidecar's was one frame, `Instant::checked_sub`, under `HashMap::retain` in `Runs::prune`. The sidecar keeps every Execute for 120 s after it finishes, so `ReportEvent` and `ProposeLesson` can be checked against it (design §6.5). Every lookup scanned the whole map. At about 1,300 requests per second the map holds about 150,000 entries, and every model call and tool report scanned all of them: quadratic work that grows with traffic.

**Fix.** Finished runs go into a queue in the order they finish; pruning pops only expired entries off its front, so each lookup costs O(1) amortised (`services/agentscd/src/runs.rs`). The audit writer's remembered-secrets map had the same scan on every record; it is now swept at most once per second (`services/agentscd/src/audit.rs`).

**Result.** Same load, same throughput, a quarter of the CPU:

| Sidecar | CPU per request before | after | change |
| --- | --- | --- | --- |
| orders (orchestrator) | 228 µs | 51 µs | 4.5× less |
| inventory (agent) | 237 µs | 60 µs | 4.0× less |

| Load (both runs) | before | after |
| --- | --- | --- |
| requests per second | 1,294 | 1,305 |
| average latency | 24.7 ms | 24.5 ms |
| p99 latency | 50.4 ms | 49.3 ms |
| errors | 0 | 0 |

Throughput did not change because the Python runtime (mock model) is the bottleneck in this setup, not the sidecar. The saving is CPU the sidecar no longer takes from the pod, and, before the fix, CPU that kept growing with traffic.

Where the sidecar's CPU goes now (inventory, share of samples):

| Subsystem | before | after |
| --- | --- | --- |
| agent-sidecar's own code | 78.6% | 12.1% |
| gRPC framing (tonic, prost, h2) | 5.9% | 24.6% |
| allocation | 3.7% | 16.8% |
| JSON (serde_json) | 4.4% | 16.1% |
| HTTP (hyper, axum, reqwest) | 1.9% | 7.5% |
| async runtime (tokio) | 1.4% | 7.2% |
| regex | 1.1% | 4.6% |
| TLS (rustls, ring) | 0.9% | 2.7% |

## What to look at next

The profile is now spread over ordinary work. In order of size:

1. **gRPC framing (about 25–30%).** The runtime makes one unary `ReportEvent` call per model call and per `load_skill`. A client-streaming `ReportEvents` (or batching in the runtime) would cut the per-call framing and HTTP/2 overhead on the unix socket.
2. **JSON (about 16%).** `ReportEvent` carries the audit record as a JSON string: the sidecar parses it, checks it, and serialises it again to write the audit line and to send it to the control plane. Carrying the checked fields in the proto message, or reusing the parsed value for both outputs, removes one round of parsing and one of serialising.
3. **Allocation (about 15%).** Records are cloned for the audit writer, the OTel exporter and the control-plane queue. They already share an `Arc` after writing; the copies happen before. Measure an allocator such as mimalloc before changing code.
4. **Regex (about 5%).** PII redaction runs `replace_all` for each pattern over every payload. A single `RegexSet` pre-check would skip payloads that contain nothing to redact, which is most of them.
