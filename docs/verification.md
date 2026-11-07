# Verification status

What has been checked outside the unit and integration tests, where, and what is still open. GitHub Actions cannot run on this repository's account (billing), so the checks below were run by hand on the development machine (macOS, Apple silicon, Docker Desktop). Update this page when a check runs again or a new one is added.

## Container images (#74)

Checked on 2026-11-07, after the Rust 1.99 upgrade.

| Check | Result |
| --- | --- |
| `docker build --ssh default -f docker/Dockerfile --target agentscd` and `--target embassy` (`BINARIES=source`, on `rust:1.99.0-bookworm`, linux/arm64) | both built |
| Both images built with `BINARIES=prebuilt`, the release workflow's path, from the `cargo zigbuild` binaries below, for linux/arm64 and (under emulation) linux/amd64 | built |
| `--version` of `agentscd`, `agentsc`, `embassy`; `agentsc-gateway --help`; `agentsc-runtime --help` in each image | 0.2.0, all start |
| `agentsc charter schema` in the agentscd image against `schemas/charter.schema.json` (charter schema level 8) | byte for byte equal |
| `RUST_BACKTRACE=1 RUST_LIB_BACKTRACE=0`, user `10001:10001` in both images | set |
| `embassy serve` from the image (arm64 and amd64): `/healthz`, `/api/v1/healthz`, `/api/v1/readyz`, `/api/v1/auth/methods`, the console page, `agentsc-http-ready` | 200, ready |

## Kubernetes (#74)

`make demo-helm CLUSTER=kind` and `make e2e-helm CLUSTER=kind` with kind v0.31.0, the four images loaded with `kind load` ([ADR 0007](adr/0007-kind-for-the-real-cluster-checks.md) explains the versions):

| Node image | Kubernetes | ValidatingAdmissionPolicy | `make demo-helm` | `make e2e-helm` |
| --- | --- | --- | --- | --- |
| `kindest/node:v1.34.3` | 1.34.3 | served, rendered | passed | passed (with the 15 s load test) |
| same cluster, chart with `ci/tutela-values.yaml` (the `tutela` section, both Secrets, egress-restricted NetworkPolicy) | 1.34.3 | served, rendered | passed | passed. embassy logged `tutela: agents are principals of tutelad`. kindnet enforced the policy: embassy reached the API server, not inventory's port 50002; sidecars reached port 15012, not 8080 |
| `kindest/node:v1.31.14` (the oldest kind v0.31.0 lists) | 1.31.14 | served, rendered | passed | passed (no load test: Docker disk) |
| `kindest/node:v1.29.14` (kind v0.27.0's image, the chart's `kubeVersion` floor) | 1.29.14 | not served, not rendered | passed | passed (no load test) |

The first runs found faults that tests against a fake API server could not catch. All are fixed (#87, #74):

- The sidecar policy refused every agent pod. Its `request.subResource` rule errored on requests without a subresource.
- The API server's ServiceAccount admission plugin mounted the pod's Kubernetes API token into both injected sidecar containers. The runtime is meant to hold no credential. The policy then refused the pod, and with the sidecar image allow-list on, IssueCertificate would have too. The injector now gives both containers an empty mount at the token's path.
- `make e2e-helm` right after `make demo-helm` read the logs of an old, terminating pod. A re-run of `make demo-helm` after `make e2e-helm` could not apply the charters.

Not checked: Kubernetes 1.30, and any cluster other than kind (a managed cloud cluster, a CNI other than kindnet).

## Release builds (#74)

The release workflow's "Build" and "Package" steps (`.github/workflows/release.yml`, job `binaries`) ran locally with its pinned tools: Rust 1.99.0, zig 0.14.1 (from PyPI's `ziglang`), cargo-zigbuild 0.23.4.

| Target | How | Result |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu.2.28`, cross from macOS | built and packaged; all four binaries need at most `GLIBC_2.28` |
| `aarch64-unknown-linux-gnu` | `cargo zigbuild ... --target aarch64-unknown-linux-gnu.2.28`, cross from macOS | built and packaged; at most `GLIBC_2.28` |
| `aarch64-apple-darwin` | `cargo build --release --locked --target aarch64-apple-darwin`, native | built and packaged |

Only GitHub can run the rest of that workflow: the multi-arch image push to GHCR, the build provenance attestations, and the GitHub release.

## Still open

- **Every GitHub Actions workflow.** CI (`ci.yml`, including the `oidc-check` job), the nightly real-model run, and a tagged release have never run on GitHub. They will run once the account's billing allows Actions again.
