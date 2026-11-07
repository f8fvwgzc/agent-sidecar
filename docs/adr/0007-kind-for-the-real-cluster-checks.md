# 7. Real-cluster checks on kind, down to the chart's Kubernetes floor

Status: implemented (#74)
Date: 2026-11-07

## Context

The chart declares `kubeVersion: ">=1.29.0-0"`, and embassy talks to the API server through `kube` 5 and `k8s-openapi` 0.29 (the `v1_33` types). Until #74 that code had only met the fake API server of the tests, and the demo targets (`make demo-helm`, `make e2e-helm`) ran only on minikube, through `make build` inside minikube's docker. The development machine has kind v0.31.0. Its release notes list node images for 1.31 to 1.35, and say older versions "may still work". Docker Desktop's VM disk there has about 3 GB to spare, and one kind cluster with the demo images uses about 1.9 GB.

## Decision

- **kind is a second cluster path of the Makefile.** `make demo-helm CLUSTER=kind` creates or reuses the kind cluster `KIND_CLUSTER`, with the node image `KIND_IMAGE`. It builds the four images on the host's docker, or takes them from `SKIP_BUILD=1` or a `docker save` archive (`KIND_ARCHIVE`), and loads them with `kind load`. `KUBE_CONTEXT` becomes `kind-<cluster>`, so `make e2e-helm` follows. minikube stays the default.
- **The versions checked:**
  - `kindest/node:v1.34.3` is the main cluster.
  - `kindest/node:v1.31.14` is the oldest image kind v0.31.0 lists.
  - `kindest/node:v1.29.14` is the chart's floor. kind v0.27.0 lists that image, and it runs under kind v0.31.0. It is also the one version without the ValidatingAdmissionPolicy API, so it checks the chart's other branch.

  Each image is pinned by the digest its release notes give.
- **The floor stays 1.29.** All three versions pass `make demo-helm` and `make e2e-helm` (docs/verification.md). Native sidecars, which the chart needs, are on by default from 1.29.

## Consequences

- The real-cluster checks found faults the fake API server could not show, fixed in #87 and #74. The worst was that the API server's ServiceAccount admission plugin gave the injected runtime the pod's API token, and the sidecar policy then refused every agent pod.
- 1.30 is not checked. kind v0.31.0 lists no 1.30 image, and 1.29 and 1.31 cover both sides of the ValidatingAdmissionPolicy change.
- On this machine the clusters run one at a time, and the images go through an archive on the host disk (`KIND_ARCHIVE`), because Docker's VM disk cannot hold two clusters, or one cluster plus the images twice.

## Alternatives

- **Raise `kubeVersion` to 1.31**, the oldest version kind v0.31.0 lists. Rejected: 1.29 works and is the version where the chart's no-policy branch runs.
- **minikube only.** Rejected for these checks. The development machine runs kind, a kind cluster starts in a minute, and kind takes any Kubernetes version as a node image.
