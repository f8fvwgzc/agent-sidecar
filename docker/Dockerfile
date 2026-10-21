# One set of binaries, two images (CONTRACT.md §7, docs/design/agent-platform.md §13-§14):
#   docker build -f docker/Dockerfile --target agentscd -t agentsc/agentscd:dev .
#   docker build -f docker/Dockerfile --target embassy  -t agentsc/embassy:dev  .
#
# BINARIES=source (default) compiles agentscd, agentsc and embassy here. BINARIES=prebuilt copies
# them from dist/linux-<arch>/ instead; the release workflow uses it so multi-arch images need no
# emulated Rust build. The build context is the repository root, filtered by
# docker/Dockerfile.dockerignore (an allowlist).
ARG BINARIES=source

FROM rust:1.99-bookworm AS binaries-source
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY proto proto
COPY crates crates
COPY services services
COPY schemas schemas
COPY examples/charters examples/charters
COPY deploy/crds deploy/crds
COPY docs/api docs/api
# embassy embeds the console (ui/) at compile time. The UI has no build step: the files are served
# as they are, so the context only has to contain them.
COPY ui ui
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,id=agentsc-target-${TARGETARCH} \
    cargo build --release --locked -p agentscd -p agentsc-cli -p embassy \
    && mkdir -p /out && cp target/release/agentscd target/release/agentsc target/release/embassy /out/

FROM scratch AS binaries-prebuilt
ARG TARGETARCH
COPY --chmod=0755 dist/linux-${TARGETARCH}/agentscd dist/linux-${TARGETARCH}/agentsc dist/linux-${TARGETARCH}/embassy /out/

# hadolint ignore=DL3006
FROM binaries-${BINARIES} AS binaries

# ---------------------------------------------------------------------------------------------
# agentscd: the sidecar binary plus the Python agent runtime it spawns (CONTRACT.md §2, §7).
# In managed mode it keeps its key, certificate, CA and last charter in /run/agentsc/state
# (--state-dir default <socket-dir>/state), which is writable by the non-root user.
FROM python:3.12-slim-bookworm AS agentscd
LABEL org.opencontainers.image.title="agentscd" \
      org.opencontainers.image.description="agent-sidecar sidecar (agentscd) with the agentsc agent runtime" \
      org.opencontainers.image.source="https://github.com/f8fvwgzc/agent-sidecar" \
      org.opencontainers.image.licenses="MIT"
COPY --from=ghcr.io/astral-sh/uv:0.10.12 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app/runtime
COPY runtime/pyproject.toml runtime/uv.lock runtime/README.md ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-install-project
COPY runtime/src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-editable
COPY --from=binaries /out/agentscd /out/agentsc /usr/local/bin/
COPY --chmod=0755 docker/agentsc-ready /usr/local/bin/agentsc-ready
RUN groupadd --gid 10001 agentsc && useradd --uid 10001 --gid 10001 --create-home agentsc \
    && install -d -o 10001 -g 10001 -m 0755 /run/agentsc /var/log/agentsc \
    && install -d -o 10001 -g 10001 -m 0700 /run/agentsc/state
ENV PATH=/app/.venv/bin:$PATH AGENTSC_RUNTIME_CMD=agentsc-runtime RUST_LOG=info
USER 10001:10001
EXPOSE 3500 50001 50002
ENTRYPOINT ["agentscd"]

# ---------------------------------------------------------------------------------------------
# embassy: the control plane. `docker run agentsc/embassy:dev` runs `embassy serve` (the default
# arguments); any other arguments replace them (`token create ...`, `ca-init ...`, `bootstrap ...`).
# /var/lib/agentsc (file store, CA directory) and /agentsc-ca (the public CA copy that Docker
# Compose shares with the sidecars) belong to the non-root user, so named volumes mounted there
# start out writable.
FROM debian:bookworm-slim AS embassy
LABEL org.opencontainers.image.title="embassy" \
      org.opencontainers.image.description="agent-sidecar control plane: CA, admission webhooks, Connect, REST API and console" \
      org.opencontainers.image.source="https://github.com/f8fvwgzc/agent-sidecar" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 embassy \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/agentsc --shell /usr/sbin/nologin embassy \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/agentsc \
    && install -d -o 10001 -g 10001 -m 0755 /agentsc-ca
COPY --from=binaries /out/embassy /usr/local/bin/embassy
COPY --chmod=0755 docker/agentsc-http-ready /usr/local/bin/agentsc-http-ready
USER 10001:10001
EXPOSE 8080 9443 15012
ENTRYPOINT ["embassy"]
CMD ["serve"]
