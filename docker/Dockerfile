# One Rust build stage, two images:
#   docker build -f docker/Dockerfile --target attached -t attache/attached:dev .
#   docker build -f docker/Dockerfile --target embassy  -t attache/embassy:dev  .

FROM rust:1.99-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY proto proto
COPY crates crates
COPY services services
COPY schemas schemas
COPY examples/charters examples/charters
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release -p attached -p attache-cli -p embassy \
    && mkdir -p /out && cp target/release/attached target/release/attache target/release/embassy /out/

# ---------------------------------------------------------------------------------------------
# attached: the sidecar binary plus the Python agent runtime it spawns (CONTRACT.md §2, §7).
FROM python:3.12-slim-bookworm AS attached
COPY --from=ghcr.io/astral-sh/uv:0.10.12 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app/runtime
COPY runtime/pyproject.toml runtime/uv.lock runtime/README.md ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-install-project
COPY runtime/src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-editable
COPY --from=build /out/attached /out/attache /usr/local/bin/
COPY docker/attache-ready /usr/local/bin/attache-ready
RUN useradd -u 10001 -m attache && mkdir -p /run/attache && chown attache /run/attache && chmod +x /usr/local/bin/attache-ready
ENV PATH=/app/.venv/bin:$PATH ATTACHE_RUNTIME_CMD=attache-runtime RUST_LOG=info
USER 10001
EXPOSE 3500 50001 50002
ENTRYPOINT ["attached"]

# ---------------------------------------------------------------------------------------------
# embassy: the CA. Runs as a Job that writes Secrets through the Kubernetes API.
FROM debian:bookworm-slim AS embassy
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd -u 10001 embassy
COPY --from=build /out/embassy /usr/local/bin/embassy
USER 10001
ENTRYPOINT ["embassy"]
