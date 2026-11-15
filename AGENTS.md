# AGENTS.md

Instructions for coding agents working in this repository ([AGENTS.md](https://agents.md) format).
People should start with [CONTRIBUTING.md](CONTRIBUTING.md); this file says the same things in
the order an agent needs them.

## What this is

agent-sidecar (short name in code: agentsc) runs AI agents next to a service, Dapr-style: a Rust
sidecar (`services/agentscd`) enforces policy, taint rules, budgets and audit on every call; a
Python runtime (`runtime/`) runs the model loop; embassy (`services/embassy`) is the control plane
and console API; `ui/` is the console; `services/agentsc-cli` is the `agentsc` CLI. Agents are
declared in a charter (`agentsc.io/v1alpha1`, `crates/agentsc-charter`).

## Ground rules

- [CONTRACT.md](CONTRACT.md) is the source of truth for the wire protocol, the charter and the
  audit record. When code and CONTRACT.md disagree, the code is wrong. A behaviour change updates
  CONTRACT.md in the same change.
- Decisions live in [docs/adr/](docs/adr/README.md); larger designs in `docs/design/`. Read the
  relevant ones before changing that area, and add an ADR for a new decision.
- Security is the product: authz, guardrails, budgets, taint and audit changes need tests, and
  they fail closed.
- A new charter field raises `CHARTER_SCHEMA_LEVEL` (`crates/agentsc-charter/src/lib.rs`), lists
  the field in `level_fields`, and decides its role in `diff.rs` (editor or admin). Tests that pin
  the level move with it.

## Commands

```bash
make build-host            # cargo build --workspace and uv sync
make test                  # Rust tests and the runtime's pytest suite
make lint                  # clippy -D warnings and ruff
cargo fmt --all --check
make validate              # validate the example charters
cargo deny check           # licenses, bans, sources, advisories
```

- After changing a proto file: `make proto`, and keep the regenerated stubs in
  `runtime/src/agentsc_runtime/pb`.
- After changing charter types: `make schema` (or `cargo run -q -p agentsc-cli -- charter schema >
  schemas/charter.schema.json` and `... charter schema --crd > deploy/crds/charters.agentsc.io.yaml`).
  Tests fail when either drifts.
- OTel goldens: `AGENTSC_UPDATE_GOLDEN=1 cargo test -p agentsc-otel`, then review the diff.
- UI logic tests: `node --test ui/tests/logic.test.mjs`.

## Conventions

- Use the short names in code and commands (`agentscd`, `agentsc`, `embassy`).
- Docs and error messages are plain, short sentences that say what happened and what to do.
- Rust follows the workspace's Symposium guidance (`cargo agents sync`); no new dependency without
  `cargo deny check` passing.
- Commit messages: a short summary line, a blank line, and a body that says why.
