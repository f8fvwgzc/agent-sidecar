# Contributing to agent-sidecar

Thank you for helping. This page explains how to build, test and send a change.

## Before you start

- Read [CONTRACT.md](CONTRACT.md). It is the source of truth for the wire protocol, the charter and the audit record. When the code and CONTRACT.md disagree, the code is wrong. A change that changes behaviour updates CONTRACT.md in the same pull request.
- For a large change, open an issue or a discussion first, so we can agree on the design.
- Security problems go to [SECURITY.md](SECURITY.md), not to a public issue.

## Build and test

You need Rust (`cargo`), `protoc`, `uv`, Go, `python3` and `curl`. See [Getting started](docs/getting-started.md).

```bash
make build-host   # cargo build --workspace and uv sync
make test         # Rust tests and the runtime's pytest suite
make lint         # clippy -D warnings and ruff
cargo fmt --all --check
make validate     # validate the example charters
make local-demo   # end-to-end demo with two sidecars and mTLS
```

If you change a proto file, run `make proto` and commit the regenerated Python stubs. If you change the charter types, run `make schema` and commit `schemas/charter.schema.json`. A test fails when the schema drifts.

## Pull requests

- Keep one topic per pull request.
- Add or update tests for every behaviour change, especially for authz, guardrails, budgets and audit.
- Make sure `make test`, `make lint` and `cargo fmt --all --check` pass.
- Update the docs in `docs/` when you change something a user can see.
- Write the commit message as a short summary line, a blank line, and a body that says why.

## Naming

The project is published as agent-sidecar. The code uses the working name attache (`attached`, `attache`, `embassy`, `attache.io/v1alpha1`). Please keep the code names in code and commands.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
