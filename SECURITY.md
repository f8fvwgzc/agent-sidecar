# Security policy

agent-sidecar governs what AI agents may do, so security reports matter a lot to this project.

## Supported versions

The project is a `v1alpha1` MVP. Only the latest commit on `main` gets fixes. It is not production-ready yet. See the known limitations in [docs/operations.md](docs/operations.md#known-limitations).

## Report a vulnerability

Please do **not** open a public issue for a security problem.

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**, or go to <https://github.com/f8fvwgzc/agent-sidecar/security/advisories/new>.

Please include:

- what an attacker can do, for example get around an authz rule, a guardrail or a budget, or read data from the audit log;
- the charter and the requests that show it;
- the commit you tested.

You should get a first answer within 7 days. A fix and an advisory follow once the problem is confirmed.

## Scope

In scope: the sidecar (`agentscd`), the runtime (`agentsc-runtime`), the CA (`embassy`), the CLI (`agentsc`), the charter validation and the Kubernetes manifests in `deploy/`.

Already known limitations listed in [docs/operations.md](docs/operations.md#known-limitations) and in [CONTRACT.md section 11](CONTRACT.md#11-known-gaps-mvp) are not new vulnerabilities. A report that shows a consequence the docs do not mention is welcome.
