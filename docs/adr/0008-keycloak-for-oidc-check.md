# 8. The Keycloak that `make oidc-check` signs in through

Status: implemented (#59)
Date: 2026-11-07

## Context

`make oidc-check` (`scripts/oidc-check.sh`) runs a real Keycloak dev realm in Docker, `deploy/keycloak/dev-realm.json`, and signs in to the console through Keycloak's own login form. The script named `quay.io/keycloak/keycloak:26.0`, a moving tag that Keycloak last rebuilt in February 2025. It had never run: Docker pulls on the development machine hung (the CLI's credential helper, found later). That machine has `quay.io/keycloak/keycloak:26.8.1-1`, Keycloak 26.8.1, and little room on Docker Desktop's VM disk for a second Keycloak image.

## Decision

- **The script pins `quay.io/keycloak/keycloak:26.8.1-1@sha256:a78d6b79...`**. This is Keycloak's own immutable rebuild tag of 26.8.1, with the digest quay.io reports for it and the local image carries. A run uses exactly the image that passed, here and in CI. `KEYCLOAK_IMAGE` still overrides it.
- **The check covers the full sign-out.** The console's sign-out sends the browser to Keycloak's end-session endpoint with `client_id` and `post_logout_redirect_uri`, and no `id_token_hint`, because the console keeps no ID token. Keycloak answers with its confirmation page. The script confirms, expects to land back on the console, and expects a new sign-in to show the login form again.
- **The script checks Docker's clock first.** Keycloak stamps the tokens with the clock of Docker's VM, which has lagged the host's after a sleep. A skew of a minute or more fails at once, with that reason, instead of failing as an expired ID token.

## Consequences

- Moving to a newer Keycloak is a deliberate change of one line, with its digest, plus a run of `make oidc-check`.
- The CI job runs the same pinned image, and its first run on GitHub pulls it.

## Alternatives

- **Pull `26.0`** with an empty Docker config. Rejected: a 20-month-old moving tag would test against an older Keycloak than the one deployments meet, and the VM disk had no room to spare.
- **The moving tag `26.8.1`**, which Keycloak rebuilt on 2026-10-31 with another digest. Rejected: a moving tag can change under the check.
