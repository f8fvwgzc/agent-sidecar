# 1. HTTP/3 for the console

Status: implemented (`embassy serve --http3`, Cargo feature `http3`, on by default)
Date: 2026-10-24

## Context

The console (`ui/`) talks to one origin, the control plane that serves it: dozens of small
`GET`s on every graph or service change, a few `PUT`s and `POST`s, and one long-lived SSE
stream (`GET /api/v1/events`) that the console keeps open for as long as the page lives. Until
now that hop was HTTP/1.1, or HTTP/2 behind an operator's own reverse proxy.

Over HTTP/1.1 the browser opens six connections and queues behind them; the SSE stream holds one
for good. Over HTTP/2 one connection carries everything, but a lost packet stalls every stream on
it (TCP head-of-line blocking), which on a laptop on Wi-Fi or a phone on the move shows up as the
whole console freezing for a round trip, SSE included. HTTP/3 (QUIC, RFC 9114) removes that:
streams are independent at the transport, the handshake is one round trip, and a connection
survives the client changing networks.

Nothing else in the system has that profile. `Connect` and `IssueCertificate` are gRPC, which
tonic speaks over HTTP/2 only (there is no gRPC over HTTP/3 in the ecosystem to depend on). The
mesh is gRPC over mTLS between sidecars in one cluster network. The app's hop to its own sidecar
is HTTP/1.1 on loopback, where there is no loss to recover from and no TLS to speed up.

## Decision

`embassy serve --http3` (with `--http-tls`; QUIC is always TLS) adds a QUIC listener on the
address of `--http-addr`, over UDP, next to the TCP listener:

- **Same router, every protocol.** The one `axum::Router` serves HTTP/1.1, HTTP/2 and HTTP/3.
  `serve/http3.rs` reads an HTTP/3 request into an `http::Request` (the body collected up to the
  router's own limit, `api::MAX_BODY`), gives it the peer address as `ConnectInfo<ClientAddr>`
  (the login rate limit reads it), runs the router, and streams the response back frame by
  frame, so the SSE stream works over HTTP/3 as it does over TCP. Nothing in the handlers knows
  which protocol it is on.
- **Discovery by `Alt-Svc`.** Every response of the TCP listener carries
  `Alt-Svc: h3=":<port>"; ma=86400`. The first request of a session is HTTP/1.1 or HTTP/2; the
  browser then moves to QUIC and remembers it for a day. Nothing has to be configured on the
  client and a network that drops UDP costs nothing: the browser stays on TCP.
- **One certificate.** The QUIC endpoint uses the serving certificate's rustls configuration
  with ALPN `h3`. Its certificate resolver reads the current certificate on every handshake, so
  renewals reach QUIC connections exactly as they reach TCP ones.
- **Dependencies.** `quinn` (QUIC, with the `ring` provider the rest of the binary uses) and
  `h3`/`h3-quinn` (HTTP/3 framing). They are behind the Cargo feature `http3`, on by default;
  `--no-default-features` builds an embassy that refuses `--http3` at start-up with a clear
  message.
- **What is deliberately off.** No 0-RTT (early data could replay a `POST`). Connection-specific
  HTTP/1.1 headers (`Connection`, `Transfer-Encoding`, `Keep-Alive`, `Upgrade`) are stripped
  from responses, as HTTP/3 forbids them. The idle timeout is 30 s and a connection may carry
  256 concurrent requests.
- **Helm.** `embassy.http3: true` adds the flag, a UDP container port, a UDP Service port and,
  with the NetworkPolicy on, a UDP ingress rule; it refuses to render without `embassy.httpTLS`.

## Consequences

- An Ingress or load balancer in front of embassy must forward UDP 8080 for browsers to reach
  QUIC. Most HTTP ingress controllers do not; a `LoadBalancer` Service or a UDP-capable proxy
  does. When UDP does not get through the console is exactly as before.
- The serving certificate must be one the browser trusts for QUIC as for TLS over TCP (the same
  requirement `--http-tls` already has).
- `Cargo.lock` gains the QUIC and HTTP/3 crates (and `rusqlite` for ADR 0003). The code was
  first written without compiling, at the author's request, then built, linted and tested in the
  follow-up commit that also regenerated the lock file.
- `curl --http3-only https://<host>:8080/api/v1/healthz` is the smoke test; Chrome's
  `chrome://net-export` or the DevTools protocol column shows `h3` once the switch happened.
- The remaining hops stay where they are for reasons that do not change with this record: gRPC
  has no HTTP/3 transport to depend on, and loopback gains nothing. If reqwest's HTTP/3 client
  leaves its unstable gate, the sidecar's `http` tools could follow without touching policy.

## Alternatives

- **A reverse proxy that terminates HTTP/3** (Caddy, nginx, Envoy) in front of embassy. Works,
  but the control plane is one binary and the chart ships no proxy; it would also hide the client
  address the login rate limit uses and add a hop to the SSE stream. Operators who already run
  such a proxy can keep doing so and leave `--http3` off.
- **HTTP/2 only.** Fixes HTTP/1.1's connection limit, keeps TCP head-of-line blocking, and most
  deployments already got it from `--http-tls`. Not enough on lossy links.
- **A WebSocket or WebTransport channel for events.** A second protocol to secure and operate
  for one stream that SSE over HTTP/3 already serves well.
