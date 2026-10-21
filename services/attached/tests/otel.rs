//! OpenTelemetry wiring (design §9): an allow-listed charter endpoint gets the sidecar's spans; an
//! endpoint the allow list does not name gets nothing; the exporter starts on the first reload
//! that turns traces or metrics on, takes the flags of later reloads, and flushes on shutdown;
//! `OTEL_EXPORTER_OTLP_ENDPOINT` wins over the charter, with its headers. The environment the
//! sidecar reads `OTEL_*` from is pinned per test (`Config::otel_env`), never the ambient one.
mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use attache_charter::TelemetrySpec;
use axum::Router;
use axum::routing::post;
use common::*;
use serde_json::Value;

#[derive(Clone, Default)]
struct Received {
    traces: Arc<Mutex<Vec<Value>>>,
    /// The `x-collector-auth` header of each trace request.
    auth: Arc<Mutex<Vec<Option<String>>>>,
}

async fn receiver() -> (std::net::SocketAddr, Received) {
    let got = Received::default();
    let g = got.clone();
    let app = Router::new()
        .route(
            "/v1/traces",
            post(
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let g = g.clone();
                    async move {
                        g.auth.lock().unwrap().push(
                            headers
                                .get("x-collector-auth")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string),
                        );
                        g.traces
                            .lock()
                            .unwrap()
                            .push(serde_json::from_slice(&body).unwrap_or(Value::Null));
                        "{}"
                    }
                },
            ),
        )
        .route("/v1/metrics", post(|| async { "{}" }));
    (serve_app(app).await, got)
}

/// Span names received so far, with their `service.name` resource attribute.
fn spans(got: &Received) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for req in got.traces.lock().unwrap().iter() {
        for rs in req["resourceSpans"].as_array().into_iter().flatten() {
            let service = rs["resource"]["attributes"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|a| a["key"] == "service.name")
                .and_then(|a| a["value"]["stringValue"].as_str())
                .unwrap_or("")
                .to_string();
            for ss in rs["scopeSpans"].as_array().into_iter().flatten() {
                for s in ss["spans"].as_array().into_iter().flatten() {
                    out.push((
                        service.clone(),
                        s["name"].as_str().unwrap_or("").to_string(),
                    ));
                }
            }
        }
    }
    out
}

fn telemetry(endpoint: &str, on: bool) -> TelemetrySpec {
    TelemetrySpec {
        otlp_endpoint: Some(endpoint.into()),
        traces: on,
        metrics: on,
        ..Default::default()
    }
}

#[tokio::test]
async fn an_allowed_charter_endpoint_receives_the_spans() {
    let (addr, got) = receiver().await;
    let endpoint = format!("http://{addr}");
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| c.telemetry = Some(telemetry(&endpoint, true)),
        |cfg| cfg.otlp_endpoint_allow = vec!["http://127.0.0.1:*".into()],
    )
    .await;
    assert!(
        rig.sidecar.state.otel.lock().unwrap().is_some(),
        "started with the charter"
    );
    let (status, _) = rig.invoke("ops-assistant", "hello").await;
    assert_eq!(status, 200);
    eventually("the invocation span", || {
        spans(&got)
            .iter()
            .any(|(svc, name)| svc == "orders" && name == "agent_invocation ops-assistant")
    })
    .await;
    // the start-up config record is a span too
    assert!(spans(&got).iter().any(|(_, n)| n.starts_with("config")));
    rig.sidecar.shutdown().await;
}

#[tokio::test]
async fn an_endpoint_the_allow_list_does_not_name_gets_nothing() {
    let (addr, got) = receiver().await;
    let endpoint = format!("http://{addr}");
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| c.telemetry = Some(telemetry(&endpoint, true)),
        |cfg| cfg.otlp_endpoint_allow = vec!["http://otel-collector:4318".into()],
    )
    .await;
    assert!(rig.sidecar.state.otel.lock().unwrap().is_none());
    rig.invoke("ops-assistant", "hello").await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(spans(&got).is_empty());
    rig.sidecar.abort();
}

#[tokio::test]
async fn the_exporter_starts_on_the_reload_that_turns_it_on_and_follows_later_flags() {
    let (addr, got) = receiver().await;
    let endpoint = format!("http://{addr}");
    let off = telemetry(&endpoint, false);
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| c.telemetry = Some(off),
        |cfg| cfg.otlp_endpoint_allow = vec!["http://127.0.0.1:*".into()],
    )
    .await;
    assert!(
        rig.sidecar.state.otel.lock().unwrap().is_none(),
        "both signals off"
    );

    let mut c = orders(&rig.audit);
    c.telemetry = Some(telemetry(&endpoint, true));
    let rec = rig.reload(&c, 2).await;
    assert_eq!(rec["rule"], "config.applied");
    assert!(
        rig.sidecar.state.otel.lock().unwrap().is_some(),
        "started by the reload"
    );
    rig.invoke("ops-assistant", "now traced").await;
    eventually("spans after the reload", || {
        spans(&got)
            .iter()
            .any(|(_, n)| n == "agent_invocation ops-assistant")
    })
    .await;

    // a later reload changes the flags of the running exporter
    let mut c = orders(&rig.audit);
    c.telemetry = Some(TelemetrySpec {
        export_payloads: true,
        metrics: false,
        ..telemetry(&endpoint, true)
    });
    let rec = rig.reload(&c, 3).await;
    assert_eq!(
        rec["input"]["weakened"],
        serde_json::json!(["telemetry.export_payloads"])
    );
    let flags = rig
        .sidecar
        .state
        .otel
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .handle
        .flags();
    assert!(flags.traces && !flags.metrics && flags.export_payloads);

    // shutdown flushes what is pending
    let before = spans(&got).len();
    rig.invoke("ops-assistant", "last one").await;
    let Rig { sidecar, .. } = rig;
    sidecar.shutdown().await;
    assert!(spans(&got).len() > before, "flushed on shutdown");
}

#[tokio::test]
async fn the_environment_endpoint_wins_with_its_headers() {
    let (addr, got) = receiver().await;
    let env = std::collections::BTreeMap::from([
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT".to_string(),
            format!("http://{addr}"),
        ),
        (
            "OTEL_EXPORTER_OTLP_HEADERS".to_string(),
            "x-collector-auth=t0ken".to_string(),
        ),
        (
            "OTEL_RESOURCE_ATTRIBUTES".to_string(),
            "deployment.environment=test".to_string(),
        ),
    ]);
    // the charter names another endpoint, and no allow list is given: the environment decides
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| c.telemetry = Some(telemetry("http://otel-collector:4318", true)),
        move |cfg| cfg.otel_env = Some(env),
    )
    .await;
    assert_eq!(
        rig.sidecar
            .state
            .otel
            .lock()
            .unwrap()
            .as_ref()
            .map(|r| r.config.endpoint.clone()),
        Some(format!("http://{addr}"))
    );
    rig.invoke("ops-assistant", "hello").await;
    eventually("the invocation span", || {
        spans(&got)
            .iter()
            .any(|(_, name)| name == "agent_invocation ops-assistant")
    })
    .await;
    assert!(
        got.auth
            .lock()
            .unwrap()
            .iter()
            .all(|a| a.as_deref() == Some("t0ken"))
    );
    let resource = got.traces.lock().unwrap()[0]["resourceSpans"][0]["resource"].clone();
    assert!(
        resource["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["key"] == "deployment.environment"),
        "{resource}"
    );
    rig.sidecar.shutdown().await;
}
