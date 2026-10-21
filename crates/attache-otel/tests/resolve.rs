//! `OtelConfig::resolve`: every branch of the endpoint rule (design §9), the flags, headers and
//! resource attributes.
use attache_charter::TelemetrySpec;
use attache_otel::OtelConfig;
use std::collections::HashMap;

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |name: &str| map.get(name).cloned()
}

fn telemetry(endpoint: Option<&str>) -> TelemetrySpec {
    TelemetrySpec {
        otlp_endpoint: endpoint.map(str::to_string),
        ..TelemetrySpec::default()
    }
}

fn resource() -> Vec<(String, String)> {
    vec![
        ("service.name".into(), "orders".into()),
        ("service.namespace".into(), "shop".into()),
        ("service.version".into(), "0.2.0".into()),
        (
            "attache.identity".into(),
            "spiffe://attache/ns/shop/svc/orders".into(),
        ),
    ]
}

fn globs(g: &[&str]) -> Vec<String> {
    g.iter().map(|s| s.to_string()).collect()
}

const HEADERS: &str = "authorization=Bearer%20s3cret,x-tenant=shop";

#[test]
fn env_endpoint_wins_and_gets_env_headers() {
    let t = telemetry(Some("http://charter-collector:4318"));
    let c = OtelConfig::resolve(
        Some(&t),
        env(&[
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "https://otel.example.com:4318/",
            ),
            ("OTEL_EXPORTER_OTLP_HEADERS", HEADERS),
        ]),
        &globs(&["*"]),
        resource(),
    )
    .expect("export on");
    assert_eq!(c.endpoint, "https://otel.example.com:4318");
    assert_eq!(
        c.headers,
        vec![
            ("authorization".to_string(), "Bearer s3cret".to_string()),
            ("x-tenant".to_string(), "shop".to_string()),
        ]
    );
    assert_eq!(c.resource, resource());
    assert!(c.traces && c.metrics && !c.export_payloads);
}

#[test]
fn env_endpoint_needs_no_allow_glob_and_keeps_its_path() {
    let c = OtelConfig::resolve(
        None,
        env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://gateway:8080/otlp/")]),
        &[],
        resource(),
    )
    .expect("export on");
    assert_eq!(c.endpoint, "http://gateway:8080/otlp");
    assert!(c.headers.is_empty());
}

#[test]
fn an_unusable_env_endpoint_turns_export_off_rather_than_falling_back() {
    let t = telemetry(Some("http://otel-collector:4318"));
    for bad in [
        "otel-collector:4318",
        "ftp://otel:21",
        "http://otel:4318?x=1",
        "http://otel:4318#f",
        "not a url",
    ] {
        assert_eq!(
            OtelConfig::resolve(
                Some(&t),
                env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", bad)]),
                &globs(&["*"]),
                resource(),
            ),
            None,
            "{bad}"
        );
    }
}

#[test]
fn an_empty_env_endpoint_counts_as_unset() {
    let t = telemetry(Some("http://otel-collector:4318"));
    let c = OtelConfig::resolve(
        Some(&t),
        env(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "  "),
            ("OTEL_EXPORTER_OTLP_HEADERS", HEADERS),
        ]),
        &globs(&["http://otel-collector:4318"]),
        resource(),
    )
    .expect("charter endpoint");
    assert_eq!(c.endpoint, "http://otel-collector:4318");
    assert!(c.headers.is_empty());
}

#[test]
fn allowed_charter_endpoint_gets_no_env_headers() {
    let t = telemetry(Some("http://otel-collector.observability:4318/"));
    let c = OtelConfig::resolve(
        Some(&t),
        env(&[("OTEL_EXPORTER_OTLP_HEADERS", HEADERS)]),
        &globs(&["https://other:4318", " http://otel-collector.*:4318 "]),
        resource(),
    )
    .expect("allowed");
    assert_eq!(c.endpoint, "http://otel-collector.observability:4318");
    assert!(
        c.headers.is_empty(),
        "env headers must never go to a charter endpoint"
    );
}

#[test]
fn charter_endpoint_not_matching_any_glob_is_refused() {
    let t = telemetry(Some("http://evil.example:4318"));
    assert_eq!(
        OtelConfig::resolve(
            Some(&t),
            env(&[]),
            &globs(&["http://otel-collector.*:4318", "https://*.example.com"]),
            resource(),
        ),
        None
    );
}

#[test]
fn charter_endpoint_with_no_allow_list_is_refused() {
    let t = telemetry(Some("http://otel-collector:4318"));
    assert_eq!(
        OtelConfig::resolve(Some(&t), env(&[]), &[], resource()),
        None
    );
    assert_eq!(
        OtelConfig::resolve(Some(&t), env(&[]), &globs(&["", "  "]), resource()),
        None
    );
}

#[test]
fn charter_endpoint_of_the_wrong_shape_is_refused_even_with_a_catch_all_glob() {
    for bad in [
        "http://user:pw@otel:4318",
        "http://otel:4318/v1/traces",
        "http://otel:4318?x",
        "http:\\\\evil.example",
    ] {
        let t = telemetry(Some(bad));
        assert_eq!(
            OtelConfig::resolve(Some(&t), env(&[]), &globs(&["*"]), resource()),
            None,
            "{bad}"
        );
    }
}

#[test]
fn no_endpoint_anywhere_means_no_export() {
    assert_eq!(
        OtelConfig::resolve(None, env(&[]), &globs(&["*"]), resource()),
        None
    );
    let t = telemetry(None);
    assert_eq!(
        OtelConfig::resolve(Some(&t), env(&[]), &globs(&["*"]), resource()),
        None
    );
}

#[test]
fn traces_and_metrics_both_off_means_no_export() {
    let t = TelemetrySpec {
        traces: false,
        metrics: false,
        ..telemetry(Some("http://otel-collector:4318"))
    };
    assert_eq!(
        OtelConfig::resolve(
            Some(&t),
            env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318")]),
            &globs(&["*"]),
            resource(),
        ),
        None
    );
}

#[test]
fn charter_flags_are_carried() {
    let t = TelemetrySpec {
        traces: false,
        metrics: true,
        export_payloads: true,
        ..telemetry(None)
    };
    let c = OtelConfig::resolve(
        Some(&t),
        env(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318")]),
        &[],
        resource(),
    )
    .expect("export on");
    assert!(!c.traces && c.metrics && c.export_payloads);
}

#[test]
fn env_resource_attributes_are_added_but_never_override() {
    let c = OtelConfig::resolve(
        None,
        env(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel:4318"),
            (
                "OTEL_RESOURCE_ATTRIBUTES",
                "deployment.environment=prod,service.name=spoofed,k8s.pod.name=orders-7d9%2Cx",
            ),
        ]),
        &[],
        resource(),
    )
    .expect("export on");
    let mut expected = resource();
    expected.push(("deployment.environment".into(), "prod".into()));
    expected.push(("k8s.pod.name".into(), "orders-7d9,x".into()));
    assert_eq!(c.resource, expected);
}
