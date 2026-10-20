//! The CLI as a user runs it (CONTRACT.md §8).
use std::io::Write;
use std::process::{Command, Stdio};

fn attache() -> Command {
    Command::new(env!("CARGO_BIN_EXE_attache"))
}

fn examples(name: &str) -> String {
    format!(
        "{}/../../examples/charters/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn validate_accepts_the_demo_charters() {
    for f in ["orders.charter.yaml", "inventory.charter.yaml"] {
        let out = attache()
            .args(["charter", "validate", &examples(f)])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{f}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("valid: "));
    }
}

#[test]
fn validate_rejects_an_unknown_field() {
    let out = attache()
        .args([
            "charter",
            "validate",
            &examples("invalid-unknown-field.charter.yaml"),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown field `pii_redaction`"), "{err}");
    assert!(err.contains("guardrails"), "{err}");
}

#[test]
fn schema_is_json_and_closed() {
    let out = attache().args(["charter", "schema"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["additionalProperties"], false,
        "unknown top-level fields are rejected by the schema too"
    );
    assert!(
        v["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "service")
    );
}

#[test]
fn logs_filters_and_sorts_records_from_a_file() {
    let lines = [
        r#"2026-10-20T11:00:00Z INFO attached: not an audit line"#,
        r#"{"ts":"2026-10-20T11:00:02.000Z","kind":"service_call","request_id":"r1","trace_id":"aaaa1111bbbb2222cccc3333dddd4444","span_id":"s2","parent_span_id":null,"service":"inventory","namespace":"attache-demo","agent":"ops-assistant","caller":"spiffe://attache/ns/attache-demo/svc/orders","caller_agent":"ops-assistant","callee":"inventory POST /admin/reset","direction":"inbound","input":null,"output":null,"input_sha256":null,"output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":1,"decision":"deny","rule":"authz.services.deny-admin","reason":"x","error":null}"#,
        r#"{"ts":"2026-10-20T11:00:01.000Z","kind":"agent_invocation","request_id":"r1","trace_id":"aaaa1111bbbb2222cccc3333dddd4444","span_id":"s1","parent_span_id":null,"service":"orders","namespace":"attache-demo","agent":"ops-assistant","caller":"local","caller_agent":null,"callee":"ops-assistant","direction":"inbound","input":"hi","output":"ok","input_sha256":null,"output_sha256":null,"tokens":{"input":10,"output":5},"cost_usd":0.0,"latency_ms":20,"decision":"allow","rule":"authz.callers.local","reason":null,"error":null}"#,
        r#"{"ts":"2026-10-20T11:00:03.000Z","kind":"agent_invocation","request_id":"r2","trace_id":"ffff1111bbbb2222cccc3333dddd4444","span_id":"s3","parent_span_id":null,"service":"orders","namespace":"attache-demo","agent":"order-triage","caller":"local","caller_agent":null,"callee":"order-triage","direction":"inbound","input":"hi","output":"ok","input_sha256":null,"output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":2,"decision":"allow","rule":null,"reason":null,"error":null}"#,
    ];
    let run = |args: &[&str]| -> String {
        let mut child = attache()
            .args(["logs", "--file", "-"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(lines.join("\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let all = run(&[]);
    assert_eq!(all.lines().count(), 3, "{all}");
    assert!(
        all.lines().next().unwrap().contains("agent_invocation"),
        "sorted by ts: {all}"
    );
    let trace = run(&["--trace", "aaaa1111"]);
    assert_eq!(trace.lines().count(), 2);
    let denied = run(&["--denied"]);
    assert_eq!(denied.lines().count(), 1);
    assert!(
        denied.contains("DENY authz.services.deny-admin"),
        "{denied}"
    );
    assert!(denied.contains("svc/orders (ops-assistant)"), "{denied}");
    let agent = run(&["--agent", "order-triage", "--raw"]);
    let v: serde_json::Value = serde_json::from_str(agent.trim()).unwrap();
    assert_eq!(v["agent"], "order-triage");
}
