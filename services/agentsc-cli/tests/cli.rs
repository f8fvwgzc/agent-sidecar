//! The CLI as a user runs it (CONTRACT.md §8).
use std::io::Write;
use std::process::{Command, Stdio};

fn agentsc() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentsc"))
}

fn examples(name: &str) -> String {
    format!(
        "{}/../../examples/charters/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn validate_accepts_the_demo_charters() {
    for f in [
        "orders.charter.yaml",
        "inventory.charter.yaml",
        "support.charter.yaml",
    ] {
        let out = agentsc()
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
    let out = agentsc()
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
    let out = agentsc().args(["charter", "schema"]).output().unwrap();
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
fn schema_crd_prints_the_committed_crd() {
    let out = agentsc()
        .args(["charter", "schema", "--crd"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let on_disk = std::fs::read_to_string(format!(
        "{}/../../deploy/crds/charters.agentsc.io.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        on_disk,
        "run `cargo run -q -p agentsc-cli -- charter schema --crd > deploy/crds/charters.agentsc.io.yaml`"
    );
}

#[test]
fn to_cr_prints_a_resource_that_validates() {
    let out = agentsc()
        .args(["charter", "to-cr", &examples("orders.charter.yaml")])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let cr: serde_json::Value = serde_yaml_ng::from_str(&text).unwrap();
    assert_eq!(cr["apiVersion"], "agentsc.io/v1alpha1");
    assert_eq!(cr["kind"], "Charter");
    assert_eq!(cr["metadata"]["name"], "orders");
    assert_eq!(cr["metadata"]["namespace"], "agentsc-demo");
    assert_eq!(cr["spec"]["service"]["name"], "orders");
    assert!(cr["spec"]["service"].get("namespace").is_none());
    assert!(cr["spec"].get("apiVersion").is_none());
    // `charter validate` reads the resource form, and to-cr of it is the same document
    let dir = std::env::temp_dir().join(format!("agentsc-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("orders.cr.yaml");
    std::fs::write(&file, &text).unwrap();
    let out = agentsc()
        .args(["charter", "validate", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("spiffe://agentsc/ns/agentsc-demo/svc/orders")
    );
    let again = agentsc()
        .args(["charter", "to-cr", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(again.stdout).unwrap(), text);
    let _ = std::fs::remove_dir_all(dir);
    // an invalid charter is refused, not converted
    let out = agentsc()
        .args([
            "charter",
            "to-cr",
            &examples("invalid-unknown-field.charter.yaml"),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown field `pii_redaction`"));
}

#[test]
fn logs_keep_and_show_new_and_unknown_kinds() {
    let config = r#"{"ts":"2026-10-21T10:00:00.000Z","kind":"config","request_id":"","trace_id":"","span_id":"","parent_span_id":null,"service":"orders","namespace":"shop","agent":null,"caller":"control-plane","caller_agent":null,"callee":"charter","direction":"internal","input":{"source":"control-plane","epoch":"e1","version":"7","sha256":"ab","weakened":[]},"output":null,"input_sha256":"x","output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":0,"decision":"allow","rule":"config.applied","reason":null,"error":null}"#;
    let learning = r#"{"ts":"2026-10-21T10:00:01.000Z","kind":"learning","request_id":"r9","trace_id":"cccc1111","span_id":"s","parent_span_id":null,"service":"orders","namespace":"shop","agent":"support","caller":"local","caller_agent":null,"callee":"learning","direction":"internal","input":{"request_id_of_run":"r8"},"output":{"note":"n","rationale":"r"},"input_sha256":null,"output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":3,"decision":"deny","rule":"learning.rate_limited","reason":null,"error":null}"#;
    let future = r#"{"ts":"2026-10-21T10:00:02.000Z","kind":"teleport","request_id":"r10","trace_id":"dddd1111","span_id":"s","parent_span_id":null,"service":"orders","namespace":"shop","agent":"support","caller":"local","caller_agent":null,"callee":"mars","direction":"sideways","input":null,"output":null,"input_sha256":null,"output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":1,"decision":"allow","rule":"teleport.ok","reason":null,"error":null,"new_field":1}"#;
    let run = |args: &[&str]| -> String {
        let mut child = agentsc()
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
            .write_all([config, learning, future].join("\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let all = run(&[]);
    let lines: Vec<&str> = all.lines().collect();
    assert_eq!(lines.len(), 3, "{all}");
    assert!(
        lines[0].contains(" config ") && lines[0].contains("allow config.applied"),
        "{all}"
    );
    assert!(
        lines[1].contains(" learning ") && lines[1].contains("DENY learning.rate_limited"),
        "{all}"
    );
    assert!(
        lines[2].contains(" teleport ")
            && lines[2].contains(" sideways ")
            && lines[2].contains("allow teleport.ok"),
        "{all}"
    );
    let only = run(&["--kind", "teleport"]);
    assert_eq!(only.lines().count(), 1, "{only}");
    let only = run(&["--kind", "config", "--raw"]);
    assert_eq!(
        only.trim_end(),
        config,
        "--raw prints the record as written"
    );
    let raw = run(&["--kind", "teleport", "--raw"]);
    assert!(
        raw.contains("\"new_field\":1"),
        "unknown fields survive --raw: {raw}"
    );
}

#[test]
fn logs_filters_and_sorts_records_from_a_file() {
    let lines = [
        r#"2026-10-20T11:00:00Z INFO agentscd: not an audit line"#,
        r#"{"ts":"2026-10-20T11:00:02.000Z","kind":"service_call","request_id":"r1","trace_id":"aaaa1111bbbb2222cccc3333dddd4444","span_id":"s2","parent_span_id":null,"service":"inventory","namespace":"agentsc-demo","agent":"ops-assistant","caller":"spiffe://agentsc/ns/agentsc-demo/svc/orders","caller_agent":"ops-assistant","callee":"inventory POST /admin/reset","direction":"inbound","input":null,"output":null,"input_sha256":null,"output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":1,"decision":"deny","rule":"authz.services.deny-admin","reason":"x","error":null}"#,
        r#"{"ts":"2026-10-20T11:00:01.000Z","kind":"agent_invocation","request_id":"r1","trace_id":"aaaa1111bbbb2222cccc3333dddd4444","span_id":"s1","parent_span_id":null,"service":"orders","namespace":"agentsc-demo","agent":"ops-assistant","caller":"local","caller_agent":null,"callee":"ops-assistant","direction":"inbound","input":"hi","output":"ok","input_sha256":null,"output_sha256":null,"tokens":{"input":10,"output":5},"cost_usd":0.0,"latency_ms":20,"decision":"allow","rule":"authz.callers.local","reason":null,"error":null}"#,
        r#"{"ts":"2026-10-20T11:00:04.000Z","kind":"guardrail","request_id":"r2","trace_id":"ffff1111bbbb2222cccc3333dddd4444","span_id":"s4","parent_span_id":null,"service":"orders","namespace":"agentsc-demo","agent":"order-triage","caller":"local","caller_agent":null,"callee":"issue_refund","direction":"internal","input":null,"output":null,"input_sha256":null,"output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":0,"decision":"allow","rule":"taint.would_deny.untrusted_write","reason":"x","error":null}"#,
        r#"{"ts":"2026-10-20T11:00:03.000Z","kind":"agent_invocation","request_id":"r2","trace_id":"ffff1111bbbb2222cccc3333dddd4444","span_id":"s3","parent_span_id":null,"service":"orders","namespace":"agentsc-demo","agent":"order-triage","caller":"local","caller_agent":null,"callee":"order-triage","direction":"inbound","input":"hi","output":"ok","input_sha256":null,"output_sha256":null,"tokens":null,"cost_usd":null,"latency_ms":2,"decision":"allow","rule":null,"reason":null,"error":null}"#,
    ];
    let run = |args: &[&str]| -> String {
        let mut child = agentsc()
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
    assert_eq!(all.lines().count(), 4, "{all}");
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
    let would = run(&["--rule", "taint.would_deny"]);
    assert_eq!(would.lines().count(), 1, "{would}");
    assert!(
        would.contains("allow taint.would_deny.untrusted_write"),
        "{would}"
    );
    let agent = run(&[
        "--agent",
        "order-triage",
        "--kind",
        "agent_invocation",
        "--raw",
    ]);
    let v: serde_json::Value = serde_json::from_str(agent.trim()).unwrap();
    assert_eq!(v["agent"], "order-triage");
}

#[test]
fn logs_read_records_of_any_version() {
    // tokens with a count this CLI does not know and more than u32 can hold, an unknown field,
    // and a JSON diagnostic that is not a record at all
    let newer = r#"{"ts":"2026-10-21T10:00:03.000Z","kind":"model_call","request_id":"r11","trace_id":"eeee1111","span_id":"s","parent_span_id":null,"service":"orders","namespace":"shop","agent":"support","caller":"local","caller_agent":null,"callee":"anthropic:claude-opus-5-5","direction":"outbound","input":null,"output":null,"input_sha256":null,"output_sha256":null,"tokens":{"input":5000000000,"output":2,"cache_read":7},"cost_usd":1.5,"latency_ms":9,"decision":"allow","rule":null,"reason":null,"error":null,"attempt":"2/3"}"#;
    let diagnostic = r#"{"timestamp":"2026-10-21T10:00:04Z","level":"INFO","fields":{"message":"charter reloaded"}}"#;
    let run = |args: &[&str]| -> String {
        let mut child = agentsc()
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
            .write_all([newer, diagnostic].join("\n").as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let text = run(&[]);
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(
        text.contains("tokens=5000000000/2 $1.5000"),
        "the record is shown: {text}"
    );
    // --raw prints the line as it was read, unknown fields and all
    assert_eq!(run(&["--raw"]).trim_end(), newer);
}

/// A sealed bundle of two entries, the key, and the JWKS, written to `dir`.
fn evidence(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    use agentsc_ledger::*;
    let key = SigningKey::from_seed(&[9u8; 32]);
    let mut entries: Vec<Entry> = Vec::new();
    for kind in ["model_call", "agent_invocation"] {
        let rec = serde_json::json!({"kind": kind, "request_id": "r1", "decision": "allow"});
        let e = Entry::next(entries.last(), "r1", "2026-10-29T10:00:00.000Z", rec);
        entries.push(e);
    }
    let s = seal(&key, "r1", 2, &entries[1].hash, "2026-10-29T10:00:01.000Z");
    let bundle = Bundle {
        format: BUNDLE_FORMAT.into(),
        exported_at: "2026-10-29T10:00:02.000Z".into(),
        chain: "r1".into(),
        entries,
        seals: vec![s],
    };
    let b = dir.join("run-r1.evidence.json");
    std::fs::write(&b, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();
    let k = dir.join("jwks.json");
    let jwks = Jwks {
        keys: vec![key.jwk(KeyStatus::Current)],
    };
    std::fs::write(&k, serde_json::to_string(&jwks).unwrap()).unwrap();
    (b, k, key.jwk(KeyStatus::Current).x)
}

#[test]
fn verify_says_what_holds_and_exits_0_1_or_2() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle, jwks, public) = evidence(dir.path());
    let run = |args: &[&str]| {
        let out = agentsc().args(args).output().unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let b = bundle.to_str().unwrap();
    let (code, out, _) = run(&["verify", b, "--keys", jwks.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("chain r1\n  ok   format"), "{out}");
    assert!(out.ends_with("the bundle verifies\n"), "{out}");
    let (code, out, _) = run(&["verify", b, "--key", &public, "--json"]);
    assert_eq!(code, 0, "{out}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["checks"].as_array().unwrap().len(), 3);

    // a tampered bundle: exit 1, the failing check named
    let text = std::fs::read_to_string(&bundle).unwrap();
    let tampered = dir.path().join("tampered.json");
    std::fs::write(&tampered, text.replace("\"allow\"", "\"deny\"")).unwrap();
    let (code, out, _) = run(&["verify", tampered.to_str().unwrap(), "--key", &public]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("  FAIL chain"), "{out}");
    assert!(out.ends_with("the bundle does NOT verify\n"), "{out}");
    // the wrong key: exit 1, seals
    let other = agentsc_ledger::SigningKey::from_seed(&[1u8; 32])
        .jwk(agentsc_ledger::KeyStatus::Current)
        .x;
    let (code, out, _) = run(&["verify", b, "--key", &other]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("  FAIL seals"), "{out}");
    // unreadable input: exit 2
    let (code, _, err) = run(&["verify", "/nonexistent.json", "--key", &public]);
    assert_eq!(code, 2, "{err}");
    let (code, _, err) = run(&["verify", jwks.to_str().unwrap(), "--key", &public]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("not an evidence bundle"), "{err}");
    let (code, _, err) = run(&["verify", b, "--key", "abcd"]);
    assert_eq!(code, 2, "{err}");
    // stdin
    let mut child = agentsc()
        .args(["verify", "-", "--key", &public])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    assert_eq!(child.wait_with_output().unwrap().status.code(), Some(0));
}
