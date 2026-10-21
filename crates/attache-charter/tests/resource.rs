//! The `Charter` custom resource form (design §4): both forms are read by `from_yaml` and
//! `from_value`; `metadata.name` == `spec.service.name`; the namespace defaults to
//! `metadata.namespace` and must equal it when both are given.
mod common;

use attache_charter::*;
use common::*;
use serde_json::json;

const CR: &str = r#"
apiVersion: attache.io/v1alpha1
kind: Charter
metadata:
  name: inventory
  namespace: attache-demo
spec:
  service:
    name: inventory
    app_port: 8000
  agents:
    - name: stock-analyst
      model: mock
  authz:
    callers: [{identity: local, agents: ["*"]}]
"#;

fn err(text: &str) -> String {
    Charter::from_yaml(text).unwrap_err().to_string()
}

#[test]
fn the_cr_form_is_read_and_takes_the_namespace_from_metadata() {
    let c = Charter::from_yaml(CR).unwrap();
    assert_eq!(c.service.name, "inventory");
    assert_eq!(c.service.namespace, "attache-demo");
    assert_eq!(c.service.app_port, 8000);
    assert_eq!(
        c.spiffe_id(),
        "spiffe://attache/ns/attache-demo/svc/inventory"
    );
    assert_eq!(c.api_version, API_VERSION);
    assert_eq!(c.kind, KIND);
}

#[test]
fn spec_namespace_may_be_given_and_must_match() {
    let same = CR.replace(
        "    name: inventory\n    app_port",
        "    name: inventory\n    namespace: attache-demo\n    app_port",
    );
    assert_eq!(
        Charter::from_yaml(&same).unwrap().service.namespace,
        "attache-demo"
    );
    let other = CR.replace(
        "    name: inventory\n    app_port",
        "    name: inventory\n    namespace: elsewhere\n    app_port",
    );
    assert!(
        err(&other).contains(
            "spec.service.namespace \"elsewhere\" must equal metadata.namespace \"attache-demo\""
        ),
        "{}",
        err(&other)
    );
    // only in spec: fine (a file applied with `kubectl apply -n`)
    let spec_only = same.replace("  namespace: attache-demo\nspec", "spec");
    assert_eq!(
        Charter::from_yaml(&spec_only).unwrap().service.namespace,
        "attache-demo"
    );
    // in neither
    let none = CR.replace("  namespace: attache-demo\n", "");
    assert!(
        err(&none).contains("spec.service.namespace or metadata.namespace is required"),
        "{}",
        err(&none)
    );
}

#[test]
fn metadata_name_must_equal_the_service_name() {
    let other = CR.replace(
        "  name: inventory\n  namespace",
        "  name: stock\n  namespace",
    );
    assert!(
        err(&other).contains("metadata.name \"stock\" must equal spec.service.name \"inventory\""),
        "{}",
        err(&other)
    );
    let missing = CR.replace("  name: inventory\n  namespace", "  namespace");
    assert!(
        err(&missing).contains("metadata.name is required"),
        "{}",
        err(&missing)
    );
}

#[test]
fn the_cr_form_is_validated_like_the_plain_form() {
    let bad_kind = CR.replace("kind: Charter", "kind: Charta");
    assert!(err(&bad_kind).contains("kind must be Charter"));
    let bad_rule = CR.replace("agents: [\"*\"]", "agents: [ghost]");
    assert!(err(&bad_rule).contains("unknown agent \"ghost\""));
    // unknown fields: in spec (with the path), in spec.service, and at the top
    let unknown = CR.replace("  authz:\n", "  authz:\n    defualt: deny\n");
    let e = err(&unknown);
    assert!(
        e.contains("unknown field `defualt`") && e.contains("spec.authz"),
        "{e}"
    );
    let unknown = CR.replace("    app_port: 8000\n", "    app_port: 8000\n    port: 1\n");
    assert!(err(&unknown).contains("unknown field `port`"));
    assert!(err(&format!("{CR}extra: 1\n")).contains("unknown field `extra`"));
    // apiVersion and kind belong to the resource, not to spec
    let nested = CR.replace("spec:\n", "spec:\n  kind: Charter\n");
    assert!(err(&nested).contains("unknown field `kind`"));
}

#[test]
fn api_server_metadata_and_status_are_accepted() {
    let from_cluster = CR.replace(
        "  namespace: attache-demo\n",
        "  namespace: attache-demo\n  uid: 5f0c-11\n  resourceVersion: \"4711\"\n  generation: 3\n  creationTimestamp: \"2026-10-21T10:00:00Z\"\n  labels: {team: shop}\n  annotations: {attache.io/version: \"7\"}\n  managedFields: [{manager: kubectl, operation: Apply}]\n",
    ) + "status:\n  observedGeneration: 3\n  appliedVersion: \"7\"\n  conditions: [{type: Valid, status: \"True\"}]\n  memory: {version: \"2\", agents: {}}\n";
    let c = Charter::from_yaml(&from_cluster).unwrap();
    assert_eq!(c.service.namespace, "attache-demo");
    let cr: CharterResource = serde_yaml_ng::from_str(&from_cluster).unwrap();
    assert_eq!(cr.metadata.other["generation"], 3);
    assert_eq!(cr.metadata.other["annotations"]["attache.io/version"], "7");
    assert!(cr.status.is_some());
}

#[test]
fn from_value_reads_both_forms() {
    let plain = serde_json::to_value(orders()).unwrap();
    assert_eq!(Charter::from_value(&plain).unwrap(), orders());
    let cr: serde_json::Value = serde_yaml_ng::from_str(CR).unwrap();
    assert_eq!(
        Charter::from_value(&cr).unwrap(),
        Charter::from_yaml(CR).unwrap()
    );
    // the same rules apply
    let mut bad = cr.clone();
    bad["metadata"]["name"] = json!("stock");
    let e = Charter::from_value(&bad).unwrap_err().to_string();
    assert!(e.contains("must equal spec.service.name"), "{e}");
    let mut unknown = plain.clone();
    unknown["guardrails"]["pii_redaction"] = json!(true);
    let e = Charter::from_value(&unknown).unwrap_err().to_string();
    assert!(e.contains("unknown field `pii_redaction`"), "{e}");
    let mut invalid = plain;
    invalid["service"]["name"] = json!("Orders");
    let e = Charter::from_value(&invalid).unwrap_err().to_string();
    assert!(e.contains("not a DNS-1123 label"), "{e}");
}

#[test]
fn to_resource_round_trips() {
    for c in [orders(), Charter::from_yaml(INVENTORY).unwrap(), v02()] {
        let cr = c.to_resource();
        assert_eq!(cr.metadata.name.as_deref(), Some(c.service.name.as_str()));
        assert_eq!(
            cr.metadata.namespace.as_deref(),
            Some(c.service.namespace.as_str())
        );
        assert_eq!(
            cr.spec.service.namespace, None,
            "the namespace lives in metadata"
        );
        assert_eq!(cr.spec.service.service_accounts, c.service.service_accounts);
        let yaml = cr.to_yaml().unwrap();
        assert!(
            yaml.starts_with("apiVersion: attache.io/v1alpha1\nkind: Charter\nmetadata:\n"),
            "{yaml}"
        );
        assert!(!yaml.contains("status"));
        assert_eq!(Charter::from_yaml(&yaml).unwrap(), c);
        assert_eq!(cr.into_charter().unwrap(), c);
    }
}

/// A note text of `chars` characters.
fn notes(chars: usize) -> serde_json::Value {
    let note = "Orders older than 30 days are never refunded. ".repeat(10);
    let n = chars / note.len() + 1;
    let list: Vec<serde_json::Value> = (0..n)
        .map(|i| json!({"id": format!("n{i}"), "text": note, "source": "review"}))
        .collect();
    json!({"version": "9", "agents": {"stock-analyst": list}})
}

#[test]
fn the_size_limit_applies_to_spec_not_to_status() {
    // design §13: embassy keeps the service's memory in status; a full memory must not make a
    // valid resource invalid
    let mut cr: serde_json::Value = serde_yaml_ng::from_str(CR).unwrap();
    cr["status"] = json!({"appliedVersion": "7", "memory": notes(300_000)});
    cr["metadata"]["annotations"] =
        json!({"kubectl.kubernetes.io/last-applied-configuration": "x".repeat(MAX_CHARTER_BYTES)});
    let text = serde_yaml_ng::to_string(&cr).unwrap();
    assert!(
        text.len() > MAX_CHARTER_BYTES + 300_000,
        "{} bytes",
        text.len()
    );
    let expected = Charter::from_yaml(CR).unwrap();
    assert_eq!(Charter::from_yaml(&text).unwrap(), expected);
    assert_eq!(Charter::from_value(&cr).unwrap(), expected);

    // the spec itself is still limited, in both readers
    let mut big = cr.clone();
    big["spec"]["agents"][0]["system"] = json!("s".repeat(31 * 1024));
    for i in 0..9 {
        let mut a = big["spec"]["agents"][0].clone();
        a["name"] = json!(format!("bulk-{i}"));
        big["spec"]["agents"].as_array_mut().unwrap().push(a);
    }
    let e = Charter::from_value(&big).unwrap_err().to_string();
    assert!(
        e.contains("bytes serialized, more than the 262144 allowed"),
        "{e}"
    );
    let e = err(&serde_yaml_ng::to_string(&big).unwrap());
    assert!(
        e.contains("bytes serialized, more than the 262144 allowed"),
        "{e}"
    );

    // a plain charter of the same size as the resource above is refused
    let plain = format!("{ORDERS}\n# {}\n", "x".repeat(MAX_CHARTER_BYTES));
    let e = err(&plain);
    assert!(e.contains("more than the 262144 allowed"), "{e}");
    // and no document is parsed beyond the API server's own limit
    let huge = format!("{CR}\n# {}\n", "x".repeat(MAX_RESOURCE_BYTES));
    let e = err(&huge);
    assert!(
        e.contains(&format!("more than the {MAX_RESOURCE_BYTES} allowed")),
        "{e}"
    );
}

#[test]
fn a_big_resource_is_read_in_any_layout() {
    // `kubectl get -o json` output, minified (one line) and pretty, with a status over 256 KiB
    let mut cr: serde_json::Value = serde_yaml_ng::from_str(CR).unwrap();
    cr["status"] = json!({"memory": notes(300_000)});
    let expected = Charter::from_yaml(CR).unwrap();
    for text in [
        serde_json::to_string(&cr).unwrap(),
        serde_json::to_string_pretty(&cr).unwrap(),
        serde_yaml_ng::to_string(&cr).unwrap(),
    ] {
        assert!(text.len() > MAX_CHARTER_BYTES);
        assert!(resource::may_be_resource_text(&text));
        assert_eq!(Charter::from_yaml(&text).unwrap(), expected);
    }
}

#[test]
fn a_plain_charter_over_the_limit_is_refused_before_it_is_parsed() {
    // not even valid YAML: refused for its size, so the parser never saw it
    let broken = format!("service: [\n{}", "x".repeat(MAX_CHARTER_BYTES));
    assert!(!resource::may_be_resource_text(&broken));
    let e = err(&broken);
    assert!(
        e.contains(&format!(
            "charter is {} bytes, more than the 262144 allowed",
            broken.len()
        )),
        "{e}"
    );
    // a plain charter whose prose happens to read like a key is parsed first, then refused for
    // its size all the same
    let prose = ORDERS.replace(
        "      You are the operations assistant",
        &format!(
            "      The order spec: {}\n      You are the operations assistant",
            "y".repeat(MAX_CHARTER_BYTES)
        ),
    );
    assert!(resource::may_be_resource_text(&prose));
    let e = err(&prose);
    assert!(
        e.contains(&format!(
            "charter is {} bytes, more than the 262144 allowed",
            prose.len()
        )),
        "{e}"
    );
}

#[test]
fn may_be_resource_text_finds_the_keys_in_every_layout() {
    for yes in [
        "spec:\n  service: {}",
        "metadata:\n  name: x",
        "{\"apiVersion\":\"attache.io/v1alpha1\",\"kind\":\"Charter\",\"spec\":{}}",
        "{ \"metadata\" : {} }",
        "{apiVersion: attache.io/v1alpha1, spec: {}}",
        "'spec': {}",
        "? spec\n: {}",
    ] {
        assert!(resource::may_be_resource_text(yes), "{yes:?}");
    }
    for no in [
        ORDERS,
        INVENTORY,
        common::V02,
        "system: a specific inspection of the metadata",
    ] {
        assert!(!resource::may_be_resource_text(no), "{no:?}");
    }
}

/// The charter as a resource (JSON, what the webhook reads), as a resource in YAML, and as plain
/// YAML (`to_yaml`, what embassy pushes and the file store keeps): every reader must come to the
/// same verdict on its size, also when YAML's indented block scalars make the plain text bigger
/// than the JSON.
fn verdicts(c: &Charter) -> [bool; 3] {
    let cr = serde_json::to_value(c.to_resource()).unwrap();
    [
        Charter::from_value(&cr).is_ok(),
        Charter::from_yaml(&c.to_resource().to_yaml().unwrap()).is_ok(),
        Charter::from_yaml(&c.to_yaml().unwrap()).is_ok(),
    ]
}

#[test]
fn every_form_agrees_on_the_size_limit() {
    // one-character lines (each costs 3 bytes in JSON, 6 in YAML) and ordinary prose, grown 1 KiB
    // at a time across the limit
    for line in [
        "x\n",
        "Refund only orders that arrived damaged, and say so.\n",
    ] {
        let chunk = line.repeat(1024 / line.len());
        let mut c = Charter::from_yaml(CR).unwrap();
        let (mut accepted, mut refused) = (0, 0);
        while refused < 3 {
            let full = c.agents.last().is_none_or(|a| {
                !a.name.starts_with("bulk-") || a.system.len() + chunk.len() > MAX_SYSTEM_BYTES
            });
            if full {
                let mut a = c.agents[0].clone();
                a.name = format!("bulk-{}", c.agents.len());
                a.system.clear();
                c.agents.push(a);
            }
            c.agents.last_mut().unwrap().system.push_str(&chunk);
            let yaml = c.to_yaml().unwrap().len();
            let [by_value, by_cr_yaml, by_plain_yaml] = verdicts(&c);
            assert_eq!(by_value, by_plain_yaml, "{line:?}: {yaml} bytes as YAML");
            assert_eq!(by_value, by_cr_yaml, "{line:?}: {yaml} bytes as YAML");
            if by_value {
                accepted += 1;
                assert!(yaml <= MAX_CHARTER_BYTES, "{line:?}: {yaml} bytes as YAML");
            } else {
                refused += 1;
            }
        }
        assert!(accepted > 50, "{line:?}: {accepted} accepted");
    }
}

#[test]
fn a_charter_whose_yaml_is_over_the_limit_is_refused_in_every_form() {
    // the verifier's case: the JSON fits (about 3 bytes per line), the plain YAML does not
    let mut c = Charter::from_yaml(CR).unwrap();
    for i in 0..4 {
        let mut a = c.agents[0].clone();
        a.name = format!("bulk-{i}");
        a.system = "x\n".repeat(15 * 1024);
        c.agents.push(a);
    }
    let json = serde_json::to_vec(&c).unwrap().len();
    let yaml = c.to_yaml().unwrap().len();
    assert!(
        json <= MAX_CHARTER_BYTES && yaml > MAX_CHARTER_BYTES,
        "{json} / {yaml}"
    );
    let e = Charter::from_value(&serde_json::to_value(c.to_resource()).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        e.contains(&format!(
            "charter is {yaml} bytes serialized as plain YAML (the form sidecars receive), more \
             than the 262144 allowed"
        )),
        "{e}"
    );
    assert_eq!(verdicts(&c), [false; 3]);
    rejects(&c, "as plain YAML");
}

#[test]
fn a_plain_charter_is_not_mistaken_for_a_resource() {
    assert!(!resource::is_resource(
        &serde_json::to_value(orders()).unwrap()
    ));
    assert!(resource::is_resource(&json!({"metadata": {}})));
    assert!(resource::is_resource(&json!({"spec": {}})));
    assert!(!resource::is_resource(&json!([1])));
}
