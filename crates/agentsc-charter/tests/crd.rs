//! The `charters.agentsc.io` CustomResourceDefinition: in sync with
//! `deploy/crds/charters.agentsc.io.yaml`, structural, and accepting the custom resource form of
//! real charters.
mod common;

use agentsc_charter::crd::{self, crd_yaml, custom_resource_definition};
use agentsc_charter::*;
use common::*;
use serde_json::{Value, json};

const ON_DISK: &str = include_str!("../../../deploy/crds/charters.agentsc.io.yaml");

#[test]
fn the_committed_crd_is_in_sync() {
    assert_eq!(
        ON_DISK,
        crd_yaml(),
        "run `cargo run -q -p agentsc-cli -- charter schema --crd > deploy/crds/charters.agentsc.io.yaml`"
    );
    let parsed: Value = serde_yaml_ng::from_str(ON_DISK).unwrap();
    assert_eq!(parsed, custom_resource_definition());
}

#[test]
fn names_scope_versions_status_and_columns() {
    let crd = custom_resource_definition();
    assert_eq!(crd["apiVersion"], "apiextensions.k8s.io/v1");
    assert_eq!(crd["kind"], "CustomResourceDefinition");
    assert_eq!(crd["metadata"]["name"], "charters.agentsc.io");
    let spec = &crd["spec"];
    assert_eq!(spec["group"], "agentsc.io");
    assert_eq!(spec["scope"], "Namespaced");
    assert_eq!(spec["names"]["kind"], "Charter");
    assert_eq!(spec["names"]["plural"], "charters");
    let versions = spec["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    let v = &versions[0];
    assert_eq!(
        (&v["name"], &v["served"], &v["storage"]),
        (&json!("v1alpha1"), &json!(true), &json!(true))
    );
    assert_eq!(v["subresources"], json!({"status": {}}));
    let columns: Vec<&str> = v["additionalPrinterColumns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(columns, ["Service", "Version", "Valid", "Synced", "Age"]);
    let status = &v["schema"]["openAPIV3Schema"]["properties"]["status"]["properties"];
    for field in [
        "observedGeneration",
        "appliedVersion",
        "conditions",
        "memory",
        "proposals",
    ] {
        assert!(status.get(field).is_some(), "status.{field}");
    }
}

/// Kubernetes' structural-schema rules, as far as they concern what we generate.
fn assert_structural(node: &Value, path: &str) {
    let obj = node
        .as_object()
        .unwrap_or_else(|| panic!("{path}: not an object"));
    for forbidden in [
        "$ref",
        "$defs",
        "$schema",
        "anyOf",
        "oneOf",
        "allOf",
        "not",
        "if",
        "then",
        "else",
        "const",
        "default",
        "uniqueItems",
        "title",
        "examples",
    ] {
        assert!(!obj.contains_key(forbidden), "{path}: has {forbidden}");
    }
    let preserve = obj.get("x-kubernetes-preserve-unknown-fields") == Some(&Value::Bool(true));
    match obj.get("type") {
        Some(Value::String(t)) => assert!(
            ["object", "array", "string", "integer", "number", "boolean"].contains(&t.as_str()),
            "{path}: type {t}"
        ),
        None => assert!(preserve, "{path}: no type and not preserve-unknown-fields"),
        Some(other) => panic!("{path}: type {other}"),
    }
    if let Some(ap) = obj.get("additionalProperties") {
        assert!(
            ap.is_object(),
            "{path}: additionalProperties must be a schema"
        );
        assert!(
            !obj.contains_key("properties"),
            "{path}: properties and additionalProperties"
        );
        assert_structural(ap, &format!("{path}.*"));
    }
    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        for (k, v) in props {
            assert_structural(v, &format!("{path}.{k}"));
        }
    }
    if let Some(items) = obj.get("items") {
        assert_structural(items, &format!("{path}[]"));
    }
}

#[test]
fn the_schema_is_structural() {
    let crd = custom_resource_definition();
    let root = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
    assert_structural(root, "");
    // the free-form tool parameters are kept as written
    let params = &root["properties"]["spec"]["properties"]["agents"]["items"]["properties"]["tools"]
        ["items"]["properties"]["parameters"];
    assert_eq!(params["x-kubernetes-preserve-unknown-fields"], true);
    // Option<T> is nullable; spec.service.namespace is optional in the resource form
    let service = &root["properties"]["spec"]["properties"]["service"];
    assert_eq!(service["required"], json!(["name", "app_port"]));
    assert_eq!(service["properties"]["namespace"]["nullable"], true);
}

/// Every object node of `node` carries `x-kubernetes-preserve-unknown-fields: true`; the paths
/// of those that do not.
fn objects_without_preserve(node: &Value, path: &str, out: &mut Vec<String>) {
    let Some(obj) = node.as_object() else {
        return;
    };
    if obj.get("type") == Some(&json!("object"))
        && obj.get("x-kubernetes-preserve-unknown-fields") != Some(&json!(true))
    {
        out.push(path.to_string());
    }
    if let Some(props) = obj.get("properties").and_then(Value::as_object) {
        for (k, v) in props {
            objects_without_preserve(v, &format!("{path}.{k}"), out);
        }
    }
    if let Some(items) = obj.get("items") {
        objects_without_preserve(items, &format!("{path}[]"), out);
    }
    if let Some(ap) = obj.get("additionalProperties") {
        objects_without_preserve(ap, &format!("{path}.*"), out);
    }
}

#[test]
fn every_object_node_preserves_unknown_fields() {
    // design §13: the API server never prunes, so the validating webhook sees what was written
    let crd = custom_resource_definition();
    let root = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
    let mut missing = Vec::new();
    objects_without_preserve(root, "", &mut missing);
    assert_eq!(
        missing,
        [".metadata"],
        "only the root metadata, where Kubernetes allows nothing but name/generateName rules"
    );
    // the walk does reach nested objects: maps, list items, Option<T>, status
    let spec = &root["properties"]["spec"]["properties"];
    for node in [
        root,
        &root["properties"]["spec"],
        &spec["service"],
        &spec["mesh"],
        &spec["mesh"]["properties"]["peers"],
        &spec["agents"]["items"],
        &spec["agents"]["items"]["properties"]["budgets"],
        &spec["agents"]["items"]["properties"]["harness"],
        &spec["agents"]["items"]["properties"]["learning"],
        &spec["agents"]["items"]["properties"]["tools"]["items"],
        &spec["skills"]["items"],
        &spec["telemetry"],
        &spec["guardrails"]["properties"]["allowed_tools"],
        &spec["guardrails"]["properties"]["input_deny"]["items"],
        &spec["authz"]["properties"]["callers"]["items"],
        &spec["audit"],
        &root["properties"]["status"],
        &root["properties"]["status"]["properties"]["conditions"]["items"],
    ] {
        assert_eq!(node["type"], "object", "{node}");
        assert_eq!(node["x-kubernetes-preserve-unknown-fields"], true, "{node}");
    }
    // the committed file says the same
    let on_disk: Value = serde_yaml_ng::from_str(ON_DISK).unwrap();
    let mut missing = Vec::new();
    objects_without_preserve(
        &on_disk["spec"]["versions"][0]["schema"]["openAPIV3Schema"],
        "",
        &mut missing,
    );
    assert_eq!(missing, [".metadata"]);
}

#[test]
fn structural_conversion_handles_refs_options_enums_and_free_form_values() {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "a": {"$ref": "#/$defs/A", "description": "own text", "default": {"x": 1}},
            "b": {"anyOf": [{"$ref": "#/$defs/A"}, {"type": "null"}]},
            "c": {"type": ["integer", "null"], "format": "uint32", "minimum": 0},
            "d": {"oneOf": [{"type": "string", "const": "x"}, {"type": "string", "const": "y"}]},
            "e": {"description": "anything"},
            "f": true,
            "g": {"type": ["string", "integer"]},
            "h": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            "i": {"type": "array", "uniqueItems": true, "items": {"type": "string"}},
            "j": {"type": "object", "additionalProperties": {"type": "integer"}},
        },
        "$defs": {"A": {"type": "object", "additionalProperties": false, "description": "def text",
                        "properties": {"x": {"type": "integer"}}, "required": ["x"]}},
    });
    let s = crd::structural(&schema);
    let p = &s["properties"];
    // a closed object (`additionalProperties: false`) still keeps unknown fields: the validator,
    // not pruning, rejects them
    assert_eq!(
        p["a"],
        json!({"type": "object", "description": "own text", "properties": {"x": {"type": "integer"}},
               "required": ["x"], "x-kubernetes-preserve-unknown-fields": true})
    );
    assert_eq!(p["b"]["nullable"], true);
    assert_eq!(p["b"]["x-kubernetes-preserve-unknown-fields"], true);
    assert_eq!(p["b"]["properties"]["x"]["type"], "integer");
    assert_eq!(
        p["c"],
        json!({"type": "integer", "nullable": true, "minimum": 0})
    );
    assert_eq!(p["d"], json!({"type": "string", "enum": ["x", "y"]}));
    assert_eq!(
        p["e"],
        json!({"description": "anything", "x-kubernetes-preserve-unknown-fields": true})
    );
    assert_eq!(
        p["f"],
        json!({"x-kubernetes-preserve-unknown-fields": true})
    );
    assert_eq!(
        p["g"],
        json!({"x-kubernetes-preserve-unknown-fields": true})
    );
    assert_eq!(
        p["h"],
        json!({"x-kubernetes-preserve-unknown-fields": true})
    );
    assert_eq!(
        p["i"],
        json!({"type": "array", "items": {"type": "string"}})
    );
    assert_eq!(
        p["j"],
        json!({"type": "object", "additionalProperties": {"type": "integer"},
               "x-kubernetes-preserve-unknown-fields": true})
    );
    assert!(s.get("additionalProperties").is_none());
    assert_eq!(s["x-kubernetes-preserve-unknown-fields"], true);
    // an object with `properties` and a schema for the others keeps them all
    let mixed = crd::structural(
        &json!({"type": "object", "properties": {"x": {"type": "string"}},
                                        "additionalProperties": {"type": "integer"}}),
    );
    assert_eq!(
        mixed,
        json!({"type": "object", "properties": {"x": {"type": "string"}},
               "x-kubernetes-preserve-unknown-fields": true})
    );
    // the flag is for objects only
    assert!(
        crd::structural(&json!({"type": "string", "additionalProperties": true}))
            .get("x-kubernetes-preserve-unknown-fields")
            .is_none()
    );
    let mut missing = Vec::new();
    objects_without_preserve(&s, "", &mut missing);
    assert_eq!(missing, Vec::<String>::new());
    assert_structural(&s, "");
}

/// A small validator for the structural subset the CRD uses: what the API server would check.
fn check(schema: &Value, v: &Value, path: &str, errs: &mut Vec<String>) {
    if v.is_null() {
        if schema.get("nullable") != Some(&Value::Bool(true)) {
            errs.push(format!("{path}: null"));
        }
        return;
    }
    let preserve = schema.get("x-kubernetes-preserve-unknown-fields") == Some(&Value::Bool(true));
    if let Some(Value::Array(allowed)) = schema.get("enum")
        && !allowed.contains(v)
    {
        errs.push(format!("{path}: {v} not in {allowed:?}"));
    }
    match schema.get("type").and_then(Value::as_str) {
        None if preserve => {}
        Some("object") => {
            let Some(o) = v.as_object() else {
                return errs.push(format!("{path}: not an object"));
            };
            for r in schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let r = r.as_str().unwrap();
                if !o.contains_key(r) {
                    errs.push(format!("{path}: missing {r}"));
                }
            }
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                for (k, sub) in o {
                    match props.get(k) {
                        Some(s) => check(s, sub, &format!("{path}.{k}"), errs),
                        None if preserve => {}
                        None => errs.push(format!("{path}.{k}: unknown (would be pruned)")),
                    }
                }
            } else if let Some(ap) = schema.get("additionalProperties") {
                for (k, sub) in o {
                    check(ap, sub, &format!("{path}.{k}"), errs);
                }
            } else if !preserve && !o.is_empty() && path != ".metadata" {
                errs.push(format!("{path}: fields would be pruned"));
            }
        }
        Some("array") => {
            let Some(a) = v.as_array() else {
                return errs.push(format!("{path}: not an array"));
            };
            if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
                && a.len() as u64 > max
            {
                errs.push(format!("{path}: more than {max} items"));
            }
            for (i, item) in a.iter().enumerate() {
                check(&schema["items"], item, &format!("{path}[{i}]"), errs);
            }
        }
        Some("string") => {
            let Some(s) = v.as_str() else {
                return errs.push(format!("{path}: not a string"));
            };
            let n = s.chars().count() as u64;
            if schema
                .get("minLength")
                .and_then(Value::as_u64)
                .is_some_and(|m| n < m)
                || schema
                    .get("maxLength")
                    .and_then(Value::as_u64)
                    .is_some_and(|m| n > m)
            {
                errs.push(format!("{path}: length {n}"));
            }
            if let Some(p) = schema.get("pattern").and_then(Value::as_str)
                && !regex::Regex::new(p).unwrap().is_match(s)
            {
                errs.push(format!("{path}: {s:?} does not match {p}"));
            }
        }
        Some("integer") => {
            let Some(n) = v.as_i64() else {
                return errs.push(format!("{path}: not an integer"));
            };
            if schema
                .get("minimum")
                .and_then(Value::as_i64)
                .is_some_and(|m| n < m)
                || schema
                    .get("maximum")
                    .and_then(Value::as_i64)
                    .is_some_and(|m| n > m)
            {
                errs.push(format!("{path}: {n} out of range"));
            }
        }
        Some("number") if v.is_number() => {}
        Some("boolean") if v.is_boolean() => {}
        other => errs.push(format!("{path}: {v} is not {other:?}")),
    }
}

fn errors(resource: &Value) -> Vec<String> {
    let crd = custom_resource_definition();
    let root = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
    let mut errs = Vec::new();
    check(root, resource, "", &mut errs);
    errs
}

#[test]
fn real_charters_in_resource_form_pass_the_crd_schema() {
    for c in [orders(), Charter::from_yaml(INVENTORY).unwrap(), v02()] {
        let cr = serde_json::to_value(c.to_resource()).unwrap();
        assert_eq!(errors(&cr), Vec::<String>::new(), "{}", c.service.name);
    }
    // and what the schema can see is refused
    let mut cr = serde_json::to_value(v02().to_resource()).unwrap();
    cr["spec"]["agents"][0]["harness"]["max_retries"] = json!(11);
    cr["spec"]["agents"][0]["learning"]["mode"] = json!("always");
    cr["spec"]["skills"][0]["name"] = json!("Refund_Policy");
    cr["spec"]["telemetry"]["otlp_endpoint"] = json!("http://otel:4318/v1/traces");
    cr["spec"]["service"]["app_port"] = json!("8000");
    cr["spec"]["guardrails"]["pii_redaction"] = json!(true);
    let errs = errors(&cr).join("\n");
    for needle in [
        "harness.max_retries: 11 out of range",
        "learning.mode: \"always\" not in",
        "skills[0].name: \"Refund_Policy\" does not match",
        "otlp_endpoint: \"http://otel:4318/v1/traces\" does not match",
        "service.app_port: not an integer",
    ] {
        assert!(errs.contains(needle), "{needle} in:\n{errs}");
    }
}

#[test]
fn unknown_fields_reach_the_validator_instead_of_being_pruned() {
    // anywhere in the resource: the schema keeps them (no "would be pruned"), the validator
    // behind the webhook refuses them with their path
    for (at, field) in [
        ("/spec/guardrails", "pii_redaction"),
        ("/spec/agents/0/learning", "auto_approve"),
        ("/spec/agents/0/tools/0", "timeout"),
        ("/spec/skills/0", "version"),
        ("/spec/service", "replicas"),
        ("/spec", "agent"),
        ("", "specs"),
    ] {
        let mut cr = serde_json::to_value(v02().to_resource()).unwrap();
        cr.pointer_mut(at)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.into(), json!(true));
        assert_eq!(errors(&cr), Vec::<String>::new(), "{at}/{field} is kept");
        let err = Charter::from_value(&cr).unwrap_err().to_string();
        assert!(
            err.contains(&format!("unknown field `{field}`")),
            "{at}: {err}"
        );
    }
    // status is embassy's and free-form below its declared fields
    let mut cr = serde_json::to_value(v02().to_resource()).unwrap();
    cr["status"] = json!({"appliedVersion": "3", "lastPush": "x",
                          "conditions": [{"type": "Valid", "status": "True", "extra": 1}]});
    assert_eq!(errors(&cr), Vec::<String>::new());
    Charter::from_value(&cr).unwrap();
}

#[test]
fn charter_spec_has_exactly_the_charter_fields() {
    let props = |v: Value| -> Vec<String> {
        let mut keys: Vec<String> = v["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    };
    let charter = props(json_schema());
    let spec = props(serde_json::to_value(schemars::schema_for!(CharterSpec)).unwrap());
    let mut expected: Vec<String> = charter
        .into_iter()
        .filter(|k| k != "apiVersion" && k != "kind")
        .collect();
    expected.sort();
    assert_eq!(spec, expected);
}
