//! `docs/api/openapi.yaml` is self-consistent: every `$ref` resolves, the SSE event names match
//! the API types, and the schemas, security schemes and headers of design §8 and §10 exist.
//! Real responses are checked against this document by the integration tests, never against
//! recorded example data.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use embassy::api::types::SseEvent;
use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn openapi_document_is_consistent() {
    let path = repo().join("docs/api/openapi.yaml");
    let text = std::fs::read_to_string(&path).expect("openapi.yaml");
    let doc: Value = serde_yaml_ng::from_str(&text).expect("openapi.yaml is YAML");
    assert_eq!(doc["openapi"], "3.1.0");

    fn walk<'a>(v: &'a Value, refs: &mut Vec<&'a str>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    if k == "$ref" {
                        refs.push(x.as_str().expect("$ref is a string"));
                    }
                    walk(x, refs);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, refs)),
            _ => {}
        }
    }
    let mut refs = Vec::new();
    walk(&doc, &mut refs);
    assert!(refs.len() > 100);
    for r in &refs {
        let pointer = r
            .strip_prefix('#')
            .unwrap_or_else(|| panic!("{r} is not local"));
        assert!(doc.pointer(pointer).is_some(), "{r} does not resolve");
    }

    let events: BTreeSet<&str> = doc["paths"]["/events"]["get"]["x-sse-events"]
        .as_object()
        .expect("x-sse-events")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(events, SseEvent::NAMES.into_iter().collect());

    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    for name in [
        "WhoAmI",
        "Graph",
        "ServiceSummary",
        "CharterDoc",
        "AgentView",
        "MemoryDoc",
        "Proposal",
        "AuditRecord",
        "HistoryEntry",
        "Note",
        "NoteInput",
        "MemoryPut",
        "ValidateResult",
        "LinkRequest",
        "LinkResult",
        "PendingAdoption",
        "Instance",
        "Skill",
        "Error",
        "CpAuditRecord",
        "SseEvent",
    ] {
        assert!(
            schemas.contains_key(name),
            "components.schemas.{name} is missing"
        );
    }
    // the audit kinds of design §5 are documented
    let kind = schemas["AuditRecord"]["properties"]["kind"]["description"]
        .as_str()
        .expect("kind description");
    assert!(kind.contains("`config`") && kind.contains("`learning`"));
    for scheme in ["bearer", "session"] {
        assert!(doc["components"]["securitySchemes"][scheme].is_object());
    }
    assert_eq!(
        doc["components"]["securitySchemes"]["session"]["name"],
        "agentsc_session"
    );
    assert_eq!(
        doc["components"]["parameters"]["Csrf"]["name"],
        "X-Agentsc-CSRF"
    );
}
