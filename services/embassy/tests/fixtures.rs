//! The golden API data in `ui/fixtures/` against the API types, the example charters, each
//! other, and `docs/api/openapi.yaml` (design §10).
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use embassy::api::ids;
use embassy::api::types::{
    AgentView, AuditRecord, CharterDoc, Edge, EdgeKind, Graph, HistoryEntry, MemoryDoc, Node,
    Proposal, ProposalStatus, ServiceSummary, SseEvent, WhoAmI,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    repo().join("ui/fixtures")
}

fn read(name: &str) -> String {
    let path = fixtures().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn json(name: &str) -> Value {
    serde_json::from_str(&read(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn typed<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_value(json(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Deserialize into `T`, serialize again, compare as JSON values.
fn round_trip<T: DeserializeOwned + Serialize>(name: &str) {
    let original = json(name);
    let value: T = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("{name} does not deserialize: {e}"));
    let back = serde_json::to_value(&value).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(back, original, "{name} changed in the round trip");
}

/// One SSE frame of `events.sse`.
struct Frame {
    id: u64,
    event: String,
    data: String,
}

fn sse_frames() -> Vec<Frame> {
    let text = read("events.sse");
    let mut frames = Vec::new();
    for block in text.split("\n\n") {
        let (mut id, mut event, mut data) = (None, None, Vec::new());
        for line in block.lines() {
            if line.is_empty() || line.starts_with(':') {
                continue;
            }
            let (field, value) = line.split_once(": ").unwrap_or((line, ""));
            match field {
                "id" => id = Some(value.parse::<u64>().expect("numeric id")),
                "event" => event = Some(value.to_string()),
                "data" => data.push(value),
                other => panic!("events.sse: unexpected field {other:?}"),
            }
        }
        match (id, event) {
            (Some(id), Some(event)) => frames.push(Frame {
                id,
                event,
                data: data.join("\n"),
            }),
            (None, None) if data.is_empty() => {}
            _ => panic!("events.sse: every event has an id and an event name: {block:?}"),
        }
    }
    frames
}

#[test]
fn every_fixture_round_trips_through_its_api_type() {
    let mut seen = BTreeSet::new();
    for entry in std::fs::read_dir(fixtures()).expect("ui/fixtures exists") {
        let name = entry
            .expect("dir entry")
            .file_name()
            .into_string()
            .expect("utf-8 name");
        match name.as_str() {
            "whoami.json" => round_trip::<WhoAmI>(&name),
            "graph.json" => round_trip::<Graph>(&name),
            "services.json" => round_trip::<Vec<ServiceSummary>>(&name),
            "charter-orders.json" | "charter-inventory.json" => round_trip::<CharterDoc>(&name),
            "agent-view.json" => round_trip::<AgentView>(&name),
            "memory.json" => round_trip::<MemoryDoc>(&name),
            "proposals.json" => round_trip::<Vec<Proposal>>(&name),
            "events-recent.json" => round_trip::<Vec<AuditRecord>>(&name),
            "history.json" => round_trip::<Vec<HistoryEntry>>(&name),
            "events.sse" => {
                for f in sse_frames() {
                    let event = SseEvent::parse(&f.event, &f.data)
                        .unwrap_or_else(|e| panic!("events.sse id {}: {e}", f.id));
                    assert_eq!(event.name(), f.event);
                    let back: Value = serde_json::from_str(&event.data().unwrap()).unwrap();
                    let original: Value = serde_json::from_str(&f.data).unwrap();
                    assert_eq!(
                        back, original,
                        "events.sse id {} changed in the round trip",
                        f.id
                    );
                }
            }
            "README.md" => {}
            other => panic!("ui/fixtures/{other} has no API type here; add it to this test"),
        }
        seen.insert(name);
    }
    for want in [
        "whoami.json",
        "graph.json",
        "services.json",
        "charter-orders.json",
        "charter-inventory.json",
        "agent-view.json",
        "memory.json",
        "proposals.json",
        "events-recent.json",
        "history.json",
        "events.sse",
    ] {
        assert!(seen.contains(want), "ui/fixtures/{want} is missing");
    }
}

#[test]
fn charters_are_the_example_files() {
    for svc in ["orders", "inventory"] {
        let doc: CharterDoc = typed(&format!("charter-{svc}.json"));
        let path = repo().join(format!("examples/charters/{svc}.charter.yaml"));
        let text = std::fs::read_to_string(&path).expect("example charter");
        assert_eq!(
            doc.yaml,
            text,
            "charter-{svc}.json yaml is not {}",
            path.display()
        );
        let as_json: Value = serde_yaml_ng::from_str(&text).expect("example charter parses");
        assert_eq!(
            doc.charter, as_json,
            "charter-{svc}.json charter is not its yaml as JSON"
        );
    }
}

#[test]
fn graph_follows_the_design_rules() {
    let graph: Graph = typed("graph.json");
    let mut nodes = BTreeMap::new();
    for n in &graph.nodes {
        assert!(
            nodes.insert(n.id().to_string(), n).is_none(),
            "duplicate node {}",
            n.id()
        );
    }
    // node ids (design §3)
    for n in &graph.nodes {
        match n {
            Node::Service(s) => assert_eq!(s.id, ids::service(&s.namespace, &s.service)),
            Node::App(a) => {
                assert!(a.id.starts_with("app:"), "{}", a.id);
                assert_eq!(a.parent, a.id.replacen("app:", "svc:", 1));
                assert!(nodes.contains_key(&a.parent));
            }
            Node::Agent(a) => {
                assert!(a.id.starts_with(&a.parent.replacen("svc:", "agent:", 1)));
                assert!(nodes.contains_key(&a.parent));
                // ports: in [invoke], out [tools in declaration order..., model]
                assert_eq!(a.ports.inputs, ["invoke"]);
                let mut out: Vec<String> = a.tools.iter().map(|t| t.name.clone()).collect();
                out.push("model".into());
                assert_eq!(a.ports.outputs, out, "{}", a.id);
                for t in &a.tools {
                    assert!(
                        nodes.contains_key(&t.target),
                        "{} tool {} → {}",
                        a.id,
                        t.name,
                        t.target
                    );
                }
            }
            Node::ModelProvider(m) => {
                assert!(m.id == ids::MODEL_ANTHROPIC || m.id == ids::MODEL_MOCK)
            }
            Node::External(e) => assert!(e.id.starts_with("external:http"), "{}", e.id),
            Node::Placeholder(_) => {}
        }
    }
    // edges: id format, endpoints and ports exist (undeclared edges may leave the source port)
    let mut edge_ids = BTreeSet::new();
    for e in &graph.edges {
        assert!(edge_ids.insert(e.id.clone()), "duplicate edge {}", e.id);
        let tool = (e.kind == EdgeKind::Tool).then_some(e.source_port.as_str());
        assert_eq!(e.id, ids::edge(e.kind, &e.source, &e.target, tool));
        assert_eq!(
            ids::parse_edge(&e.id),
            Some((e.kind, e.source.as_str(), e.target.as_str(), tool))
        );
        let (src, dst) = (nodes[&e.source], nodes[&e.target]);
        let src_ports = src.ports().expect("source has ports");
        let dst_ports = dst.ports().expect("target has ports");
        assert!(dst_ports.inputs.contains(&e.target_port), "{}", e.id);
        if e.declared {
            assert!(src_ports.outputs.contains(&e.source_port), "{}", e.id);
        }
        assert!(e.stats.denied <= e.stats.calls && e.stats.errors <= e.stats.calls);
        assert!(e.stats.calls == 0 || e.stats.last_ts.is_some(), "{}", e.id);
    }
    // every declared tool has its edge
    for n in &graph.nodes {
        if let Node::Agent(a) = n {
            for t in &a.tools {
                let id = ids::edge(EdgeKind::Tool, &a.id, &t.target, Some(&t.name));
                assert!(edge_ids.contains(&id), "missing {id}");
            }
            let model = ids::model_for_agent_model(&a.model);
            assert!(edge_ids.contains(&ids::edge(EdgeKind::Model, &a.id, model, None)));
        }
    }
    // the realism the fixtures promise: one external node, one undeclared denied edge,
    // a denied-only declared edge (the /admin/reset call)
    assert!(graph.nodes.iter().any(|n| matches!(n, Node::External(_))));
    let undeclared: Vec<&Edge> = graph.edges.iter().filter(|e| !e.declared).collect();
    assert_eq!(undeclared.len(), 1);
    assert!(undeclared[0].stats.denied > 0);
    let reset = graph
        .edges
        .iter()
        .find(|e| e.source_port == "inventory_admin_reset")
        .expect("the admin reset edge");
    assert!(reset.declared && reset.stats.calls > 0 && reset.stats.denied == reset.stats.calls);
}

#[test]
fn fixtures_agree_with_each_other() {
    let graph: Graph = typed("graph.json");
    let services: Vec<ServiceSummary> = typed("services.json");
    let memory: MemoryDoc = typed("memory.json");
    let proposals: Vec<Proposal> = typed("proposals.json");
    let history: Vec<HistoryEntry> = typed("history.json");
    let view: AgentView = typed("agent-view.json");

    for svc in &services {
        let doc: CharterDoc = typed(&format!("charter-{}.json", svc.service));
        assert_eq!(svc.epoch.as_deref(), Some(doc.epoch.as_str()));
        assert_eq!(svc.charter_version.as_deref(), Some(doc.version.as_str()));
        let node = graph
            .nodes
            .iter()
            .find_map(|n| match n {
                Node::Service(s) if s.service == svc.service && s.namespace == svc.namespace => {
                    Some(s)
                }
                _ => None,
            })
            .expect("a service node per service");
        assert_eq!(node.charter_version, svc.charter_version);
        assert_eq!(node.instances as usize, svc.instances.len());
        assert_eq!(node.status, svc.status);
        // the agents of the graph are the charter's
        let charter_agents: BTreeSet<String> = doc.charter["agents"]
            .as_array()
            .expect("agents")
            .iter()
            .map(|a| a["name"].as_str().expect("name").to_string())
            .collect();
        let graph_agents: BTreeSet<String> = graph
            .nodes
            .iter()
            .filter_map(|n| match n {
                Node::Agent(a) if a.parent == node.id => Some(a.label.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(graph_agents, charter_agents, "{}", svc.service);
        for inst in &svc.instances {
            assert_eq!(inst.acked_version, svc.charter_version);
        }
    }

    // orders: memory, proposals, history, agent view
    let orders = services
        .iter()
        .find(|s| s.service == "orders")
        .expect("orders");
    assert_eq!(
        orders.memory_version.as_deref(),
        Some(memory.version.as_str())
    );
    let doc: CharterDoc = typed("charter-orders.json");
    assert_eq!(history[0].version, doc.version, "history is newest first");
    assert_eq!(
        history[0].sha256,
        hex::encode(Sha256::digest(doc.yaml.as_bytes()))
    );
    let ops = doc.charter["agents"]
        .as_array()
        .expect("agents")
        .iter()
        .find(|a| a["name"] == "ops-assistant")
        .expect("ops-assistant");
    assert_eq!(&view.agent, ops);
    let learning = graph
        .nodes
        .iter()
        .find_map(|n| match n {
            Node::Agent(a) if a.id == ids::agent("attache-demo", "orders", "ops-assistant") => {
                Some(a.learning.clone())
            }
            _ => None,
        })
        .expect("ops-assistant node");
    let pending = proposals
        .iter()
        .filter(|p| p.status == ProposalStatus::Pending && p.agent == "ops-assistant")
        .count();
    assert_eq!(learning.pending as usize, pending);
    assert_eq!(
        learning.notes as usize,
        memory.agents["ops-assistant"].len()
    );
    for note in &memory.agents["ops-assistant"] {
        assert!(
            proposals
                .iter()
                .any(|p| p.status == ProposalStatus::Approved && p.note == note.text),
            "note {} comes from an approved proposal",
            note.id
        );
    }

    // recent events: newest first, from known services
    let recent: Vec<AuditRecord> = typed("events-recent.json");
    assert!(
        recent.windows(2).all(|w| w[0].ts >= w[1].ts),
        "newest first"
    );
    assert!(
        recent
            .iter()
            .all(|r| services.iter().any(|s| s.service == r.service))
    );
    assert!(
        recent.iter().all(|r| r.ts < graph.generated_at),
        "before the snapshot"
    );
}

#[test]
fn sse_transcript_follows_the_design_rules() {
    let graph: Graph = typed("graph.json");
    let services: Vec<ServiceSummary> = typed("services.json");
    let edges: BTreeSet<&str> = graph.edges.iter().map(|e| e.id.as_str()).collect();
    let frames = sse_frames();
    assert!(frames.windows(2).all(|w| w[0].id < w[1].id), "ids increase");
    let mut kinds = BTreeSet::new();
    let mut audit_traces = BTreeSet::new();
    for f in &frames {
        kinds.insert(f.event.clone());
        match SseEvent::parse(&f.event, &f.data).expect("parses") {
            SseEvent::Audit(a) => {
                assert_eq!(a.animate, a.edge_id.is_some(), "id {}", f.id);
                if let Some(e) = &a.edge_id {
                    assert!(
                        edges.contains(e.as_str()),
                        "id {}: edge {e} not in the graph",
                        f.id
                    );
                }
                assert!(services.iter().any(|s| s.service == a.record.service));
                assert!(a.record.ts > graph.generated_at, "after the snapshot");
                audit_traces.insert(a.record.trace_id.clone());
            }
            SseEvent::Graph(g) => {
                let (old, new): (u64, u64) =
                    (graph.version.parse().unwrap(), g.version.parse().unwrap());
                assert!(new > old, "graph versions increase");
            }
            _ => {}
        }
    }
    for want in ["registry", "audit", "graph", "proposal", "ack"] {
        assert!(kinds.contains(want), "events.sse has no {want} event");
    }
    assert_eq!(
        audit_traces.len(),
        1,
        "the audit events are one cross-pod call"
    );
    let audit_services: BTreeSet<String> = frames
        .iter()
        .filter_map(|f| match SseEvent::parse(&f.event, &f.data) {
            Ok(SseEvent::Audit(a)) => Some(a.record.service),
            _ => None,
        })
        .collect();
    assert_eq!(audit_services.len(), 2, "the call crosses pods");
}

/// Every `$ref` of the OpenAPI document resolves, every SSE event is documented, and every
/// fixture names an existing schema.
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
        "attache_session"
    );
    assert_eq!(
        doc["components"]["parameters"]["Csrf"]["name"],
        "X-Attache-CSRF"
    );
}
