//! The golden API data in `ui/fixtures/` against the API types, the example charters, each
//! other, and `docs/api/openapi.yaml` (design §10).
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use embassy::api::ids;
use embassy::api::types::{
    AgentView, AuditRecord, CharterDoc, Edge, EdgeKind, Graph, HistoryEntry, LinkResult, MemoryDoc,
    Node, NoteSource, Proposal, ProposalStatus, Role, ServiceStatus, ServiceSummary, SseEvent,
    TraceDoc, TraceSummary, ValidateResult, WhoAmI,
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
            "whoami.json" | "whoami-viewer.json" => round_trip::<WhoAmI>(&name),
            "graph.json" => round_trip::<Graph>(&name),
            "services.json" => round_trip::<Vec<ServiceSummary>>(&name),
            "charter-validate.json" => round_trip::<ValidateResult>(&name),
            n if n.starts_with("charter-") => round_trip::<CharterDoc>(&name),
            "agent-view.json" | "agent-view-support.json" => round_trip::<AgentView>(&name),
            "links-result.json" => round_trip::<LinkResult>(&name),
            "memory.json" => round_trip::<MemoryDoc>(&name),
            "proposals.json" => round_trip::<Vec<Proposal>>(&name),
            "events-recent.json" => round_trip::<Vec<AuditRecord>>(&name),
            "history.json" => round_trip::<Vec<HistoryEntry>>(&name),
            // the timeline's runs (added with the timeline fixtures; checked when present)
            "traces.json" => round_trip::<Vec<TraceSummary>>(&name),
            n if n.starts_with("trace-") && n.ends_with(".json") => {
                round_trip::<TraceDoc>(&name);
                let doc: TraceDoc = typed(&name);
                assert_eq!(
                    name,
                    format!("trace-{}.json", doc.trace_id),
                    "trace-<trace_id>.json"
                );
            }
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
        "whoami-viewer.json",
        "graph.json",
        "services.json",
        "charter-orders.json",
        "charter-inventory.json",
        "charter-support.json",
        "charter-reports.json",
        "charter-validate.json",
        "agent-view.json",
        "agent-view-support.json",
        "links-result.json",
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
            Node::Placeholder(p) => {
                // a peer no charter and no instance names: its service is a placeholder too
                if let Some(parent) = &p.parent {
                    assert!(
                        matches!(nodes.get(parent), Some(Node::Placeholder(_))),
                        "{} parent {parent}",
                        p.id
                    );
                }
            }
        }
    }
    assert!(
        graph
            .nodes
            .iter()
            .any(|n| matches!(n, Node::Placeholder(_))),
        "a placeholder for an unknown peer"
    );
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
        let file = format!("charter-{}.json", svc.service);
        if svc.charter_version.is_none() {
            // no stored charter: no charter document, a pending adoption, no agents in the graph
            assert_eq!(svc.status, ServiceStatus::NoCharter, "{}", svc.service);
            assert!(svc.pending_adoption.is_some() && !svc.instances.is_empty());
            assert!(!fixtures().join(&file).exists(), "{file}");
            let frame = ids::service(&svc.namespace, &svc.service);
            assert!(
                !graph
                    .nodes
                    .iter()
                    .any(|n| matches!(n, Node::Agent(a) if a.parent == frame))
            );
            continue;
        }
        let doc: CharterDoc = typed(&file);
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
        // degraded: connected, and an instance has an ack error, lags or is not ready
        let lagging = svc.instances.iter().any(|i| {
            i.ack_error.is_some() || i.acked_version != svc.charter_version || !i.runtime_ready
        });
        let want = match (svc.instances.is_empty(), lagging) {
            (true, _) => ServiceStatus::Disconnected,
            (false, true) => ServiceStatus::Degraded,
            (false, false) => ServiceStatus::Connected,
        };
        assert_eq!(svc.status, want, "{}", svc.service);
    }
    assert!(
        services.iter().any(|s| s.status == ServiceStatus::Degraded),
        "a degraded service (an instance with an ack error)"
    );

    // orders: history and agent view; support: memory and proposals
    let support = services
        .iter()
        .find(|s| s.service == "support")
        .expect("support");
    assert_eq!(
        support.memory_version.as_deref(),
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
    let support_view: AgentView = typed("agent-view-support.json");
    let support_doc: CharterDoc = typed("charter-support.json");
    assert_eq!(support_view.agent, support_doc.charter["agents"][0]);
    let learning = |id: String| {
        graph
            .nodes
            .iter()
            .find_map(|n| match n {
                Node::Agent(a) if a.id == id => Some(a.learning.clone()),
                _ => None,
            })
            .expect("agent node")
    };
    // memory exists only for agents with learning enabled (design §3)
    let ops_learning = learning(ids::agent("attache-demo", "orders", "ops-assistant"));
    assert!(!ops_learning.enabled && ops_learning.notes == 0);
    let sa = learning(ids::agent("attache-demo", "support", "support-agent"));
    assert!(sa.enabled);
    let pending = proposals
        .iter()
        .filter(|p| p.status == ProposalStatus::Pending && p.agent == "support-agent")
        .count();
    assert_eq!(sa.pending as usize, pending);
    assert!(pending > 0);
    assert_eq!(sa.notes as usize, memory.agents["support-agent"].len());
    assert_eq!(
        memory.agents.keys().collect::<Vec<_>>(),
        ["support-agent"],
        "only agents with learning enabled have notes"
    );
    for note in &memory.agents["support-agent"] {
        match note.source {
            NoteSource::Review => assert!(
                proposals
                    .iter()
                    .any(|p| p.status == ProposalStatus::Approved && p.note == note.text),
                "note {} comes from an approved proposal",
                note.id
            ),
            NoteSource::Manual => {
                assert!(note.request_id.is_none() && note.approved_by.is_some())
            }
            NoteSource::Auto => assert!(note.expires_at.is_some()),
        }
    }
    let viewer: WhoAmI = typed("whoami-viewer.json");
    assert!(viewer.role == Role::Viewer && !viewer.payloads);

    // recent events: strictly newest first, equal timestamps in reverse write order (a pod
    // writes a tool_call before its call record, and an agent_invocation after the other
    // records of its span), from known services
    let recent: Vec<AuditRecord> = typed("events-recent.json");
    let rank = |r: &AuditRecord| match r.kind.as_str() {
        "tool_call" => 0,
        "agent_call" | "service_call" | "http_call" => 1,
        "agent_invocation" => 3,
        _ => 2,
    };
    for w in recent.windows(2) {
        assert!(w[0].ts >= w[1].ts, "newest first: {} {}", w[0].ts, w[1].ts);
        if w[0].ts == w[1].ts {
            assert_eq!(w[0].service, w[1].service, "ties within one pod");
            assert!(
                rank(&w[0]) > rank(&w[1]),
                "{} {} before {}: not reverse write order",
                w[0].ts,
                w[0].kind,
                w[1].kind
            );
        }
    }
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
    let mut graph_version: u64 = graph.version.parse().unwrap();
    for (i, f) in frames.iter().enumerate() {
        kinds.insert(f.event.clone());
        match SseEvent::parse(&f.event, &f.data).expect("parses") {
            SseEvent::Audit(a) => {
                assert_eq!(a.animate, a.edge_id.is_some(), "id {}", f.id);
                if let Some(e) = &a.edge_id {
                    // an edge the snapshot does not have yet: a graph event announces it
                    assert!(
                        edges.contains(e.as_str())
                            || frames[i + 1..].iter().any(|g| g.event == "graph"),
                        "id {}: edge {e} not in the graph and no graph event follows",
                        f.id
                    );
                }
                assert!(services.iter().any(|s| s.service == a.record.service));
                assert!(a.record.ts > graph.generated_at, "after the snapshot");
            }
            SseEvent::Graph(g) => {
                let new: u64 = g.version.parse().unwrap();
                assert!(new > graph_version, "graph versions increase");
                graph_version = new;
            }
            SseEvent::Lagged(l) => {
                // the 1024 queued events and the one that did not fit, at least
                assert!(l.dropped > 1024, "id {}: dropped {}", f.id, l.dropped);
                assert!(f.id - frames[i - 1].id >= l.dropped, "id {}: id gap", f.id);
            }
            _ => {}
        }
    }
    for want in SseEvent::NAMES {
        // span_start events arrive with the timeline fixtures
        if want == "span_start" {
            continue;
        }
        assert!(kinds.contains(want), "events.sse has no {want} event");
    }
    assert_eq!(
        frames[0].event, "reset",
        "the client reconnected with a stale Last-Event-ID"
    );
    let acks: Vec<bool> = frames
        .iter()
        .filter_map(|f| match SseEvent::parse(&f.event, &f.data) {
            Ok(SseEvent::Ack(a)) => Some(a.applied),
            _ => None,
        })
        .collect();
    assert!(
        acks.contains(&true) && acks.contains(&false),
        "an applied and a failed ack"
    );
    // the request audit events: every request keeps one trace and one request id; one request
    // crosses pods (the stock question), and the record kinds the UI must animate or not are there
    let records: Vec<AuditRecord> = frames
        .iter()
        .filter_map(|f| match SseEvent::parse(&f.event, &f.data) {
            Ok(SseEvent::Audit(a)) => Some(a.record),
            _ => None,
        })
        .collect();
    let mut by_request: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<&str>)> = BTreeMap::new();
    for r in records.iter().filter(|r| r.kind != "config") {
        let (traces, pods) = by_request.entry(r.request_id.as_str()).or_default();
        traces.insert(r.trace_id.as_str());
        pods.insert(r.service.as_str());
    }
    assert!(by_request.values().all(|(traces, _)| traces.len() == 1));
    assert!(
        by_request.values().any(|(_, pods)| pods.len() == 2),
        "a call across pods"
    );
    let has = |pred: &dyn Fn(&AuditRecord) -> bool| records.iter().any(pred);
    assert!(has(&|r| r.kind == "config"), "a config record");
    assert!(
        has(&|r| r.kind == "agent_invocation" && r.caller == "local" && r.caller_agent.is_some()),
        "a local orchestrator's call"
    );
    assert!(has(&|r| r.kind == "http_call"), "an http_call");
    assert!(
        has(&|r| r.kind == "model_call" && r.callee == "mock"),
        "a model_call to the mock model"
    );
}

/// Every charter in the fixtures passes `attache charter validate` (the CLI of this workspace).
/// `cargo test --workspace` builds the CLI before it runs any test (its own tests need it); a
/// lone `cargo test -p embassy` may not have it, and then this test says so and passes, except
/// in CI (`CI` set), where the CLI must be there.
#[test]
fn fixture_charters_pass_the_cli_validator() {
    let exe = std::env::current_exe().expect("test executable");
    // target/<profile>/deps/fixtures-<hash> -> target/<profile>/attache
    let cli = exe
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join(format!("attache{}", std::env::consts::EXE_SUFFIX)))
        .expect("target directory");
    if !cli.exists() {
        assert!(
            std::env::var_os("CI").is_none(),
            "{} is missing: CI runs cargo test --workspace, which builds it",
            cli.display()
        );
        eprintln!(
            "skipped: {} is not built (cargo build -p attache-cli)",
            cli.display()
        );
        return;
    }
    let dir = tempfile::tempdir().expect("temp dir");
    let mut checked = 0;
    for entry in std::fs::read_dir(fixtures()).expect("ui/fixtures exists") {
        let name = entry.expect("dir entry").file_name().into_string().unwrap();
        let yaml = match name.as_str() {
            // the candidate is JSON, which YAML reads as it is
            "charter-validate.json" => {
                let v: ValidateResult = typed(&name);
                serde_json::to_string_pretty(&v.charter).unwrap()
            }
            n if n.starts_with("charter-") => typed::<CharterDoc>(n).yaml,
            _ => continue,
        };
        let file = dir.path().join(name.replace(".json", ".yaml"));
        std::fs::write(&file, yaml).expect("write charter");
        let out = std::process::Command::new(&cli)
            .args(["charter", "validate"])
            .arg(&file)
            .output()
            .expect("run attache charter validate");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.starts_with("valid: "),
            "{name}: attache charter validate: {stdout} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        checked += 1;
    }
    assert!(checked >= 5, "only {checked} charters checked");
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
        "TraceSummary",
        "Span",
        "SpanEvent",
        "TraceDoc",
        "SpanStartEvent",
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
