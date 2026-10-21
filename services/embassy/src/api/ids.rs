//! Graph node and edge ids (design §3, §10.1). Ids are stable across reloads; the UI keys
//! node positions by them.
//!
//! Nodes: `svc:<ns>/<svc>`, `app:<ns>/<svc>`, `agent:<ns>/<svc>/<agent>`, `model:anthropic`,
//! `model:mock`, `external:<scheme>://<host>[:<port>]`. Edges:
//! `edge:<kind>:<source node id>-><target node id>`, plus `#<tool name>` for tool edges.
use super::types::EdgeKind;

pub const MODEL_ANTHROPIC: &str = "model:anthropic";
pub const MODEL_MOCK: &str = "model:mock";

pub fn service(namespace: &str, service: &str) -> String {
    format!("svc:{namespace}/{service}")
}

pub fn app(namespace: &str, service: &str) -> String {
    format!("app:{namespace}/{service}")
}

pub fn agent(namespace: &str, service: &str, agent: &str) -> String {
    format!("agent:{namespace}/{service}/{agent}")
}

/// `origin` is `scheme://host[:port]` as `url::Origin::ascii_serialization` writes it.
pub fn external(origin: &str) -> String {
    format!("external:{origin}")
}

/// The provider node of an agent's declared `model` (`mock` → `model:mock`).
pub fn model_for_agent_model(model: &str) -> &'static str {
    if model == "mock" {
        MODEL_MOCK
    } else {
        MODEL_ANTHROPIC
    }
}

/// The provider node of a `model_call` record, from its `callee` (`mock`, or
/// `anthropic:<model>`).
pub fn model_for_callee(callee: &str) -> &'static str {
    if callee == "mock" || callee.starts_with("mock:") {
        MODEL_MOCK
    } else {
        MODEL_ANTHROPIC
    }
}

pub fn edge(kind: EdgeKind, source: &str, target: &str, tool: Option<&str>) -> String {
    let mut id = format!("edge:{}:{source}->{target}", kind.as_str());
    if let Some(t) = tool {
        id.push('#');
        id.push_str(t);
    }
    id
}

/// The parts of an edge id: kind, source, target, tool. `None` when it is not an edge id.
pub fn parse_edge(id: &str) -> Option<(EdgeKind, &str, &str, Option<&str>)> {
    let rest = id.strip_prefix("edge:")?;
    let (kind, rest) = rest.split_once(':')?;
    let kind = match kind {
        "invoke" => EdgeKind::Invoke,
        "tool" => EdgeKind::Tool,
        "model" => EdgeKind::Model,
        _ => return None,
    };
    let (source, rest) = rest.split_once("->")?;
    let (target, tool) = match (kind, rest.rsplit_once('#')) {
        (EdgeKind::Tool, Some((target, tool))) if !tool.is_empty() => (target, Some(tool)),
        (EdgeKind::Tool, _) => return None,
        (_, _) => (rest, None),
    };
    if source.is_empty() || target.is_empty() {
        return None;
    }
    Some((kind, source, target, tool))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ids() {
        assert_eq!(service("shop", "orders"), "svc:shop/orders");
        assert_eq!(app("shop", "orders"), "app:shop/orders");
        assert_eq!(
            agent("shop", "orders", "ops-assistant"),
            "agent:shop/orders/ops-assistant"
        );
        assert_eq!(
            external("https://api.partner.example"),
            "external:https://api.partner.example"
        );
        assert_eq!(model_for_agent_model("mock"), MODEL_MOCK);
        assert_eq!(model_for_agent_model("claude-opus-5-5"), MODEL_ANTHROPIC);
        assert_eq!(model_for_callee("mock"), MODEL_MOCK);
        assert_eq!(
            model_for_callee("anthropic:claude-opus-5-5"),
            MODEL_ANTHROPIC
        );
    }

    #[test]
    fn edge_ids_round_trip() {
        let invoke = edge(
            EdgeKind::Invoke,
            "app:shop/orders",
            "agent:shop/orders/ops-assistant",
            None,
        );
        assert_eq!(
            invoke,
            "edge:invoke:app:shop/orders->agent:shop/orders/ops-assistant"
        );
        assert_eq!(
            parse_edge(&invoke),
            Some((
                EdgeKind::Invoke,
                "app:shop/orders",
                "agent:shop/orders/ops-assistant",
                None
            ))
        );
        let http = edge(
            EdgeKind::Tool,
            "agent:shop/orders/ops-assistant",
            "external:https://api.partner.example:8443",
            Some("partner_eta"),
        );
        assert_eq!(
            parse_edge(&http),
            Some((
                EdgeKind::Tool,
                "agent:shop/orders/ops-assistant",
                "external:https://api.partner.example:8443",
                Some("partner_eta")
            ))
        );
        assert_eq!(
            parse_edge("edge:tool:a->b"),
            None,
            "a tool edge names its tool"
        );
        assert_eq!(parse_edge("edge:wire:a->b"), None);
        assert_eq!(parse_edge("node:a->b"), None);
        assert_eq!(parse_edge("edge:model:->model:mock"), None);
    }
}
