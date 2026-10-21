//! Charters shared by the integration tests.
#![allow(dead_code)]

use attache_charter::Charter;

pub const ORDERS: &str = include_str!("../../../../examples/charters/orders.charter.yaml");
pub const INVENTORY: &str = include_str!("../../../../examples/charters/inventory.charter.yaml");

/// A charter that uses every v0.2 field (design §4), valid as written.
pub const V02: &str = r#"
apiVersion: attache.io/v1alpha1
kind: Charter
service:
  name: support
  namespace: shop
  app_port: 8000
  service_accounts: [support, support-canary]
skills:
  - name: refund-policy
    description: How to decide whether a refund is allowed.
    instructions: |
      Look up the order with get_order first. Refund only within 30 days.
    tools: [get_order]
  - name: escalation
    description: When to hand a case to a human.
    instructions: Escalate when the customer asks for a manager.
telemetry:
  otlp_endpoint: http://otel-collector:4318
  traces: true
  metrics: true
  export_payloads: false
  control_plane_payloads: true
agents:
  - name: support
    type: orchestrator
    model: claude-opus-5-5
    system: You help customers of the shop.
    tools:
      - name: get_order
        description: Get one order.
        type: service
        service: orders
        method: GET
        path: /orders/{id}
      - name: refund
        description: Refund one order.
        type: service
        service: orders
        method: POST
        path: /orders/{id}/refund
      - name: triage
        description: Ask the triage agent.
        type: agent
        agent: triage
      - name: partner
        description: Look a parcel up at the carrier.
        type: http
        method: GET
        url: https://api.partner.example/v1/parcels/{id}
    skills: [refund-policy, escalation]
    harness:
      max_retries: 2
      request_timeout_seconds: 120
      fallback_model: claude-haiku-5-5
      tool_result_max_chars: 20000
    learning:
      enabled: true
      mode: review
      max_notes: 20
      max_note_chars: 500
      note_ttl_days: 7
      from_peers: false
      max_proposals_per_hour: 10
  - name: triage
    model: mock
    system: You sort tickets.
guardrails:
  pii_redact: true
  input_deny:
    - { name: no-secrets, regex: "(?i)password\\s*[:=]" }
  allowed_tools:
    support: [get_order, refund, triage, partner]
authz:
  default: deny
  callers:
    - identity: local
      agents: ["*"]
    - identity: spiffe://attache/ns/shop/svc/web
      agents: [support]
  services:
    - name: self-orders
      identity: local
      service: orders
      allow: ["GET /orders/*", "POST /orders/*"]
audit:
  sink: stdout
  redact: [input.context.card]
"#;

pub fn v02() -> Charter {
    Charter::from_yaml(V02).expect("the v0.2 fixture is valid")
}

pub fn orders() -> Charter {
    Charter::from_yaml(ORDERS).expect("orders charter valid")
}

/// The validation error text, which must exist.
pub fn invalid(c: &Charter) -> String {
    match c.validate() {
        Ok(()) => panic!("expected the charter to be invalid"),
        Err(e) => e.to_string(),
    }
}

/// Assert the charter is invalid and the error names `needle`.
pub fn rejects(c: &Charter, needle: &str) {
    let msg = invalid(c);
    assert!(msg.contains(needle), "expected {needle:?} in:\n{msg}");
}

/// Assert the charter is valid.
pub fn accepts(c: &Charter) {
    if let Err(e) = c.validate() {
        panic!("expected a valid charter:\n{e}");
    }
}
