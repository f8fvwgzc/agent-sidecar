//! Approvals of tool calls in embassy (secops/approvals.rs, CONTRACT.md §5.4): the stores (SQLite
//! always, PostgreSQL with `AGENTSC_TEST_POSTGRES_URL`), and a request from a sidecar decided
//! through the API, expired, or ended by a quarantine.
mod common;

use std::sync::Arc;

use agentsc_proto::{ApprovalRequest, control_message, sidecar_message};
use common::{Env, NS, hello, orders_yaml};
use embassy::api::types::CpAction;
use embassy::secops::{
    Approval, ApprovalFilter, ApprovalPut, ApprovalStatus, PENDING_MAX, SecOpsStore,
};
use embassy::store::StoreError;
use embassy::store::postgres::{PgOptions, PgStore};
use embassy::store::sqlite::SqliteStore;
use serde_json::json;

fn pending(id: &str, agent: &str, expires_at: &str) -> Approval {
    Approval {
        id: id.into(),
        namespace: NS.into(),
        service: "orders".into(),
        agent: agent.into(),
        agent_id: None,
        tool: "refund".into(),
        request_id: "r1".into(),
        trace_id: "t1".into(),
        args_sha256: "ab".repeat(32),
        status: ApprovalStatus::Pending,
        requested_at: "2026-10-29T10:00:00.000Z".into(),
        expires_at: expires_at.into(),
        decided_at: None,
        decided_by: None,
        reason: None,
    }
}

const LATER: &str = "2099-01-01T00:00:00.000Z";
const NOW: &str = "2026-10-29T10:00:05.000Z";

async fn approval_rules(store: Arc<dyn SecOpsStore>) {
    assert!(matches!(
        store
            .put_approval(&pending("a1", "ops", LATER))
            .await
            .unwrap(),
        ApprovalPut::Stored(_)
    ));
    assert!(matches!(
        store
            .put_approval(&pending("a1", "ops", LATER))
            .await
            .unwrap(),
        ApprovalPut::Existing(_)
    ));
    // approved once; a second decision is a conflict
    let a = store
        .decide_approval("a1", true, "bob", None, NOW)
        .await
        .unwrap();
    assert_eq!(
        (a.status, a.decided_by.as_deref()),
        (ApprovalStatus::Approved, Some("bob"))
    );
    assert_eq!(
        store
            .decide_approval("a1", false, "bob", Some("no"), NOW)
            .await,
        Err(StoreError::Conflict {
            current: "approved".into()
        })
    );
    // past its time: expired, not approved
    store
        .put_approval(&pending("a2", "ops", "2026-10-29T10:00:01.000Z"))
        .await
        .unwrap();
    let late = store
        .decide_approval("a2", true, "bob", None, NOW)
        .await
        .unwrap();
    assert_eq!(late.status, ApprovalStatus::Expired);
    // the expirer
    store
        .put_approval(&pending("a3", "ops", "2026-10-29T10:00:02.000Z"))
        .await
        .unwrap();
    store
        .put_approval(&pending("a4", "ops", LATER))
        .await
        .unwrap();
    let gone = store.expire_approvals(NOW, None).await.unwrap();
    assert_eq!(
        gone.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
        ["a3"]
    );
    // a quarantine expires all of the agent's pending ones
    let gone = store
        .expire_approvals(NOW, Some((NS, "orders", "ops")))
        .await
        .unwrap();
    assert_eq!(
        gone.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
        ["a4"]
    );
    // at most PENDING_MAX pending per agent
    for i in 0..PENDING_MAX {
        store
            .put_approval(&pending(&format!("m{i}"), "triage", LATER))
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .put_approval(&pending("one-more", "triage", LATER))
            .await
            .unwrap(),
        ApprovalPut::TooMany
    );
    let list = store
        .list_approvals(&ApprovalFilter {
            status: Some(ApprovalStatus::Pending),
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(list.len(), PENDING_MAX);
    assert_eq!(store.get_approval("none").await, Err(StoreError::NotFound));
}

#[tokio::test]
async fn the_sqlite_store_keeps_approvals() {
    let s = SqliteStore::open_in_memory().unwrap();
    approval_rules(s).await;
}

#[tokio::test]
async fn the_postgres_store_keeps_approvals() {
    let Ok(base) = std::env::var("AGENTSC_TEST_POSTGRES_URL") else {
        eprintln!(
            "AGENTSC_TEST_POSTGRES_URL is not set: the PostgreSQL approvals test did not run"
        );
        return;
    };
    let schema = format!("t_{}", uuid::Uuid::new_v4().simple());
    let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let sep = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{sep}options=-c%20search_path%3D{schema}");
    let s = PgStore::open(PgOptions {
        url: url.clone(),
        ca_file: None,
        pool_size: 4,
        application_name: schema.clone(),
        allow_plaintext: false,
    })
    .await
    .unwrap();
    approval_rules(s).await;
    let (raw, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(conn);
    assert!(
        raw.batch_execute("UPDATE approvals SET status = 'pending' WHERE id = 'a1'")
            .await
            .is_err()
    );
    assert!(raw.batch_execute("DELETE FROM approvals").await.is_err());
}

fn request(id: &str, timeout_s: u32) -> sidecar_message::Msg {
    sidecar_message::Msg::ApprovalRequest(ApprovalRequest {
        id: id.into(),
        agent: "ops".into(),
        tool: "lookup_order".into(),
        request_id: "run-1".into(),
        trace_id: "t1".into(),
        args_sha256: "cd".repeat(32),
        timeout_s,
        requested_at: common::now_ts(),
    })
}

async fn next_decision(sc: &mut common::Sidecar) -> agentsc_proto::ApprovalDecision {
    let deadline = tokio::time::Instant::now() + common::WAIT;
    loop {
        match tokio::time::timeout_at(deadline, sc.rx.message()).await {
            Ok(Ok(Some(m))) => {
                if let Some(control_message::Msg::ApprovalDecision(d)) = m.msg {
                    return d;
                }
            }
            other => panic!("no decision: {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_request_is_decided_through_the_api_and_the_sidecar_learns() {
    let env = Env::start().await;
    env.create("orders", &orders_yaml()).await;
    let mut sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-1"))
        .await
        .unwrap();
    sc.send(request("ap-1", 600)).await;
    common::eventually("the pending approval", || async {
        env.get("/approvals?status=pending", "carol")
            .await
            .body
            .as_array()
            .is_some_and(|a| a.len() == 1)
    })
    .await;
    let a = env.get("/approvals/ap-1", "carol").await;
    assert_eq!(a.status, 200, "{}", a.text);
    assert!(a.body["agent_id"].as_str().unwrap().starts_with("agt_"));
    assert_eq!(env.get("/approvals/ap-1", "dave").await.status, 404);
    // carol (viewer) may read, not decide; bob (editor) decides
    assert_eq!(
        env.call("POST", "/approvals/ap-1/approve", "carol", None, None)
            .await
            .status,
        403
    );
    let r = env
        .call(
            "POST",
            "/approvals/ap-1/approve",
            "bob",
            Some(json!({"reason": "ok for 1001"})),
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["status"], "approved");
    let d = next_decision(&mut sc).await;
    assert_eq!(
        (
            d.id.as_str(),
            d.decision.as_str(),
            d.decided_by.as_str(),
            d.reason.as_str()
        ),
        ("ap-1", "approved", "bob", "ok for 1001")
    );
    let again = env
        .call(
            "POST",
            "/approvals/ap-1/deny",
            "bob",
            Some(json!({"reason": "x"})),
            None,
        )
        .await;
    assert_eq!(
        (again.status, again.error()),
        (409, "not_pending"),
        "{}",
        again.text
    );

    // a deny needs a reason
    sc.send(request("ap-2", 600)).await;
    common::eventually("ap-2", || async {
        env.get("/approvals/ap-2", "bob").await.status == 200
    })
    .await;
    assert_eq!(
        env.call("POST", "/approvals/ap-2/deny", "bob", Some(json!({})), None)
            .await
            .status,
        400
    );
    let r = env
        .call(
            "POST",
            "/approvals/ap-2/deny",
            "bob",
            Some(json!({"reason": "not today"})),
            None,
        )
        .await;
    assert_eq!(r.body["status"], "denied", "{}", r.text);
    assert_eq!(next_decision(&mut sc).await.decision, "denied");

    // asked again after a reconnect: the decision comes back at once
    sc.send(request("ap-2", 600)).await;
    assert_eq!(next_decision(&mut sc).await.decision, "denied");

    // nobody decides: expired, pushed
    sc.send(request("ap-3", 1)).await;
    let d = next_decision(&mut sc).await;
    assert_eq!((d.id.as_str(), d.decision.as_str()), ("ap-3", "expired"));

    // a quarantine expires the agent's pending approvals
    sc.send(request("ap-4", 600)).await;
    common::eventually("ap-4", || async {
        env.get("/approvals/ap-4", "bob").await.status == 200
    })
    .await;
    let agent = env.get("/approvals/ap-4", "bob").await.body["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let q = env
        .call(
            "POST",
            &format!("/agents/{agent}/quarantine"),
            "alice",
            Some(json!({"reason": "r"})),
            None,
        )
        .await;
    assert_eq!(q.status, 200, "{}", q.text);
    let d = next_decision(&mut sc).await;
    assert_eq!((d.id.as_str(), d.decision.as_str()), ("ap-4", "expired"));

    let audit = env.hub.store.cp_audit(200).await.unwrap();
    assert!(audit.iter().any(|r| r.action == CpAction::ApprovalApprove
        && r.reason.as_deref() == Some("lookup_order in run run-1: ok for 1001")));
    assert!(
        audit
            .iter()
            .any(|r| r.action == CpAction::ApprovalDeny && r.actor == "bob")
    );
    env.stop().await;
}
