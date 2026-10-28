//! Risk scoring in embassy (secops/risk.rs, CONTRACT.md §5.5): runs scored once from the ledger,
//! baselines learned without losing a replica's update, and an unusual run that quarantines its
//! agent when `risk.quarantine_score` is set.
mod common;

use std::sync::Arc;

use agentsc_proto::{AuditBatch, sidecar_message};
use common::{Env, NS, hello, orders_yaml};
use embassy::api::types::CpAction;
use embassy::secops::{LedgerRecord, RiskRow, SecOpsStore};
use embassy::store::sqlite::SqliteStore;
use serde_json::{Value, json};

async fn risk_store_rules(store: Arc<dyn SecOpsStore>) {
    let key = embassy::store::ServiceKey::new(NS, "orders");
    let id = store
        .sync_agents(&key, &["ops".to_string()].into())
        .await
        .unwrap()[0]
        .entry
        .id
        .clone();
    let rec = LedgerRecord {
        chain: "r1".into(),
        namespace: NS.into(),
        service: "orders".into(),
        agent_id: Some(id.clone()),
        kind: "model_call".into(),
        record: json!({"kind": "model_call"}),
    };
    store
        .ledger_append("2026-10-29T10:00:00.000Z", &[rec])
        .await
        .unwrap();
    assert_eq!(
        store
            .risk_unscored("2026-10-29T10:00:01.000Z", 10)
            .await
            .unwrap(),
        ["r1"]
    );
    assert!(store.risk_claim("r1").await.unwrap());
    assert!(!store.risk_claim("r1").await.unwrap(), "scored once");
    assert!(
        store
            .risk_unscored("2099-01-01T00:00:00.000Z", 10)
            .await
            .unwrap()
            .is_empty()
    );
    // baselines: an update from a stale read is refused
    assert_eq!(store.get_baseline(&id).await.unwrap(), None);
    assert!(store.put_baseline(&id, None, 1, "{}", "t").await.unwrap());
    assert!(!store.put_baseline(&id, None, 1, "{}", "t").await.unwrap());
    assert!(
        store
            .put_baseline(&id, Some(1), 2, "{\"runs\":2}", "t")
            .await
            .unwrap()
    );
    assert!(
        !store
            .put_baseline(&id, Some(1), 2, "{}", "t")
            .await
            .unwrap()
    );
    assert_eq!(
        store.get_baseline(&id).await.unwrap(),
        Some((2, "{\"runs\":2}".into()))
    );
    let row = |chain: &str, at: &str| RiskRow {
        agent_id: id.clone(),
        chain: chain.into(),
        score: 1.5,
        reasons: vec!["x".into()],
        novelty: 0.0,
        scored_at: at.into(),
    };
    store
        .put_risk(&row("r1", "2026-10-29T10:00:00.000Z"))
        .await
        .unwrap();
    store
        .put_risk(&row("r2", "2026-10-29T11:00:00.000Z"))
        .await
        .unwrap();
    assert_eq!(store.latest_risk(&id).await.unwrap().unwrap().chain, "r2");
}

#[tokio::test]
async fn the_sqlite_store_keeps_risk() {
    risk_store_rules(SqliteStore::open_in_memory().unwrap()).await;
}

#[tokio::test]
async fn the_postgres_store_keeps_risk() {
    let Ok(base) = std::env::var("AGENTSC_TEST_POSTGRES_URL") else {
        eprintln!("AGENTSC_TEST_POSTGRES_URL is not set: the PostgreSQL risk test did not run");
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
    let s = embassy::store::postgres::PgStore::open(embassy::store::postgres::PgOptions {
        url,
        ca_file: None,
        pool_size: 4,
        application_name: schema,
        allow_plaintext: false,
    })
    .await
    .unwrap();
    risk_store_rules(s).await;
}

fn run_records(run: &str, tools: &[&str], denials: usize, hosts: &[&str]) -> Vec<String> {
    let mut out: Vec<Value> = vec![common::rec(
        "model_call",
        json!({"request_id": run, "callee": "mock", "direction": "outbound", "tokens": {"input": 100, "output": 20}, "input": null, "output": null}),
    )];
    for t in tools {
        out.push(common::rec("tool_call", json!({"request_id": run, "callee": t, "direction": "internal", "input": null, "output": null})));
    }
    for _ in 0..denials {
        out.push(common::rec("tool_call", json!({"request_id": run, "callee": "admin_reset", "direction": "internal", "decision": "deny", "input": null, "output": null})));
    }
    for h in hosts {
        out.push(common::rec("http_call", json!({"request_id": run, "callee": format!("https://{h}/x"), "direction": "outbound", "input": null, "output": null})));
    }
    out.iter().map(Value::to_string).collect()
}

#[tokio::test]
async fn an_unusual_run_quarantines_its_agent_and_the_sidecar_is_told() {
    let env = Env::start().await;
    let mut cfg = (**env.hub.config.load()).clone();
    cfg.risk.quarantine_score = Some(3.0);
    env.hub.config.store(Arc::new(cfg));
    env.create("orders", &orders_yaml()).await;
    let mut sc = env
        .sidecar(NS, "orders", hello(NS, "orders", "orders-1"))
        .await
        .unwrap();
    let ops = sc.next_agent_ids().await["ops"].clone();
    assert!(sc.next_quarantine().await.is_empty());

    // four usual runs, each scored once it is in the ledger
    for i in 0..4 {
        let run = format!("usual-{i}");
        sc.send(sidecar_message::Msg::Audit(AuditBatch {
            records_json: run_records(&run, &["lookup_order"], 0, &[]),
        }))
        .await;
        common::eventually("in the ledger", || async {
            env.get(&format!("/ledger/runs/{run}"), "alice").await.body["entries"] == 2
        })
        .await;
        embassy::secops::risk::score_chain(&env.hub, &run)
            .await
            .unwrap();
    }
    let r = env.get(&format!("/agents/{ops}/risk"), "carol").await;
    assert_eq!(r.body["baseline_runs"], 4, "{}", r.text);
    assert_eq!(r.body["latest"]["score"], 0.0, "{}", r.text);
    assert!(r.body["quarantine_score"] == 3.0);

    // an unusual one: new tools, denials, hosts it never called
    sc.send(sidecar_message::Msg::Audit(AuditBatch {
        records_json: run_records(
            "odd",
            &["lookup_order", "export_all", "wire_money"],
            4,
            &["a.evil.example", "b.evil.example"],
        ),
    }))
    .await;
    common::eventually("the odd run in the ledger", || async {
        env.get("/ledger/runs/odd", "alice").await.status == 200
    })
    .await;
    // the ledger takes a batch at once; wait for every record of it
    common::eventually("all of it", || async {
        env.get("/ledger/runs/odd", "alice").await.body["entries"] == 10
    })
    .await;
    embassy::secops::risk::score_chain(&env.hub, "odd")
        .await
        .unwrap();
    let r = env.get(&format!("/agents/{ops}/risk"), "carol").await;
    let score = r.body["latest"]["score"].as_f64().unwrap();
    assert!(score >= 3.0, "{}", r.text);
    assert!(
        r.body["latest"]["reasons"]
            .to_string()
            .contains("hosts it never called"),
        "{}",
        r.text
    );
    assert_eq!(
        r.body["baseline_runs"], 4,
        "a quarantining run is not learned"
    );

    let a = env.get(&format!("/agents/{ops}"), "carol").await;
    assert_eq!(a.body["quarantine"]["by"], "embassy:risk", "{}", a.text);
    assert!(
        a.body["quarantine"]["reason"]
            .as_str()
            .unwrap()
            .starts_with("automatic: risk score")
    );
    // earlier pushes (the registry's syncs) may come first: wait for the one that names ops
    let mut pushed = sc.next_quarantine().await;
    for _ in 0..10 {
        if pushed.contains_key("ops") {
            break;
        }
        pushed = sc.next_quarantine().await;
    }
    assert!(pushed.contains_key("ops"), "{pushed:?}");

    // scored once: a second scoring does nothing
    embassy::secops::risk::score_chain(&env.hub, "odd")
        .await
        .unwrap();
    let audit = env.hub.store.cp_audit(200).await.unwrap();
    let auto: Vec<_> = audit
        .iter()
        .filter(|r| r.action == CpAction::AgentQuarantined && r.actor == "embassy:risk")
        .collect();
    assert_eq!(auto.len(), 1);
    env.stop().await;
}
