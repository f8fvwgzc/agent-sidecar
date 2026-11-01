//! The shadow dual run on charter writes (Tutela INTEGRATION §1, design §8.3): the role check
//! decides, `tutela-pdp` runs next to it on the permission keys of the diff, and the difference
//! is counted. The role-on-diff rules themselves are in `tests/api.rs`.

mod common;

use common::{Env, NS, Resp, orders_yaml};
use serde_json::{Value, json};

async fn put(env: &Env, who: &str, svc: &str, charter: &Value, v: &str) -> Resp {
    env.call(
        "PUT",
        &format!("/services/{NS}/{svc}/charter"),
        who,
        Some(json!({ "yaml": charter.to_string() })),
        Some(v),
    )
    .await
}

async fn report(env: &Env) -> Value {
    let r = env.get("/authz/shadow", "alice").await;
    assert_eq!(r.status, 200, "{}", r.text);
    serde_json::from_str(&r.text).unwrap()
}

#[tokio::test]
async fn the_new_check_agrees_with_the_old_on_every_kind_of_write() {
    let env = Env::start().await;
    // a first charter with PUT: editor no, admin yes
    let r = Env::send(
        env.req(
            "PUT",
            &format!("/api/v1/services/{NS}/orders/charter"),
            Some("bob"),
        )
        .header("If-None-Match", "*")
        .body(json!({"yaml": orders_yaml()}).to_string()),
    )
    .await;
    assert_eq!(r.status, 403, "{}", r.text);
    let v1 = env.create("orders", &orders_yaml()).await;

    // an editor's change, then one only an admin may make, by each
    let (_, base) = env.charter("orders").await;
    let mut editor = base.clone();
    editor["agents"][1]["system"] = json!("Classify by urgency.");
    let r = put(&env, "bob", "orders", &editor, &v1).await;
    assert_eq!(r.status, 200, "{}", r.text);
    let v2 = r.version();

    let mut admin = editor.clone();
    admin["guardrails"]["pii_redact"] = json!(false);
    let r = put(&env, "bob", "orders", &admin, &v2).await;
    assert_eq!(r.status, 403, "{}", r.text);
    let r = put(&env, "alice", "orders", &admin, &v2).await;
    assert_eq!(r.status, 200, "{}", r.text);

    let v = report(&env).await;
    assert_eq!(v["stage"], "shadow");
    assert_eq!(v["checks"], 5, "{v}");
    assert_eq!(v["matches"], 5, "{v}");
    assert_eq!(v["mismatches"], 0, "{v}");
    assert_eq!(v["errors"], 0, "{v}");
    assert_eq!(v["recent"], json!([]));
    env.stop().await;
}

#[tokio::test]
async fn the_old_check_still_decides_and_a_difference_is_only_counted() {
    let env = Env::start().await;
    let v1 = env.create("orders", &orders_yaml()).await;
    // a model that takes write away from editors
    env.hub
        .shadow
        .use_manifest(&embassy::authz::MANIFEST.replace(
            "grants = { namespace = \"read\", service = \"write\" }",
            "grants = { namespace = \"read\", service = \"read\" }",
        ))
        .unwrap();

    let (_, base) = env.charter("orders").await;
    let mut c = base.clone();
    c["agents"][1]["system"] = json!("Classify by urgency.");
    let r = put(&env, "bob", "orders", &c, &v1).await;
    assert_eq!(r.status, 200, "the role check decided: {}", r.text);

    let v = report(&env).await;
    assert_eq!(v["mismatches"], 1, "{v}");
    let m = &v["recent"][0];
    assert_eq!(m["old"], true);
    assert_eq!(m["new"], false);
    assert_eq!(m["keys"], json!(["service:write"]));
    assert_eq!(m["denied"], json!(["service:write"]));
    assert_eq!(m["service"], "orders");
    // an opaque principal, not the token's name
    let principal = m["principal"].as_str().unwrap();
    assert!(principal.starts_with("sa:sa_"), "{principal}");
    assert!(!v.to_string().contains("bob"), "{v}");
    env.stop().await;
}

#[tokio::test]
async fn only_an_admin_reads_the_counts() {
    let env = Env::start().await;
    let r = env.get("/authz/shadow", "bob").await;
    assert_eq!(r.status, 403, "{}", r.text);
    env.stop().await;
}
