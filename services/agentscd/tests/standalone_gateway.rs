//! The standalone model gateway (`agentsc-gateway`, docs/LLM-CONNECTION.md): callers
//! authenticate with a tenant token; each of the three wire formats goes to a provider that
//! speaks it, the platform's (the LLM connection contract) or the tenant's own key; spend is held
//! against the tenant's budget and every call is recorded. A fake upstream speaks Anthropic
//! Messages, OpenAI Chat Completions and Responses, and records what reached it.
mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use agentsc_common::audit::AuditWriter;
use agentsc_common::llm_contract::{
    Contract, ProviderConnection, ProviderKind, SecretSource, Upstream,
};
use agentscd::gateway::standalone::{self, Gateway, SERVICE, Settings};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use common::serve_app;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// What reached the fake upstream: path, headers, body.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<(String, HeaderMap, Value)>>>);

impl Seen {
    fn all(&self) -> Vec<(String, HeaderMap, Value)> {
        self.0.lock().unwrap().clone()
    }
    fn last(&self) -> (String, HeaderMap, Value) {
        self.all().pop().expect("a call reached the upstream")
    }
}

fn sse(events: &[Value], named: bool) -> String {
    events
        .iter()
        .map(|e| match (named, e["type"].as_str()) {
            (true, Some(t)) => format!("event: {t}\ndata: {e}\n\n"),
            _ => format!("data: {e}\n\n"),
        })
        .collect()
}

async fn fake(
    State(seen): State<Seen>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let path = uri.path().to_string();
    seen.0
        .lock()
        .unwrap()
        .push((path.clone(), headers, body.clone()));
    let stream = body["stream"] == true;
    let event_stream =
        |text: String| ([("content-type", "text/event-stream")], text).into_response();
    match path.as_str() {
        "/v1/messages" if stream => event_stream(sse(
            &[
                json!({"type": "message_start", "message": {"usage": {"input_tokens": 1000, "output_tokens": 1}}}),
                json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 50}}),
                json!({"type": "message_stop"}),
            ],
            true,
        )),
        "/v1/messages" => axum::Json(json!({
            "type": "message", "role": "assistant", "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "hello"}],
            "usage": {"input_tokens": 1000, "output_tokens": 50}
        }))
        .into_response(),
        "/v1/chat/completions" if stream => {
            let mut chunks = vec![
                json!({"choices": [{"index": 0, "delta": {"content": "hi"}}]}),
                json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
            ];
            // like OpenAI: the usage chunk only when the request asked for it
            if body["stream_options"]["include_usage"] == true {
                chunks.push(json!({"choices": [], "usage": {"prompt_tokens": 2000, "completion_tokens": 100}}));
            }
            event_stream(sse(&chunks, false) + "data: [DONE]\n\n")
        }
        "/v1/chat/completions" => axum::Json(json!({
            "choices": [{"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 2000, "completion_tokens": 100}
        }))
        .into_response(),
        "/v1/responses" if stream => event_stream(sse(
            &[
                json!({"type": "response.created", "response": {"status": "in_progress"}}),
                json!({"type": "response.completed", "response": {"status": "completed", "output": [],
                    "usage": {"input_tokens": 3000, "output_tokens": 200}}}),
            ],
            true,
        )),
        _ => (StatusCode::NOT_FOUND, "no such path").into_response(),
    }
}

/// A shared buffer standing in for stdout.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Lines {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Lines {
    fn records(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

struct Rig {
    url: String,
    seen: Seen,
    audit: Lines,
    tmp: tempfile::TempDir,
}

fn sha(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn write(dir: &Path, name: &str, text: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p
}

/// The gateway: platform upstream Anthropic (the contract, key file `platform-key`); tenants
/// `texc` (the platform), `onto` (its own OpenAI key, `gpt-*` only) and `cheap` (a tiny budget).
async fn rig() -> Rig {
    let seen = Seen::default();
    let app = axum::Router::new()
        .route("/v1/messages", post(fake))
        .route("/v1/chat/completions", post(fake))
        .route("/v1/responses", post(fake))
        .with_state(seen.clone());
    let upstream = format!("http://{}", serve_app(app).await);
    let tmp = tempfile::tempdir().unwrap();
    let platform_key = write(tmp.path(), "platform-key", "sk-ant-platform-1\n");
    let onto_key = write(tmp.path(), "onto-key", "sk-onto-own");
    let tenants: standalone::TenantsFile = serde_yaml_ng::from_str(&format!(
        r#"
tenants:
  - name: texc
    token_sha256: {texc}
    max_cost_usd_per_day: 10
  - name: onto
    token_sha256: {onto}
    models: ["gpt-*"]
    providers:
      - kind: openai
        base_url: {upstream}/v1
        api_key_file: {onto_key}
  - name: cheap
    token_sha256: {cheap}
    max_cost_usd_per_day: 0.000001
"#,
        texc = sha("tok-texc"),
        onto = sha("tok-onto"),
        cheap = sha("tok-cheap"),
        onto_key = onto_key.display(),
    ))
    .unwrap();
    let audit = Lines::default();
    let gw = Gateway::new(Settings {
        tenants,
        contract: Some(Contract {
            upstream: Upstream::Provider(ProviderConnection {
                kind: ProviderKind::Anthropic,
                base_url: upstream.clone(),
                key: Some(SecretSource::File(platform_key)),
            }),
            model: "claude-opus-5-5".into(),
            model_small: Some("claude-haiku-5-5".into()),
            timeout: None,
            max_retries: None,
        }),
        audit_payloads: false,
        audit: AuditWriter::with_sink(SERVICE, "", vec![], Box::new(audit.clone())),
    })
    .unwrap();
    let (addr, _) = standalone::serve(gw, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    Rig {
        url: format!("http://{addr}"),
        seen,
        audit,
        tmp,
    }
}

struct Answer {
    status: u16,
    headers: reqwest::header::HeaderMap,
    text: String,
}

impl Answer {
    fn rule(&self) -> &str {
        self.headers
            .get("x-agentsc-rule")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

async fn call(rig: &Rig, path: &str, auth: Option<(&str, &str)>, body: Value) -> Answer {
    let mut req = reqwest::Client::new()
        .post(format!("{}{path}", rig.url))
        .json(&body);
    if let Some((h, v)) = auth {
        req = req.header(h, v);
    }
    let r = req.send().await.unwrap();
    Answer {
        status: r.status().as_u16(),
        headers: r.headers().clone(),
        text: r.text().await.unwrap(),
    }
}

fn messages(stream: bool) -> Value {
    json!({"model": "claude-opus-5-5", "max_tokens": 256, "stream": stream,
           "messages": [{"role": "user", "content": "hi"}]})
}

/// Records are written once the answer was read to the end: wait for the n-th.
async fn record(rig: &Rig, n: usize) -> Value {
    for _ in 0..100 {
        let all = rig.audit.records();
        if all.len() > n {
            return all[n].clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no record {n}: {:?}", rig.audit.records());
}

#[tokio::test]
async fn callers_need_a_tenant_token() {
    let rig = rig().await;
    for auth in [
        None,
        Some(("authorization", "Bearer tok-nobody")),
        Some(("x-api-key", "tok-texc ")),
    ] {
        let a = call(&rig, "/v1/messages", auth, messages(false)).await;
        if auth.is_some_and(|(_, v)| v == "tok-texc ") {
            assert_eq!(a.status, 200, "x-api-key works too (trimmed)");
            continue;
        }
        assert_eq!(a.status, 401, "{auth:?}");
        assert_eq!(a.headers["www-authenticate"], "Bearer");
        assert_eq!(a.rule(), "auth.unauthenticated");
        let body: Value = serde_json::from_str(&a.text).unwrap();
        assert_eq!(
            body["error"]["type"], "authentication_error",
            "the Anthropic error shape"
        );
    }
    assert_eq!(
        rig.seen.all().len(),
        1,
        "nothing unauthenticated reached the upstream"
    );
    let models = reqwest::Client::new()
        .get(format!("{}/v1/models", rig.url))
        .bearer_auth("tok-texc")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(models["data"][0]["id"], "claude-opus-5-5");
    assert_eq!(models["data"][1]["id"], "claude-haiku-5-5");
}

#[tokio::test]
async fn the_platform_key_is_the_gateways_and_its_file_is_read_for_every_call() {
    let rig = rig().await;
    let a = call(
        &rig,
        "/v1/messages",
        Some(("authorization", "Bearer tok-texc")),
        messages(false),
    )
    .await;
    assert_eq!(a.status, 200, "{}", a.text);
    let (path, headers, body) = rig.seen.last();
    assert_eq!(path, "/v1/messages");
    assert_eq!(headers["x-api-key"], "sk-ant-platform-1");
    assert!(
        headers.get("authorization").is_none(),
        "the caller's token never goes upstream"
    );
    assert_eq!(body["model"], "claude-opus-5-5");
    let rec = record(&rig, 0).await;
    assert_eq!(
        (
            rec["kind"].as_str(),
            rec["caller"].as_str(),
            rec["callee"].as_str()
        ),
        (
            Some("model_call"),
            Some("tenant:texc"),
            Some("anthropic:claude-opus-5-5")
        )
    );
    assert_eq!(rec["tokens"], json!({"input": 1000, "output": 50}));
    // 1000 × $4 + 50 × $20 per 1M tokens
    assert_eq!(rec["cost_usd"], 0.005);
    assert_eq!(
        rec["input"],
        json!({"wire": "anthropic-messages", "model": "claude-opus-5-5", "stream": false}),
        "no prompt without --audit-payloads"
    );

    // the Secret is rotated: the next call carries the new key
    write(rig.tmp.path(), "platform-key", "sk-ant-platform-2");
    let a = call(
        &rig,
        "/v1/messages",
        Some(("authorization", "Bearer tok-texc")),
        messages(true),
    )
    .await;
    assert_eq!(a.status, 200);
    assert!(a.text.contains("message_stop"), "streamed through");
    assert_eq!(rig.seen.last().1["x-api-key"], "sk-ant-platform-2");
    assert_eq!(
        record(&rig, 1).await["tokens"],
        json!({"input": 1000, "output": 50})
    );
}

#[tokio::test]
async fn a_tenants_own_key_serves_both_openai_formats() {
    let rig = rig().await;
    let chat =
        json!({"model": "gpt-5", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let a = call(
        &rig,
        "/v1/chat/completions",
        Some(("authorization", "Bearer tok-onto")),
        chat,
    )
    .await;
    assert_eq!(a.status, 200, "{}", a.text);
    assert!(a.text.contains("[DONE]"));
    let (path, headers, body) = rig.seen.last();
    assert_eq!(path, "/v1/chat/completions");
    assert_eq!(
        headers["authorization"], "Bearer sk-onto-own",
        "the tenant's key"
    );
    assert_eq!(
        body["stream_options"],
        json!({"include_usage": true}),
        "the gateway asks for the usage"
    );
    let rec = record(&rig, 0).await;
    assert_eq!(
        (rec["caller"].as_str(), rec["callee"].as_str()),
        (Some("tenant:onto"), Some("openai:gpt-5"))
    );
    assert_eq!(rec["tokens"], json!({"input": 2000, "output": 100}));
    assert!(
        rec["cost_usd"].as_f64().unwrap() > 0.0,
        "gpt-5 is not in the table: the top tier"
    );

    let responses = json!({"model": "gpt-5", "stream": true, "input": "hi",
        "tools": [{"type": "function", "name": "shell", "parameters": {}}]});
    let a = call(
        &rig,
        "/v1/responses",
        Some(("x-api-key", "tok-onto")),
        responses,
    )
    .await;
    assert_eq!(a.status, 200, "{}", a.text);
    assert_eq!(rig.seen.last().0, "/v1/responses");
    assert_eq!(
        record(&rig, 1).await["tokens"],
        json!({"input": 3000, "output": 200})
    );
}

#[tokio::test]
async fn calls_are_held_to_formats_models_tools_and_budgets() {
    let rig = rig().await;
    let texc = Some(("authorization", "Bearer tok-texc"));
    // Anthropic speaks Messages only; no translation
    let a = call(
        &rig,
        "/v1/responses",
        texc,
        json!({"model": "claude-opus-5-5", "input": "hi"}),
    )
    .await;
    assert_eq!((a.status, a.rule()), (400, "model.wire_unsupported"));
    let body: Value = serde_json::from_str(&a.text).unwrap();
    assert_eq!(
        body["error"]["code"], "model.wire_unsupported",
        "the OpenAI error shape"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("/v1/messages")
    );
    // onto may call gpt-* only, and its own provider speaks OpenAI only
    let onto = Some(("authorization", "Bearer tok-onto"));
    let a = call(&rig, "/v1/messages", onto, messages(false)).await;
    assert_eq!((a.status, a.rule()), (403, "model.not_allowed"));
    let a = call(
        &rig,
        "/v1/messages",
        onto,
        json!({"model": "gpt-5", "max_tokens": 8, "messages": []}),
    )
    .await;
    assert_eq!((a.status, a.rule()), (400, "model.wire_unsupported"));
    // a hosted tool bills outside the token price and acts outside the tool policy
    let a = call(
        &rig,
        "/v1/responses",
        onto,
        json!({"model": "gpt-5", "input": "hi", "tools": [{"type": "web_search"}]}),
    )
    .await;
    assert_eq!((a.status, a.rule()), (400, "model.request_invalid"));
    // the budget holds before the call goes out
    let a = call(
        &rig,
        "/v1/messages",
        Some(("authorization", "Bearer tok-cheap")),
        messages(false),
    )
    .await;
    assert_eq!((a.status, a.rule()), (403, "budget.max_cost_usd_per_day"));
    assert!(
        rig.seen.all().is_empty(),
        "no refused call reached the upstream"
    );
    let kinds: Vec<String> = rig
        .audit
        .records()
        .iter()
        .map(|r| {
            format!(
                "{} {}",
                r["kind"].as_str().unwrap(),
                r["rule"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "authz model.wire_unsupported",
            "authz model.not_allowed",
            "authz model.wire_unsupported",
            "authz model.request_invalid",
            "budget budget.max_cost_usd_per_day"
        ]
    );
}

/// The review finding: Responses stores answers under the key that made them, and
/// `previous_response_id` / `item_reference` pull stored state into the prompt, uncounted. On the
/// platform's key (shared by its tenants) nothing is stored and nothing stored is referred to; on
/// a tenant's own key stored state is its own, and reserves the model's whole context window.
#[tokio::test]
async fn stored_responses_are_never_shared_on_the_platform_key() {
    let seen = Seen::default();
    let app = axum::Router::new()
        .route("/v1/responses", post(fake))
        .with_state(seen.clone());
    let upstream = format!("http://{}", serve_app(app).await);
    let tmp = tempfile::tempdir().unwrap();
    let platform_key = write(tmp.path(), "platform-key", "sk-platform");
    let own_key = write(tmp.path(), "own-key", "sk-own");
    let tenants: standalone::TenantsFile = serde_yaml_ng::from_str(&format!(
        r#"
tenants:
  - name: shared
    token_sha256: {shared}
  - name: byo
    token_sha256: {byo}
    max_cost_usd_per_day: 1
    providers: [{{kind: openai, base_url: "{upstream}/v1", api_key_file: "{own_key}"}}]
"#,
        shared = sha("tok-shared"),
        byo = sha("tok-byo"),
        own_key = own_key.display(),
    ))
    .unwrap();
    let gw = Gateway::new(Settings {
        tenants,
        contract: Some(Contract {
            upstream: Upstream::Provider(ProviderConnection {
                kind: ProviderKind::OpenAi,
                base_url: format!("{upstream}/v1"),
                key: Some(SecretSource::File(platform_key)),
            }),
            model: "gpt-5".into(),
            model_small: None,
            timeout: None,
            max_retries: None,
        }),
        audit_payloads: false,
        audit: AuditWriter::with_sink(SERVICE, "", vec![], Box::new(std::io::sink())),
    })
    .unwrap();
    let (addr, _) = standalone::serve(gw, "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let rig = Rig {
        url: format!("http://{addr}"),
        seen,
        audit: Lines::default(),
        tmp,
    };
    let shared = Some(("authorization", "Bearer tok-shared"));
    let byo = Some(("authorization", "Bearer tok-byo"));
    let ask = |extra: Value| {
        let mut b =
            json!({"model": "gpt-5", "stream": true, "input": "hi", "max_output_tokens": 256});
        b.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        b
    };
    let referenced = json!({"input": [{"type": "item_reference", "id": "msg_other_tenant"}]});
    let continued = json!({"previous_response_id": "resp_other_tenant"});

    // the platform's key: nothing stored, even when asked
    for extra in [json!({}), json!({"store": true})] {
        let a = call(&rig, "/v1/responses", shared, ask(extra)).await;
        assert_eq!(a.status, 200, "{}", a.text);
        let (_, headers, body) = rig.seen.last();
        assert_eq!(headers["authorization"], "Bearer sk-platform");
        assert_eq!(body["store"], false);
    }
    for extra in [referenced.clone(), continued.clone()] {
        let a = call(&rig, "/v1/responses", shared, ask(extra)).await;
        assert_eq!(
            (a.status, a.rule()),
            (400, "model.request_invalid"),
            "{}",
            a.text
        );
        assert!(
            a.text.contains("stored under the platform's key"),
            "{}",
            a.text
        );
    }
    assert_eq!(rig.seen.all().len(), 2, "no reference reached the upstream");

    // the tenant's own key: storing is its business; stored state reserves the context window
    let a = call(&rig, "/v1/responses", byo, ask(json!({}))).await;
    assert_eq!(a.status, 200, "{}", a.text);
    let (_, headers, body) = rig.seen.last();
    assert_eq!(headers["authorization"], "Bearer sk-own");
    assert!(body.get("store").is_none(), "left as the tenant sent it");
    for extra in [referenced, continued] {
        let a = call(&rig, "/v1/responses", byo, ask(extra)).await;
        assert_eq!(
            (a.status, a.rule()),
            (403, "budget.max_cost_usd_per_day"),
            "{}",
            a.text
        );
    }
}
