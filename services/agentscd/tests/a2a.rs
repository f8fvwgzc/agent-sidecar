//! A2A 1.0 (charter schema level 10, docs/design/a2a.md), both ways:
//!
//! - the sidecar's A2A server: agent cards, caller tokens, `SendMessage` as an invocation by
//!   `a2a:<name>` that starts untrusted, `ask_caller` questions as `TASK_STATE_INPUT_REQUIRED` and
//!   the next message as their answer, `GetTask` and `CancelTask` for the caller's own tasks;
//! - `type: a2a` tools against a fake A2A agent: the sidecar builds the message and headers,
//!   polls a working task, renders the task for the model and leaves an `a2a_call` record.
mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use agentsc_charter::{A2aSpec, CallerRule, TaintLabel, TaintMode, TaintSpec, ToolSpec};
use agentsc_common::a2a::{ROLE_USER, code, state};
use agentsc_proto::ToolArgumentsRequest;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use common::*;
use serde_json::{Value, json};

const SERVED: &str = "order-triage";
const CALLER: &str = "ops-assistant";
const PARTNER_TOKEN: &str = "partner-token-1";
const OTHER_TOKEN: &str = "other-token-2";

/// A sidecar serving `order-triage` over A2A to the callers `a2a:partner` and `a2a:other`. Its
/// runtime asks "Card or credit?" until the context carries answers.
async fn served_rig() -> (Rig, String, tempfile::TempDir) {
    let callers = tempfile::tempdir().unwrap();
    std::fs::write(callers.path().join("partner"), format!("{PARTNER_TOKEN}\n")).unwrap();
    std::fs::write(callers.path().join("other"), OTHER_TOKEN).unwrap();
    let dir = callers.path().to_path_buf();
    let runtime = FakeRuntime::with(|req| {
        Box::pin(async move {
            if req.context_json.contains("answers") {
                ok("Refunded as store credit.")
            } else {
                asked(&[("Card or credit?", "Credit, the card expired.")])
            }
        })
    });
    let rig = rig(
        runtime,
        |c| {
            let a = c.agents.iter_mut().find(|a| a.name == SERVED).unwrap();
            a.a2a = Some(A2aSpec {
                description: "Triage of order problems: refunds, delays, damage.".into(),
                skills: Vec::new(),
            });
            a.taint = Some(TaintSpec {
                mode: TaintMode::Enforce,
                input: TaintLabel::Trusted,
            });
            for name in ["partner", "other"] {
                c.authz.callers.push(CallerRule {
                    identity: format!("a2a:{name}"),
                    agents: vec![SERVED.into()],
                    caller_agents: Vec::new(),
                });
            }
            c.validate()
                .expect("the charter with an a2a agent is valid");
        },
        move |cfg| {
            cfg.a2a_addr = Some(SocketAddr::from(([127, 0, 0, 1], 0)));
            cfg.a2a_public_url = Some("https://agents.example.com/".into());
            cfg.a2a_callers_dir = dir;
        },
    )
    .await;
    let base = format!("http://{}", rig.sidecar.state.a2a_bound.get().unwrap());
    (rig, base, callers)
}

async fn rpc(
    base: &str,
    token: Option<&str>,
    version: Option<&str>,
    method: &str,
    params: Value,
) -> (u16, Value) {
    let mut req = reqwest::Client::new()
        .post(format!("{base}/a2a/{SERVED}"))
        .json(&json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params}));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    if let Some(v) = version {
        req = req.header("A2A-Version", v);
    }
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

async fn call(base: &str, token: &str, method: &str, params: Value) -> Value {
    let (status, v) = rpc(base, Some(token), Some("1.0"), method, params).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["id"], 7, "{v}");
    v
}

fn message(text: &str, task_id: Option<&str>) -> Value {
    let mut m = json!({"message": {"messageId": uuid::Uuid::new_v4().to_string(), "role": ROLE_USER,
                                   "parts": [{"text": text}]}});
    if let Some(t) = task_id {
        m["message"]["taskId"] = json!(t);
    }
    m
}

#[tokio::test]
async fn the_a2a_server_publishes_cards_and_turns_questions_into_input_required_tasks() {
    let (rig, base, _callers) = served_rig().await;
    let http = reqwest::Client::new();

    // the card: the only served agent, also at the well-known path of the server
    let card: Value = http
        .get(format!("{base}/.well-known/agent-card.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(card["name"], SERVED);
    assert_eq!(
        card["supportedInterfaces"][0]["url"],
        "https://agents.example.com/a2a/order-triage"
    );
    assert_eq!(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC");
    assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
    assert_eq!(card["skills"][0]["id"], SERVED);
    assert_eq!(
        card["securitySchemes"]["bearer"]["httpAuthSecurityScheme"]["scheme"],
        "Bearer"
    );
    assert_eq!(card["capabilities"]["streaming"], false);
    let same: Value = http
        .get(format!("{base}/a2a/{SERVED}/.well-known/agent-card.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(same, card);
    // an agent without an a2a block is not there at all
    let r = http
        .get(format!("{base}/a2a/{CALLER}/.well-known/agent-card.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let r = http
        .post(format!("{base}/a2a/{CALLER}"))
        .bearer_auth(PARTNER_TOKEN)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // no token, or a wrong one: 401 and an authz record
    let (status, v) = rpc(&base, None, Some("1.0"), "SendMessage", message("hi", None)).await;
    assert_eq!(status, 401, "{v}");
    let (status, _) = rpc(
        &base,
        Some("nope"),
        Some("1.0"),
        "SendMessage",
        message("hi", None),
    )
    .await;
    assert_eq!(status, 401);
    wait_audit(&rig.audit, 2, |r| r["rule"] == "a2a.unauthenticated").await;

    // A2A 0.3 (no version header) is refused
    let (_, v) = rpc(
        &base,
        Some(PARTNER_TOKEN),
        None,
        "SendMessage",
        message("hi", None),
    )
    .await;
    assert_eq!(v["error"]["code"], code::VERSION_NOT_SUPPORTED, "{v}");

    // the run asks: an input-required task with the questions as text and as data
    let v = call(
        &base,
        PARTNER_TOKEN,
        "SendMessage",
        message("Order 7 arrived broken.", None),
    )
    .await;
    let task = &v["result"]["task"];
    assert_eq!(task["status"]["state"], state::INPUT_REQUIRED, "{v}");
    let id = task["id"].as_str().unwrap().to_string();
    let parts = &task["status"]["message"]["parts"];
    assert!(
        parts[0]["text"]
            .as_str()
            .unwrap()
            .contains("Card or credit?"),
        "{parts}"
    );
    assert_eq!(
        parts[1]["data"]["questions"][0]["recommended"],
        "Credit, the card expired."
    );
    // the invocation's caller is the A2A identity, and the run starts untrusted
    let inv = wait_audit(&rig.audit, 1, |r| {
        r["kind"] == "agent_invocation" && r["caller"] == "a2a:partner"
    })
    .await;
    let rid = inv[0]["request_id"].as_str().unwrap().to_string();
    assert_eq!(task["metadata"]["agentsc.io/request_id"], rid);
    assert!(
        rig.sidecar
            .state
            .taint
            .labels(&rid)
            .contains(&TaintLabel::Untrusted)
    );

    // another caller cannot see or answer the task
    let v = call(&base, OTHER_TOKEN, "GetTask", json!({"id": id})).await;
    assert_eq!(v["error"]["code"], code::TASK_NOT_FOUND, "{v}");
    let v = call(
        &base,
        OTHER_TOKEN,
        "SendMessage",
        message("Credit", Some(&id)),
    )
    .await;
    assert_eq!(v["error"]["code"], code::TASK_NOT_FOUND, "{v}");

    // the answer: the same input again, with the question and the answer in context.answers
    let v = call(
        &base,
        PARTNER_TOKEN,
        "SendMessage",
        message("Store credit, please.", Some(&id)),
    )
    .await;
    let task = &v["result"]["task"];
    assert_eq!(task["id"], id.as_str());
    assert_eq!(task["status"]["state"], state::COMPLETED, "{v}");
    assert_eq!(
        task["artifacts"][0]["parts"][0]["text"],
        "Refunded as store credit."
    );
    let runs = rig.runtime.seen();
    let last = runs.last().unwrap();
    assert_eq!(last.input, "Order 7 arrived broken.");
    let ctx: Value = serde_json::from_str(&last.context_json).unwrap();
    assert_eq!(
        ctx["answers"],
        json!([{"question": "Card or credit?", "answer": "Store credit, please."}])
    );

    // GetTask shows it; a finished task takes no more messages and cannot be canceled
    let v = call(&base, PARTNER_TOKEN, "GetTask", json!({"id": id})).await;
    assert_eq!(v["result"]["status"]["state"], state::COMPLETED, "{v}");
    let v = call(
        &base,
        PARTNER_TOKEN,
        "SendMessage",
        message("again", Some(&id)),
    )
    .await;
    assert_eq!(v["error"]["code"], code::UNSUPPORTED_OPERATION, "{v}");
    let v = call(&base, PARTNER_TOKEN, "CancelTask", json!({"id": id})).await;
    assert_eq!(v["error"]["code"], code::TASK_NOT_CANCELABLE, "{v}");

    // a task waiting for input can be canceled
    let v = call(
        &base,
        PARTNER_TOKEN,
        "SendMessage",
        message("Order 8 is late.", None),
    )
    .await;
    let id2 = v["result"]["task"]["id"].as_str().unwrap().to_string();
    let v = call(&base, PARTNER_TOKEN, "CancelTask", json!({"id": id2})).await;
    assert_eq!(v["result"]["status"]["state"], state::CANCELED, "{v}");

    // what the server does not do, and what is not A2A
    let v = call(
        &base,
        PARTNER_TOKEN,
        "SendStreamingMessage",
        message("x", None),
    )
    .await;
    assert_eq!(v["error"]["code"], code::UNSUPPORTED_OPERATION);
    let v = call(&base, PARTNER_TOKEN, "Nope", json!({})).await;
    assert_eq!(v["error"]["code"], code::METHOD_NOT_FOUND);
    let v = call(
        &base,
        PARTNER_TOKEN,
        "SendMessage",
        json!({"message": {"messageId": "m", "role": ROLE_USER,
        "parts": [{"url": "https://files.example/x.pdf"}]}}),
    )
    .await;
    assert_eq!(v["error"]["code"], code::CONTENT_TYPE_NOT_SUPPORTED);
    let v = call(
        &base,
        PARTNER_TOKEN,
        "SendMessage",
        json!({"message": {"messageId": "m", "role": "ROLE_AGENT",
        "parts": [{"text": "x"}]}}),
    )
    .await;
    assert_eq!(v["error"]["code"], code::INVALID_PARAMS);
}

// ---- type: a2a tools ---------------------------------------------------------------------------

/// What the fake agent was sent.
#[derive(Default)]
struct Agent {
    seen: Mutex<Vec<(HeaderMap, Value)>>,
    polls: Mutex<usize>,
}

/// A2A 1.0 over JSON-RPC: "Quote …" asks for the currency; an answer (a `taskId`) completes;
/// "slow" is working until the second `GetTask`; "boom" is a JSON-RPC error.
async fn agent(
    State(s): State<Arc<Agent>>,
    headers: HeaderMap,
    Json(m): Json<Value>,
) -> Json<Value> {
    s.seen.lock().unwrap().push((headers, m.clone()));
    let id = m["id"].clone();
    let task = |tid: &str, st: &str, extra: Value| {
        let mut t = json!({"id": tid, "contextId": "c-1", "status": {"state": st}});
        if let Value::Object(e) = extra {
            t.as_object_mut().unwrap().extend(e);
        }
        t
    };
    let result = match m["method"].as_str() {
        Some("SendMessage") => {
            let msg = &m["params"]["message"];
            let text = msg["parts"][0]["text"].as_str().unwrap_or("");
            if text == "boom" {
                return Json(
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32603, "message": "quote engine down"}}),
                );
            }
            let t = if msg.get("taskId").is_some() {
                task(
                    "t-1",
                    state::COMPLETED,
                    json!({"artifacts": [{"artifactId": "a", "parts": [{"text": "EUR 380"}]}]}),
                )
            } else if text == "slow" {
                task("t-2", state::WORKING, json!({}))
            } else {
                task(
                    "t-1",
                    state::INPUT_REQUIRED,
                    json!({"status": {"state": state::INPUT_REQUIRED,
                    "message": {"messageId": "m", "role": "ROLE_AGENT", "parts": [{"text": "Which currency?"}]}}}),
                )
            };
            json!({"task": t})
        }
        Some("GetTask") => {
            let mut polls = s.polls.lock().unwrap();
            *polls += 1;
            if *polls < 2 {
                task("t-2", state::WORKING, json!({}))
            } else {
                task(
                    "t-2",
                    state::COMPLETED,
                    json!({"artifacts": [{"artifactId": "a", "parts": [{"text": "done late"}]}]}),
                )
            }
        }
        _ => {
            return Json(
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no"}}),
            );
        }
    };
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn a2a_call(tool: &str, request_id: &str, args: Value) -> ToolArgumentsRequest {
    ToolArgumentsRequest {
        ctx: ctx(CALLER, tool, request_id, "00f067aa0ba902b7"),
        arguments_json: args.to_string(),
    }
}

#[tokio::test]
async fn an_a2a_tool_sends_the_message_answers_input_required_and_is_audited() {
    let s = Arc::new(Agent::default());
    let addr = serve_app(
        Router::new()
            .route("/a2a/quotes", post(agent))
            .with_state(s.clone()),
    )
    .await;
    let secrets = tempfile::tempdir().unwrap();
    std::fs::write(secrets.path().join("partner"), "tool-token-9\n").unwrap();
    let dir = secrets.path().to_path_buf();
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| {
            let t: ToolSpec = serde_json::from_value(json!({
                "name": "partner_quotes", "type": "a2a", "description": "Quotes from the partner's agent.",
                "url": format!("http://{addr}/a2a/quotes"), "credential": {"secret": "partner"}}))
            .unwrap();
            let a = c.agents.iter_mut().find(|a| a.name == CALLER).unwrap();
            a.tools.push(t);
            c.guardrails.allowed_tools.get_mut(CALLER).unwrap().push("partner_quotes".into());
            c.validate().expect("the charter with an a2a tool is valid");
        },
        move |cfg| cfg.tool_secrets_dir = dir,
    )
    .await;
    // the runtime is offered the fixed parameters
    let mut tools = tools(&rig.sock).await;
    let _run = in_flight(&rig.sidecar, "r1", CALLER);

    let out = tools
        .invoke_a2a(a2a_call(
            "partner_quotes",
            "r1",
            json!({"input": "Quote 40 WIDGET-1"}),
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!out.is_error, "{}", out.text);
    assert!(out.text.contains("task_id \"t-1\""), "{}", out.text);
    assert!(out.text.ends_with("Which currency?"), "{}", out.text);
    let (headers, sent) = s.seen.lock().unwrap()[0].clone();
    assert_eq!(headers["authorization"], "Bearer tool-token-9");
    assert_eq!(headers["a2a-version"], "1.0");
    assert!(headers.contains_key("traceparent"));
    assert_eq!(sent["method"], "SendMessage");
    assert_eq!(sent["params"]["message"]["role"], ROLE_USER);
    assert_eq!(
        sent["params"]["message"]["parts"][0]["text"],
        "Quote 40 WIDGET-1"
    );
    assert_eq!(sent["params"]["configuration"]["returnImmediately"], false);

    // the model answers with the task_id; a context goes as a data part
    let out = tools
        .invoke_a2a(a2a_call(
            "partner_quotes",
            "r1",
            json!({"input": "EUR", "task_id": "t-1", "context": {"order": 7}}),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.text, "EUR 380");
    let (_, sent) = s.seen.lock().unwrap()[1].clone();
    assert_eq!(sent["params"]["message"]["taskId"], "t-1");
    assert_eq!(
        sent["params"]["message"]["parts"][1]["data"],
        json!({"order": 7})
    );

    // a working task is polled with GetTask until it is done
    let out = tools
        .invoke_a2a(a2a_call("partner_quotes", "r1", json!({"input": "slow"})))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(out.text, "done late");
    assert_eq!(*s.polls.lock().unwrap(), 2);

    // a JSON-RPC error is the agent's text: Unavailable with a2a.error
    let st = tools
        .invoke_a2a(a2a_call("partner_quotes", "r1", json!({"input": "boom"})))
        .await
        .unwrap_err();
    assert_eq!(st.code(), tonic::Code::Unavailable);
    assert_eq!(st.metadata().get("x-agentsc-rule").unwrap(), "a2a.error");
    assert!(
        st.message().contains("quote engine down"),
        "{}",
        st.message()
    );

    // only input, context and task_id, and only the types the tool takes
    for bad in [
        json!({"input": 3}),
        json!({"input": "x", "url": "https://evil.example"}),
        json!({"input": "x", "context": [1]}),
    ] {
        let st = tools
            .invoke_a2a(a2a_call("partner_quotes", "r1", bad.clone()))
            .await
            .unwrap_err();
        assert_eq!(st.code(), tonic::Code::PermissionDenied, "{bad}");
    }
    // 3 messages, 2 polls and the error: the refused calls sent nothing
    assert_eq!(s.seen.lock().unwrap().len(), 6);

    // the records: an a2a_call per sent message, with the rendered state
    let recs = wait_audit(&rig.audit, 4, |r| r["kind"] == "a2a_call").await;
    assert_eq!(recs[0]["callee"], format!("a2a http://{addr}"));
    assert_eq!(recs[0]["output"]["state"], state::INPUT_REQUIRED);
    assert_eq!(recs[0]["output"]["task_id"], "t-1");
    assert_eq!(recs[0]["input"]["url"], format!("http://{addr}/a2a/quotes"));
    assert!(
        rig.sidecar.state.loaded().unwrap().runtime_spec(CALLER)["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| {
                t["name"] == "partner_quotes"
                    && t["parameters"]["required"] == json!(["input"])
                    && t.get("credential").is_none()
            })
    );
}
