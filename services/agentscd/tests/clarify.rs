//! Questions to the caller against a real sidecar (docs/design/agent-practices.md, Wire): the
//! sidecar treats a run's questions as model output (clarify: never, max_questions, the
//! 1000-character cut, output_deny, pii_redact), renders `output` from the questions it keeps,
//! returns them over HTTP, gRPC and the mesh, and audits the run with rule `clarify.asked`
//! (CONTRACT.md §4.1, §6).
mod common;

use agentsc_charter::{Charter, Clarify, PracticesSpec, RegexRule};
use agentsc_common::audit::sha256_hex;
use agentsc_proto::app_api_client::AppApiClient;
use agentsc_proto::{ExecuteResponse, InvokeAgentRequest, Question, ToolAgentRequest};
use agentscd::pipeline::{MAX_QUESTION_CHARS, RULE_CLARIFY_ASKED, render_questions};
use common::*;
use serde_json::{Value, json};

const SPAN: &str = "00f067aa0ba902b7";
const INVENTORY: &str = include_str!("../../../examples/charters/inventory.charter.yaml");
const DENY_RULE: &str = "guardrail.output_deny.no-keys";

const REFUND: (&str, &str) = (
    "Refund to the card or as store credit?",
    "Store credit, because the card on the order has expired.",
);
const NOTIFY: (&str, &str) = ("Tell the customer now?", "Yes, before the refund.");

fn q(question: &str, recommended: &str) -> Question {
    Question {
        question: question.into(),
        recommended: recommended.into(),
    }
}

/// A runtime that answers every Execute with `resp`.
fn returning(resp: ExecuteResponse) -> FakeRuntime {
    FakeRuntime::with(move |_| {
        let resp = resp.clone();
        Box::pin(async move { resp })
    })
}

/// The questions of an HTTP response body.
fn questions_of(v: &Value) -> Vec<Question> {
    v["questions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            q(
                x["question"].as_str().unwrap(),
                x["recommended"].as_str().unwrap(),
            )
        })
        .collect()
}

fn practices(c: &mut Charter, agent: &str, p: PracticesSpec) {
    let a = c.agents.iter_mut().find(|a| a.name == agent).unwrap();
    a.practices = Some(p);
}

fn no_keys(c: &mut Charter) {
    c.guardrails.output_deny.push(RegexRule {
        name: "no-keys".into(),
        regex: "sk-[A-Z0-9]+|TODO$".into(),
    });
}

async fn invocation_records(rig: &Rig, request_id: &str) -> Vec<Value> {
    wait_audit(&rig.audit, 1, |v| {
        v["request_id"] == request_id && v["kind"] == "agent_invocation"
    })
    .await
}

#[tokio::test]
async fn the_http_response_has_questions_only_when_the_runtime_asked() {
    let rt = FakeRuntime::with(|req| {
        Box::pin(async move {
            if req.input.contains("refund") {
                asked(&[REFUND, NOTIFY])
            } else {
                ok("Order 1001 shipped.")
            }
        })
    });
    let rig = rig(rt, |_| {}, |_| {}).await;

    let (code, v) = rig.invoke("ops-assistant", "refund order 1001").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["status"], "ok");
    assert_eq!(
        v["questions"],
        json!([
            { "question": REFUND.0, "recommended": REFUND.1 },
            { "question": NOTIFY.0, "recommended": NOTIFY.1 },
        ])
    );
    let output = v["output"].as_str().unwrap();
    assert!(
        output.contains(REFUND.0) && output.contains(NOTIFY.1),
        "{output}"
    );
    assert!(v.get("rule").is_none(), "an ok response has no rule: {v}");

    let (code, v) = rig.invoke("ops-assistant", "where is order 1001?").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["output"], "Order 1001 shipped.");
    assert!(v.get("questions").is_none(), "no questions key: {v}");
    rig.sidecar.abort();
}

#[tokio::test]
async fn questions_over_max_questions_are_dropped_and_long_strings_cut() {
    // ops-assistant keeps 2 per round; order-triage has no practices block, so the default 5
    let rt = FakeRuntime::with(|_| {
        Box::pin(async move {
            let long = "é".repeat(MAX_QUESTION_CHARS + 500);
            let mut qs = vec![q(&long, &long)];
            qs.extend((2..=7).map(|i| q(&format!("Question {i}?"), &format!("Answer {i}."))));
            ExecuteResponse {
                questions: qs,
                ..ok("I need these decisions from you before I go on.")
            }
        })
    });
    let rig = rig(
        rt,
        |c| {
            practices(
                c,
                "ops-assistant",
                PracticesSpec {
                    max_questions: 2,
                    ..Default::default()
                },
            )
        },
        |_| {},
    )
    .await;

    let (code, v) = rig.invoke("ops-assistant", "refund order 1001").await;
    assert_eq!(code, 200, "{v}");
    let qs = v["questions"].as_array().unwrap();
    assert_eq!(qs.len(), 2, "{v}");
    for s in [&qs[0]["question"], &qs[0]["recommended"]] {
        let s = s.as_str().unwrap();
        assert_eq!(
            s.chars().count(),
            MAX_QUESTION_CHARS,
            "cut on a character boundary"
        );
        assert!(s.chars().all(|c| c == 'é'));
    }
    assert_eq!(
        qs[1]["question"], "Question 2?",
        "a short string is kept whole"
    );
    assert_eq!(qs[1]["recommended"], "Answer 2.");

    let (code, v) = rig.invoke("order-triage", "triage order 1001").await;
    assert_eq!(code, 200, "{v}");
    let qs = v["questions"].as_array().unwrap();
    assert_eq!(qs.len(), PracticesSpec::default().max_questions as usize);
    assert_eq!(qs[4]["question"], "Question 5?");
    rig.sidecar.abort();
}

#[tokio::test]
async fn an_output_deny_match_in_a_question_denies_the_invocation() {
    let secret = "sk-QUESTION1";
    let late = format!("{} {secret}", "é".repeat(MAX_QUESTION_CHARS + 10));
    // the cut ends this one with "TODO": what the caller would get matches, the whole does not
    let cut_match = format!("{}TODO and more", "a".repeat(MAX_QUESTION_CHARS - 4));
    let rt = FakeRuntime::with(move |req| {
        let late = late.clone();
        let cut_match = cut_match.clone();
        Box::pin(async move {
            let qs = match req.input.as_str() {
                "in a question" => {
                    vec![q(REFUND.0, REFUND.1), q(&format!("Use {secret}?"), "Yes.")]
                }
                "in a recommended answer" => vec![q("Which key?", &format!("Use {secret}."))],
                "past the cut" => vec![q(&late, "Yes.")],
                "in the cut" => vec![q(&cut_match, "Yes.")],
                // the third question is dropped unseen: max_questions is 2
                _ => vec![
                    q(REFUND.0, REFUND.1),
                    q(NOTIFY.0, NOTIFY.1),
                    q(&format!("Use {secret}?"), "Yes."),
                ],
            };
            ExecuteResponse {
                questions: qs,
                ..ok("I need these decisions from you before I go on.")
            }
        })
    });
    let rig = rig(
        rt,
        |c| {
            no_keys(c);
            practices(
                c,
                "ops-assistant",
                PracticesSpec {
                    max_questions: 2,
                    ..Default::default()
                },
            );
        },
        |_| {},
    )
    .await;

    for input in [
        "in a question",
        "in a recommended answer",
        "past the cut",
        "in the cut",
    ] {
        let (code, v) = rig.invoke("ops-assistant", input).await;
        assert_eq!(code, 403, "{input}: {v}");
        assert_eq!(v["status"], "denied");
        assert_eq!(v["rule"], DENY_RULE, "{input}");
        assert_eq!(v["output"], "", "{input}: output withheld");
        assert!(
            v.get("questions").is_none(),
            "{input}: questions withheld: {v}"
        );
        let steps = v["steps"].as_array().unwrap();
        assert_eq!(steps.last().unwrap()["kind"], "guardrail", "{input}");
    }

    // The log keeps the hash of the matched string, never the string (CONTRACT.md §6).
    let (_, v) = rig.invoke("ops-assistant", "in a question").await;
    let rid = v["request_id"].as_str().unwrap();
    let inv = invocation_records(&rig, rid).await;
    assert_eq!(inv.len(), 1);
    assert_eq!(inv[0]["decision"], "deny");
    assert_eq!(inv[0]["rule"], DENY_RULE);
    assert!(inv[0]["output"].is_null(), "{}", inv[0]);
    let guard = rig.records(|r| r["request_id"] == rid && r["kind"] == "guardrail");
    assert_eq!(guard.len(), 1, "{guard:?}");
    assert_eq!(guard[0]["decision"], "deny");
    assert_eq!(guard[0]["output"], format!("[redacted:{DENY_RULE}]"));
    let matched = format!("Use {secret}?");
    assert_eq!(
        guard[0]["output_sha256"],
        sha256_hex(matched.as_bytes()).as_str()
    );
    let raw = std::fs::read_to_string(&rig.audit).unwrap();
    assert!(!raw.contains(secret), "{secret} in the audit log:\n{raw}");

    // a question over max_questions never reaches the caller, so it is not held against the run
    let (code, v) = rig.invoke("ops-assistant", "too many").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["questions"].as_array().unwrap().len(), 2);
    rig.sidecar.abort();
}

#[tokio::test]
async fn an_output_deny_match_in_the_rendered_or_redacted_text_denies_the_invocation() {
    // Neither string alone matches no-ssn; the rendering of the two does.
    let ssn = q("Use the SSN on file?", "123-45-6789");
    // Redaction lengthens the email, so the cut now ends the string with "TODO": what the
    // caller would get matches, while the raw string and its raw cut form do not.
    let shifted = format!("bob@example.com {}TODO and more", "a".repeat(979));
    // The cut brings SECRET within 30 characters of PART2: only the delivered rendering matches.
    let split = q(
        &format!("{}SECRET{}", "a".repeat(990), "x".repeat(50)),
        "PART2",
    );
    let rt = FakeRuntime::with({
        let (ssn, shifted, split) = (ssn.clone(), shifted.clone(), split.clone());
        move |req| {
            let qs = match req.input.as_str() {
                "across the strings" => vec![ssn.clone()],
                "after the cut" => vec![split.clone()],
                _ => vec![q(&shifted, "Yes.")],
            };
            Box::pin(async move {
                ExecuteResponse {
                    questions: qs,
                    ..ok("I need these decisions from you before I go on.")
                }
            })
        }
    });
    let rig = rig(
        rt,
        |c| {
            no_keys(c);
            c.guardrails.output_deny.push(RegexRule {
                name: "no-ssn".into(),
                regex: r"(?is)ssn.{0,40}\d{3}-\d{2}-\d{4}".into(),
            });
            c.guardrails.output_deny.push(RegexRule {
                name: "no-split".into(),
                regex: r"(?s)SECRET.{0,30}PART2".into(),
            });
        },
        |_| {},
    )
    .await;

    // the matched text is the one hashed in the guardrail record (CONTRACT.md §6)
    let delivered = format!("[redacted:email] {}TODO", "a".repeat(979));
    let split_delivered = q(
        &format!("{}SECRET{}", "a".repeat(990), "x".repeat(4)),
        "PART2",
    );
    assert_eq!(split_delivered.question.chars().count(), MAX_QUESTION_CHARS);
    assert_ne!(split_delivered.question, split.question);
    for (input, rule, matched) in [
        (
            "across the strings",
            "guardrail.output_deny.no-ssn",
            render_questions(&[ssn]),
        ),
        ("after redaction", DENY_RULE, delivered),
        (
            "after the cut",
            "guardrail.output_deny.no-split",
            render_questions(&[split_delivered]),
        ),
    ] {
        let (code, v) = rig.invoke("ops-assistant", input).await;
        assert_eq!(code, 403, "{input}: {v}");
        assert_eq!(v["status"], "denied");
        assert_eq!(v["rule"], rule, "{input}");
        assert_eq!(v["output"], "", "{input}: output withheld");
        assert!(
            v.get("questions").is_none(),
            "{input}: questions withheld: {v}"
        );
        let rid = v["request_id"].as_str().unwrap();
        let inv = invocation_records(&rig, rid).await;
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0]["decision"], "deny");
        assert!(inv[0]["output"].is_null(), "{input}: {}", inv[0]);
        let guard = rig.records(|r| r["request_id"] == rid && r["kind"] == "guardrail");
        assert_eq!(guard.len(), 1, "{input}: {guard:?}");
        assert_eq!(guard[0]["output"], format!("[redacted:{rule}]"));
        assert_eq!(
            guard[0]["output_sha256"],
            sha256_hex(matched.as_bytes()).as_str(),
            "{input}"
        );
    }
    let raw = std::fs::read_to_string(&rig.audit).unwrap();
    assert!(!raw.contains("123-45-6789"), "the SSN in the log:\n{raw}");
    rig.sidecar.abort();
}

#[tokio::test]
async fn pii_is_redacted_before_the_cut() {
    // cut first, the string would end "bob@exampl", which the redaction no longer recognises
    let long = format!("{} bob@example.com", "a".repeat(989));
    let rig = rig(FakeRuntime::asking(&[(&long, "Yes.")]), |_| {}, |_| {}).await;
    let (code, v) = rig.invoke("ops-assistant", "refund order 1001").await;
    assert_eq!(code, 200, "{v}");
    let question = v["questions"][0]["question"].as_str().unwrap();
    assert_eq!(question, format!("{} [redacted:", "a".repeat(989)));
    assert_eq!(question.chars().count(), MAX_QUESTION_CHARS);
    assert!(!question.contains("bob@"), "{question}");
    assert_eq!(v["output"], render_questions(&questions_of(&v)));
    rig.sidecar.abort();
}

#[tokio::test]
async fn pii_redact_rewrites_emails_in_questions_and_recommended_answers() {
    // the runtime's output renders the questions too, so each email is in it once more
    let ask = || {
        FakeRuntime::asking(&[(
            "Send the refund note to bob@example.com?",
            "Yes, to bob@example.com, the address on the order.",
        )])
    };
    // the orders charter has pii_redact on
    let rig_on = rig(ask(), |_| {}, |_| {}).await;
    let (code, v) = rig_on.invoke("ops-assistant", "refund order 1001").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        v["questions"],
        json!([{
            "question": "Send the refund note to [redacted:email]?",
            "recommended": "Yes, to [redacted:email], the address on the order.",
        }])
    );
    assert_eq!(v["output"], render_questions(&questions_of(&v)));
    let rid = v["request_id"].as_str().unwrap();
    let guard = wait_audit(&rig_on.audit, 1, |r| {
        r["request_id"] == rid && r["rule"] == "guardrail.pii_redact"
    })
    .await;
    assert_eq!(guard.len(), 1, "{guard:?}");
    // the rendered output is built from the redacted strings: no email counts twice
    assert_eq!(guard[0]["output"]["redactions"], 2);
    let steps = v["steps"].as_array().unwrap();
    assert_eq!(steps.last().unwrap()["summary"], "2 redaction(s)", "{v}");
    let raw = std::fs::read_to_string(&rig_on.audit).unwrap();
    assert!(
        !raw.contains("bob@example.com"),
        "an email in the log:\n{raw}"
    );
    rig_on.sidecar.abort();

    let rig_off = rig(ask(), |c| c.guardrails.pii_redact = false, |_| {}).await;
    let (code, v) = rig_off.invoke("ops-assistant", "refund order 1001").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        v["questions"][0]["question"],
        "Send the refund note to bob@example.com?"
    );
    assert_eq!(
        v["questions"][0]["recommended"],
        "Yes, to bob@example.com, the address on the order."
    );
    assert_eq!(v["output"], render_questions(&questions_of(&v)));
    rig_off.sidecar.abort();
}

#[tokio::test]
async fn the_grpc_app_api_response_carries_questions() {
    let rig = rig(FakeRuntime::asking(&[REFUND]), |_| {}, |_| {}).await;
    let mut app = AppApiClient::connect(format!("http://{}", rig.sidecar.grpc_addr))
        .await
        .unwrap();
    let resp = app
        .invoke_agent(InvokeAgentRequest {
            agent: "ops-assistant".into(),
            input: "refund order 1001".into(),
            ..Default::default()
        })
        .await
        .expect("a run that asked is ok")
        .into_inner();
    assert_eq!(resp.status, "ok");
    assert_eq!(resp.questions, vec![q(REFUND.0, REFUND.1)]);
    assert_eq!(resp.output, render_questions(&resp.questions));
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_local_agent_tool_returns_the_callees_questions_to_the_runtime() {
    let rig = rig(FakeRuntime::asking(&[NOTIFY]), |_| {}, |_| {}).await;
    let mut tools = tools(&rig.sock).await;
    // the calling run is in flight while its runtime calls the tool, as the pipeline holds it
    let _run = in_flight(&rig.sidecar, "local-asked", "ops-assistant");
    let resp = tools
        .invoke_agent(ToolAgentRequest {
            ctx: ctx("ops-assistant", "order_triage", "local-asked", SPAN),
            target_service: String::new(),
            target_agent: "order-triage".into(),
            input: "triage order 1001".into(),
            context_json: String::new(),
        })
        .await
        .expect("the nested run asked, status ok")
        .into_inner();
    assert_eq!(resp.status, "ok");
    assert_eq!(resp.questions, vec![q(NOTIFY.0, NOTIFY.1)]);
    let inv = invocation_records(&rig, "local-asked").await;
    assert_eq!(inv.len(), 1);
    assert_eq!(inv[0]["agent"], "order-triage");
    assert_eq!(inv[0]["rule"], RULE_CLARIFY_ASKED);
    rig.sidecar.abort();
}

/// The calling agent's answers to NOTIFY, as its agent tool sends them.
const ANSWERS: &str =
    r#"{"answers": [{"question": "Tell the customer now?", "answer": "Yes, before the refund."}]}"#;

/// The rule a denial names in `x-agentsc-rule`.
fn rule_of(st: &tonic::Status) -> &str {
    st.metadata()
        .get("x-agentsc-rule")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

fn triage(request_id: &str, context_json: &str) -> ToolAgentRequest {
    ToolAgentRequest {
        ctx: ctx("ops-assistant", "order_triage", request_id, SPAN),
        target_service: String::new(),
        target_agent: "order-triage".into(),
        input: "triage order 1001".into(),
        context_json: context_json.into(),
    }
}

#[tokio::test]
async fn a_local_agent_tool_answers_the_callees_questions_in_context() {
    // the callee asks until it gets answers in its context
    let rt = FakeRuntime::with(|req| {
        Box::pin(async move {
            if req.context_json.is_empty() {
                asked(&[NOTIFY])
            } else {
                ok("P2, the customer is told first.")
            }
        })
    });
    let rig = rig(rt, |_| {}, |_| {}).await;
    let mut tools = tools(&rig.sock).await;
    let _runs = (
        in_flight(&rig.sidecar, "local-answered", "ops-assistant"),
        in_flight(&rig.sidecar, "local-unanswered", "ops-assistant"),
    );
    let resp = tools
        .invoke_agent(triage("local-answered", ANSWERS))
        .await
        .expect("answered")
        .into_inner();
    assert_eq!(resp.status, "ok");
    assert!(resp.questions.is_empty(), "{resp:?}");
    assert_eq!(resp.output, "P2, the customer is told first.");
    let seen = rig.runtime.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].input, "triage order 1001");
    assert_eq!(
        seen[0].context_json, ANSWERS,
        "the callee gets the context as sent"
    );
    assert_eq!(seen[0].caller_agent, "ops-assistant");

    // both sides audit the input with its context, as for an app's invocation
    let audited = json!({
        "input": "triage order 1001",
        "context": serde_json::from_str::<Value>(ANSWERS).unwrap(),
    });
    let inv = invocation_records(&rig, "local-answered").await;
    assert_eq!(inv.len(), 1);
    assert_eq!(inv[0]["agent"], "order-triage");
    assert_eq!(inv[0]["input"], audited);
    let calls = wait_audit(&rig.audit, 2, |v| {
        v["request_id"] == "local-answered"
            && (v["kind"] == "tool_call" || v["kind"] == "agent_call")
    })
    .await;
    assert_eq!(calls.len(), 2);
    for r in &calls {
        assert_eq!(r["agent"], "ops-assistant", "{r}");
        assert_eq!(r["input"], audited, "{r}");
    }

    // without a context the record keeps the plain input, and the callee asks
    let resp = tools
        .invoke_agent(triage("local-unanswered", ""))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.questions, vec![q(NOTIFY.0, NOTIFY.1)]);
    let inv = invocation_records(&rig, "local-unanswered").await;
    assert_eq!(inv[0]["input"], "triage order 1001");
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_forwarded_context_passes_the_callees_input_guardrails() {
    // CONTRACT.md §5.1 step 3: input_deny and max_input_bytes see the context, as an app's
    let rig = rig(FakeRuntime::answering("P3"), |_| {}, |_| {}).await;
    let mut tools = tools(&rig.sock).await;
    let _runs = (
        in_flight(&rig.sidecar, "ctx-secret", "ops-assistant"),
        in_flight(&rig.sidecar, "ctx-big", "ops-assistant"),
        in_flight(&rig.sidecar, "ctx-bad", "ops-assistant"),
    );

    let secret =
        r#"{"answers": [{"question": "Which login?", "answer": "password = sk-CTX-321"}]}"#;
    let err = tools
        .invoke_agent(triage("ctx-secret", secret))
        .await
        .expect_err("the callee's input_deny matches the context");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert_eq!(rule_of(&err), "guardrail.input_deny.no-secrets", "{err:?}");

    // input and context are 8192 bytes at most together (the orders charter's max_input_bytes)
    let big = json!({ "note": "x".repeat(8192 - "triage order 1001".len()) }).to_string();
    let err = tools
        .invoke_agent(triage("ctx-big", &big))
        .await
        .expect_err("input and context are over the limit");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    assert_eq!(rule_of(&err), "guardrail.max_input_bytes", "{err:?}");

    // a context that is not a JSON object is the runtime's mistake: refused before any call
    for bad in ["[1, 2]", "\"Yes.\"", "{not json"] {
        let err = tools
            .invoke_agent(triage("ctx-bad", bad))
            .await
            .expect_err("not an object");
        assert_eq!(err.code(), tonic::Code::PermissionDenied, "{bad}: {err:?}");
        assert_eq!(rule_of(&err), "guardrail.tool_spec", "{bad}: {err:?}");
    }
    assert!(
        rig.runtime.seen().is_empty(),
        "no callee ran: {:?}",
        rig.runtime.seen()
    );
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_mesh_call_carries_questions_back_to_the_calling_agent() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let ca = agentsc_pki::ca_init().unwrap();
    let tls_dir = |service: &str| {
        let leaf = agentsc_pki::issue_leaf(&ca, "agentsc-demo", service, 1).unwrap();
        let dir = root.join(format!("tls-{service}"));
        agentsc_pki::TlsMaterial::write(&leaf, &ca.cert_pem, &dir).unwrap();
        dir
    };
    let start = |name: &str, c: &Charter, tls: std::path::PathBuf| {
        let path = root.join(format!("{name}.charter.yaml"));
        write_charter(&path, c);
        let cfg = agentscd::Config::for_test(path, tls, root.join(format!("sock-{name}")));
        agentscd::start(cfg)
    };

    // inventory: stock-analyst's (fake) run asks, with an email the callee's pii_redact catches,
    // until its context holds the answer
    let mut inv = Charter::from_yaml(INVENTORY).unwrap();
    inv.audit.sink = agentsc_charter::AuditSink::File;
    let inv_audit = root.join("inventory-audit.jsonl");
    inv.audit.file = Some(inv_audit.to_string_lossy().into_owned());
    let inv_rt = FakeRuntime::with(|req| {
        Box::pin(async move {
            if req.context_json.is_empty() {
                asked(&[(
                    "Reorder now or wait for ops-lead@example.com?",
                    "Reorder now.",
                )])
            } else {
                ok("Reordered 50 of WIDGET-1.")
            }
        })
    });
    serve_runtime(&root.join("sock-inventory"), inv_rt.clone());
    let inventory = start("inventory", &inv, tls_dir("inventory"))
        .await
        .expect("inventory starts");
    let inv_mesh = inventory.mesh_addr.expect("inventory mesh is up");

    // orders: its ops-assistant calls stock-analyst over the mesh through its stock_analyst tool
    let mut ord = Charter::from_yaml(ORDERS).unwrap();
    ord.mesh
        .peers
        .insert("inventory".into(), inv_mesh.to_string());
    let orders = start("orders", &ord, tls_dir("orders"))
        .await
        .expect("orders starts");
    let mut tools = tools(&root.join("sock-orders")).await;
    let _run = in_flight(&orders, "mesh-asked", "ops-assistant");
    let resp = tools
        .invoke_agent(ToolAgentRequest {
            ctx: ctx("ops-assistant", "stock_analyst", "mesh-asked", SPAN),
            target_service: "inventory".into(),
            target_agent: "stock-analyst".into(),
            input: "should we reorder WIDGET-1?".into(),
            context_json: String::new(),
        })
        .await
        .expect("the remote run asked, status ok")
        .into_inner();
    assert_eq!(resp.status, "ok");
    assert_eq!(
        resp.questions,
        vec![q(
            "Reorder now or wait for [redacted:email]?",
            "Reorder now."
        )]
    );
    assert_eq!(resp.output, render_questions(&resp.questions));

    let recs = wait_audit(&inv_audit, 1, |v| {
        v["request_id"] == "mesh-asked" && v["kind"] == "agent_invocation"
    })
    .await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["caller_agent"], "ops-assistant");
    assert_eq!(recs[0]["rule"], RULE_CLARIFY_ASKED);

    // the calling agent answers in context, which reaches the remote run as its context
    let answers = r#"{"answers": [{"question": "Reorder now or wait for [redacted:email]?", "answer": "Reorder now."}]}"#;
    let resp = tools
        .invoke_agent(ToolAgentRequest {
            ctx: ctx("ops-assistant", "stock_analyst", "mesh-asked", SPAN),
            target_service: "inventory".into(),
            target_agent: "stock-analyst".into(),
            input: "should we reorder WIDGET-1?".into(),
            context_json: answers.into(),
        })
        .await
        .expect("answered")
        .into_inner();
    assert_eq!(resp.status, "ok");
    assert!(resp.questions.is_empty(), "{resp:?}");
    assert_eq!(resp.output, "Reordered 50 of WIDGET-1.");
    let seen = inv_rt.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].context_json, answers);
    assert_eq!(seen[1].caller_agent, "ops-assistant");
    let recs = wait_audit(&inv_audit, 2, |v| {
        v["request_id"] == "mesh-asked" && v["kind"] == "agent_invocation"
    })
    .await;
    assert_eq!(recs.len(), 2);
    assert_eq!(
        recs[1]["input"]["context"],
        serde_json::from_str::<Value>(answers).unwrap()
    );
    assert!(recs[1]["rule"].is_null(), "{}", recs[1]);
    orders.abort();
    inventory.abort();
}

#[tokio::test]
async fn the_invocation_record_of_a_run_that_asked_has_rule_clarify_asked() {
    let rt = FakeRuntime::with(|req| {
        Box::pin(async move {
            if req.input == "ask" {
                asked(&[REFUND])
            } else {
                ok("done")
            }
        })
    });
    let rig = rig(rt, |_| {}, |_| {}).await;

    let (_, v) = rig.invoke("ops-assistant", "ask").await;
    let rid = v["request_id"].as_str().unwrap();
    let recs = invocation_records(&rig, rid).await;
    assert_eq!(recs.len(), 1, "exactly one agent_invocation record");
    assert_eq!(recs[0]["decision"], "allow");
    assert_eq!(recs[0]["rule"], RULE_CLARIFY_ASKED);
    assert_eq!(
        recs[0]["output"], v["output"],
        "the log holds the output the caller got"
    );
    assert_eq!(
        recs[0]["output"],
        render_questions(&[q(REFUND.0, REFUND.1)])
    );

    let (_, v) = rig.invoke("ops-assistant", "answer").await;
    let rid = v["request_id"].as_str().unwrap();
    let recs = invocation_records(&rig, rid).await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["decision"], "allow");
    assert!(recs[0]["rule"].is_null(), "{}", recs[0]);
    rig.sidecar.abort();
}

#[tokio::test]
async fn a_denied_or_errored_run_never_returns_questions() {
    let rt = FakeRuntime::with(|req| {
        Box::pin(async move {
            let (status, rule) = if req.input == "deny" {
                ("denied", "budget.max_steps")
            } else {
                ("error", "model.error")
            };
            ExecuteResponse {
                status: status.into(),
                rule: rule.into(),
                reason: "the run stopped".into(),
                questions: vec![q(REFUND.0, REFUND.1)],
                ..Default::default()
            }
        })
    });
    let rig = rig(rt, |_| {}, |_| {}).await;
    for (input, code, status) in [("deny", 429, "denied"), ("fail", 502, "error")] {
        let (c, v) = rig.invoke("ops-assistant", input).await;
        assert_eq!(c, code, "{v}");
        assert_eq!(v["status"], status);
        assert!(v.get("questions").is_none(), "{input}: {v}");
        let rid = v["request_id"].as_str().unwrap();
        let recs = invocation_records(&rig, rid).await;
        assert_eq!(recs.len(), 1);
        assert_ne!(recs[0]["rule"], RULE_CLARIFY_ASKED, "{}", recs[0]);
    }

    let mut app = AppApiClient::connect(format!("http://{}", rig.sidecar.grpc_addr))
        .await
        .unwrap();
    let err = app
        .invoke_agent(InvokeAgentRequest {
            agent: "ops-assistant".into(),
            input: "deny".into(),
            ..Default::default()
        })
        .await
        .expect_err("a denied run is a gRPC error, with no response body");
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    rig.sidecar.abort();
}

#[tokio::test]
async fn the_runtime_gets_the_practices_in_its_agent_spec() {
    let rig = rig(
        FakeRuntime::answering("done"),
        |c| {
            practices(
                c,
                "order-triage",
                serde_json::from_value(json!({ "clarify": "never", "max_questions": 3 })).unwrap(),
            )
        },
        |_| {},
    )
    .await;
    rig.invoke("ops-assistant", "hi").await;
    rig.invoke("order-triage", "hi").await;

    // an agent without the block gets the defaults, filled
    assert_eq!(
        rig.runtime.last_spec("ops-assistant")["practices"],
        json!({
            "plan": true, "clarify": "blocking", "max_questions": 5,
            "brevity": "lite", "agent_brevity": "full", "auto_clarity": true,
        })
    );
    // a partial block keeps the defaults for what it leaves out
    assert_eq!(
        rig.runtime.last_spec("order-triage")["practices"],
        json!({
            "plan": true, "clarify": "never", "max_questions": 3,
            "brevity": "lite", "agent_brevity": "full", "auto_clarity": true,
        })
    );
    rig.sidecar.abort();
}

/// The sidecar renders `output` as the runtime does (`prompts.render_questions`), byte for byte.
#[test]
fn render_questions_writes_the_runtimes_format() {
    assert_eq!(
        render_questions(&[q(REFUND.0, REFUND.1), q(NOTIFY.0, NOTIFY.1)]),
        concat!(
            "I need these decisions from you before I go on:\n",
            "\n",
            "1. Refund to the card or as store credit?\n",
            "   Recommended: Store credit, because the card on the order has expired.\n",
            "\n",
            "2. Tell the customer now?\n",
            "   Recommended: Yes, before the refund.",
        )
    );
    assert_eq!(
        render_questions(&[q("Ship today?", "Yes.")]),
        "I need these decisions from you before I go on:\n\n1. Ship today?\n   Recommended: Yes."
    );
}

#[tokio::test]
async fn clarify_never_drops_the_runtimes_questions() {
    // the runtime asks anyway, with a key in one question; its output is an answer with an email
    let rt = FakeRuntime::with(|req| {
        Box::pin(async move {
            let mut questions = vec![q(REFUND.0, REFUND.1)];
            if req.input.contains("key") {
                questions.push(q("Use sk-DROPPED1?", "Yes."));
            }
            ExecuteResponse {
                questions,
                ..ok("Refunded; the note went to bob@example.com.")
            }
        })
    });
    let rig = rig(
        rt,
        |c| {
            no_keys(c);
            practices(
                c,
                "ops-assistant",
                PracticesSpec {
                    clarify: Clarify::Never,
                    ..Default::default()
                },
            );
        },
        |_| {},
    )
    .await;

    for input in ["refund order 1001", "refund with a key"] {
        let (code, v) = rig.invoke("ops-assistant", input).await;
        assert_eq!(code, 200, "{input}: a dropped question is not checked: {v}");
        assert!(v.get("questions").is_none(), "{input}: {v}");
        assert_eq!(
            v["output"], "Refunded; the note went to [redacted:email].",
            "{input}: the output passes as usual"
        );
        let rid = v["request_id"].as_str().unwrap();
        let recs = invocation_records(&rig, rid).await;
        assert_eq!(recs.len(), 1);
        assert!(recs[0]["rule"].is_null(), "{input}: {}", recs[0]);
        assert_eq!(recs[0]["output"], v["output"]);
    }

    // order-triage has no practices block: clarify is blocking, so it asks, and the key denies
    let (code, v) = rig.invoke("order-triage", "refund order 1001").await;
    assert_eq!(code, 200, "{v}");
    assert_eq!(
        v["questions"],
        json!([{ "question": REFUND.0, "recommended": REFUND.1 }])
    );
    assert_eq!(v["output"], render_questions(&[q(REFUND.0, REFUND.1)]));
    let (code, v) = rig.invoke("order-triage", "refund with a key").await;
    assert_eq!(code, 403, "{v}");
    assert_eq!(v["rule"], DENY_RULE);
    rig.sidecar.abort();
}

#[tokio::test]
async fn the_output_is_rendered_from_the_questions_the_caller_gets() {
    // The runtime's output is not its questions and holds a key and an email. The caller gets
    // an output rendered from the questions as the sidecar left them: two of three, the long
    // one cut, the email redacted.
    let runtime_output = "Not the questions: use sk-RUNTIME1 or mail alice@example.com.";
    let long = "é".repeat(MAX_QUESTION_CHARS + 500);
    let rt = returning(ExecuteResponse {
        questions: vec![
            q(REFUND.0, "Store credit; mail bob@example.com."),
            q(&long, NOTIFY.1),
            q("Close the ticket?", "Yes, once refunded."),
        ],
        ..ok(runtime_output)
    });
    let rig = rig(
        rt,
        |c| {
            no_keys(c);
            practices(
                c,
                "ops-assistant",
                PracticesSpec {
                    max_questions: 2,
                    ..Default::default()
                },
            );
        },
        |_| {},
    )
    .await;

    let (code, v) = rig.invoke("ops-assistant", "refund order 1001").await;
    assert_eq!(
        code, 200,
        "the runtime's output is replaced, so not checked: {v}"
    );
    let expected = format!(
        "I need these decisions from you before I go on:\n\n\
         1. {}\n   Recommended: Store credit; mail [redacted:email].\n\n\
         2. {}\n   Recommended: {}",
        REFUND.0,
        "é".repeat(MAX_QUESTION_CHARS),
        NOTIFY.1,
    );
    assert_eq!(v["output"], expected);
    assert_eq!(v["output"], render_questions(&questions_of(&v)));

    let rid = v["request_id"].as_str().unwrap();
    let recs = invocation_records(&rig, rid).await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["rule"], RULE_CLARIFY_ASKED);
    assert_eq!(
        recs[0]["output"], v["output"],
        "the log holds the output the caller got"
    );
    // only the kept email counts: the runtime's output is never redacted, only dropped
    let guard = rig.records(|r| r["request_id"] == rid && r["kind"] == "guardrail");
    assert_eq!(guard.len(), 1, "{guard:?}");
    assert_eq!(guard[0]["rule"], "guardrail.pii_redact");
    assert_eq!(guard[0]["output"]["redactions"], 1);
    let raw = std::fs::read_to_string(&rig.audit).unwrap();
    for gone in [
        "sk-RUNTIME1",
        "alice@example.com",
        "bob@example.com",
        "Close the ticket?",
    ] {
        assert!(!raw.contains(gone), "{gone} in the audit log:\n{raw}");
    }
    rig.sidecar.abort();
}
