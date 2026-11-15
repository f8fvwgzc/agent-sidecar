//! A2A 1.0 over its JSON-RPC binding (docs/design/a2a.md): what the sidecar's A2A server
//! (agentscd `a2a`) and its `type: a2a` tool client (here) share. The field and enum names are the
//! proto3 JSON names of the normative `specification/a2a.proto` (`TASK_STATE_COMPLETED`,
//! `ROLE_USER`, camelCase fields, a `Part` with exactly one of `text`, `raw`, `url`, `data`).
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::mcp_client::{RULE_RESPONSE_TOO_LARGE, RemoteError, quote, read_capped};

/// The A2A version both sides speak, sent and required as the `A2A-Version` header.
pub const VERSION: &str = "1.0";
pub const VERSION_HEADER: &str = "A2A-Version";
/// The only protocol binding the sidecar serves and calls.
pub const BINDING: &str = "JSONRPC";

pub const ROLE_USER: &str = "ROLE_USER";
pub const ROLE_AGENT: &str = "ROLE_AGENT";

/// JSON-RPC method names (A2A 1.0 §9.4).
pub mod method {
    pub const SEND_MESSAGE: &str = "SendMessage";
    pub const SEND_STREAMING_MESSAGE: &str = "SendStreamingMessage";
    pub const GET_TASK: &str = "GetTask";
    pub const LIST_TASKS: &str = "ListTasks";
    pub const CANCEL_TASK: &str = "CancelTask";
    pub const SUBSCRIBE_TO_TASK: &str = "SubscribeToTask";
    pub const GET_EXTENDED_AGENT_CARD: &str = "GetExtendedAgentCard";
    /// The push notification config methods, none of which the sidecar serves.
    pub const PUSH_CONFIG: [&str; 4] = [
        "CreateTaskPushNotificationConfig",
        "GetTaskPushNotificationConfig",
        "ListTaskPushNotificationConfigs",
        "DeleteTaskPushNotificationConfig",
    ];
}

/// JSON-RPC error codes: the standard ones and A2A's (§9.5).
pub mod code {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    pub const TASK_NOT_FOUND: i64 = -32001;
    pub const TASK_NOT_CANCELABLE: i64 = -32002;
    pub const PUSH_NOTIFICATION_NOT_SUPPORTED: i64 = -32003;
    pub const UNSUPPORTED_OPERATION: i64 = -32004;
    pub const CONTENT_TYPE_NOT_SUPPORTED: i64 = -32005;
    pub const INVALID_AGENT_RESPONSE: i64 = -32006;
    pub const EXTENDED_AGENT_CARD_NOT_CONFIGURED: i64 = -32007;
    pub const VERSION_NOT_SUPPORTED: i64 = -32009;
}

/// `TaskState` values.
pub mod state {
    pub const SUBMITTED: &str = "TASK_STATE_SUBMITTED";
    pub const WORKING: &str = "TASK_STATE_WORKING";
    pub const COMPLETED: &str = "TASK_STATE_COMPLETED";
    pub const FAILED: &str = "TASK_STATE_FAILED";
    pub const CANCELED: &str = "TASK_STATE_CANCELED";
    pub const INPUT_REQUIRED: &str = "TASK_STATE_INPUT_REQUIRED";
    pub const REJECTED: &str = "TASK_STATE_REJECTED";
    pub const AUTH_REQUIRED: &str = "TASK_STATE_AUTH_REQUIRED";

    /// A task in this state never changes again.
    pub fn is_terminal(s: &str) -> bool {
        matches!(s, COMPLETED | FAILED | CANCELED | REJECTED)
    }
}

/// Is `version` (an `A2A-Version` value) one this side speaks? Any 1.x; an empty value means 0.3.
pub fn version_supported(version: &str) -> bool {
    let v = version.trim();
    v == "1" || v.starts_with("1.")
}

/// The text of a list of `Part`s: text parts as they are, data parts as compact JSON, one per
/// line. `raw` and `url` parts are named, never fetched.
pub fn text_of(parts: Option<&Value>) -> String {
    let Some(Value::Array(parts)) = parts else {
        return String::new();
    };
    let mut out: Vec<String> = Vec::new();
    for p in parts {
        if let Some(t) = p.get("text").and_then(Value::as_str) {
            out.push(t.to_string());
        } else if let Some(d) = p.get("data") {
            out.push(d.to_string());
        } else if let Some(u) = p.get("url").and_then(Value::as_str) {
            out.push(format!("[file at {u}]"));
        } else if p.get("raw").is_some() {
            let name = p.get("filename").and_then(Value::as_str).unwrap_or("file");
            out.push(format!("[{name}, not shown]"));
        }
    }
    out.join("\n")
}

/// A JSON-RPC error object.
pub fn rpc_error(code: i64, message: impl Into<String>) -> Value {
    json!({"code": code, "message": message.into()})
}

// ---- the `type: a2a` tool client ----------------------------------------------------------------

/// A JSON-RPC error, a transport failure or an answer that is not A2A.
pub const RULE_ERROR: &str = "a2a.error";
/// The agent does not speak A2A 1.0 (`VersionNotSupportedError`, or no JSON-RPC at all).
pub const RULE_UNSUPPORTED_VERSION: &str = "a2a.unsupported_version";
/// The tool's `credential` file cannot be read.
pub const RULE_CREDENTIAL: &str = "a2a.credential_unavailable";
/// Polling a task that is still working: the first wait, doubled up to the longest.
const POLL_FIRST: Duration = Duration::from_millis(250);
const POLL_LONGEST: Duration = Duration::from_secs(4);

/// One `SendMessage` of an `a2a` tool call.
pub struct Send<'a> {
    /// The agent's JSON-RPC endpoint (the charter's `url`).
    pub url: &'a str,
    /// The text part.
    pub input: &'a str,
    /// A data part, when the model sent `context`.
    pub context: Option<&'a Value>,
    /// The task this message answers (an `input_required` task), when the model sent `task_id`.
    pub task_id: Option<&'a str>,
    pub bearer: Option<&'a str>,
    pub traceparent: Option<String>,
    pub request_id: Option<&'a str>,
    /// When the whole call, polling a working task included, gives up.
    pub deadline: Instant,
    /// The most read of one answer (the sidecar's `--max-response-bytes`).
    pub max_bytes: usize,
}

/// The `Message` a [`Send`] carries.
pub fn message_of(s: &Send<'_>) -> Value {
    let mut parts = vec![json!({"text": s.input})];
    if let Some(c) = s.context {
        parts.push(json!({"data": c, "mediaType": "application/json"}));
    }
    let mut m = json!({
        "messageId": uuid::Uuid::new_v4().to_string(),
        "role": ROLE_USER,
        "parts": parts,
    });
    if let Some(t) = s.task_id {
        m["taskId"] = json!(t);
    }
    m
}

/// Send the message and return the `SendMessageResponse` (`{"task": …}` or `{"message": …}`).
/// A task that is still submitted or working is polled with `GetTask` until it is not, or until
/// the deadline, when it is returned as it is.
pub async fn send_message(http: &reqwest::Client, s: &Send<'_>) -> Result<Value, RemoteError> {
    let params = json!({
        "message": message_of(s),
        "configuration": {
            "acceptedOutputModes": ["text/plain", "application/json"],
            "returnImmediately": false,
        },
    });
    let result = call(http, s, method::SEND_MESSAGE, params).await?;
    let mut task = match (result.get("task"), result.get("message")) {
        (Some(t), _) if t.is_object() => t.clone(),
        (_, Some(m)) if m.is_object() => return Ok(result),
        _ => {
            return Err(RemoteError::ours(
                RULE_ERROR,
                "the agent's SendMessage result is neither a task nor a message",
            ));
        }
    };
    let mut wait = POLL_FIRST;
    while matches!(task_state(&task), state::SUBMITTED | state::WORKING) {
        let Some(id) = task.get("id").and_then(Value::as_str).map(str::to_string) else {
            break;
        };
        if Instant::now() + wait >= s.deadline {
            break;
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(POLL_LONGEST);
        let got = call(http, s, method::GET_TASK, json!({"id": id})).await?;
        if !got.is_object() {
            return Err(RemoteError::ours(
                RULE_ERROR,
                "the agent's GetTask result is not a task",
            ));
        }
        task = got;
    }
    Ok(json!({"task": task}))
}

fn task_state(task: &Value) -> &str {
    task.pointer("/status/state")
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// One JSON-RPC request to the agent; its `result`.
async fn call(
    http: &reqwest::Client,
    s: &Send<'_>,
    method: &str,
    params: Value,
) -> Result<Value, RemoteError> {
    let left = s.deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(RemoteError::ours(
            RULE_ERROR,
            format!("{method}: the call's time ran out"),
        ));
    }
    let id = uuid::Uuid::new_v4().to_string();
    let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let mut req = http
        .post(s.url)
        .timeout(left)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header(VERSION_HEADER, VERSION);
    if let Some(token) = s.bearer {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(tp) = &s.traceparent {
        req = req.header("traceparent", tp);
    }
    if let Some(rid) = s.request_id {
        req = req.header("x-agentsc-request-id", rid);
    }
    let resp = req
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| RemoteError::ours(RULE_ERROR, format!("{method} {}: {e}", s.url)))?;
    let status = resp.status();
    let raw = read_capped(resp, s.max_bytes).await.map_err(|e| {
        if e.rule == RULE_RESPONSE_TOO_LARGE {
            e
        } else {
            RemoteError::ours(RULE_ERROR, e.reason)
        }
    })?;
    let msg: Option<Value> = serde_json::from_slice(&raw).ok();
    if let Some(err) = msg.as_ref().and_then(|m| m.get("error")) {
        return Err(error_of(err, status.as_u16()));
    }
    if !status.is_success() {
        let text = quote(&String::from_utf8_lossy(&raw));
        return Err(match status.as_u16() {
            401 | 403 => RemoteError::ours(
                RULE_ERROR,
                format!("the agent refused the call's credentials (HTTP {status})"),
            ),
            _ if text.is_empty() => {
                RemoteError::ours(RULE_ERROR, format!("the agent answered HTTP {status}"))
            }
            _ => RemoteError::theirs(
                RULE_ERROR,
                format!("the agent answered HTTP {status}: {text}"),
            ),
        });
    }
    match msg {
        Some(m) if m.get("id") == Some(&json!(id)) && m.get("result").is_some() => {
            Ok(m["result"].clone())
        }
        _ => Err(RemoteError::ours(
            RULE_UNSUPPORTED_VERSION,
            format!(
                "the answer to {method} is not a JSON-RPC response: the agent does not speak A2A {VERSION} over JSON-RPC"
            ),
        )),
    }
}

/// A JSON-RPC `error` of the agent.
fn error_of(err: &Value, status: u16) -> RemoteError {
    let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
    let message = quote(err.get("message").and_then(Value::as_str).unwrap_or(""));
    if code == code::VERSION_NOT_SUPPORTED {
        return RemoteError::theirs(
            RULE_UNSUPPORTED_VERSION,
            format!("the agent does not support A2A {VERSION}: {message}"),
        );
    }
    RemoteError::theirs(
        RULE_ERROR,
        format!("the agent answered HTTP {status}, JSON-RPC error {code}: {message}"),
    )
}

/// What the model gets of an answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    pub text: String,
    pub is_error: bool,
    /// The task's state, or `message` for a plain message.
    pub state: String,
    pub task_id: Option<String>,
}

/// Render a `SendMessageResponse` for the model. A task that needs input names its `task_id`, so
/// the model can answer with another call; a failed, rejected or canceled one is an error.
pub fn render(answer: &Value) -> Rendered {
    if let Some(m) = answer.get("message") {
        return Rendered {
            text: text_of(m.get("parts")),
            is_error: false,
            state: "message".into(),
            task_id: None,
        };
    }
    let task = answer.get("task").unwrap_or(&Value::Null);
    let st = task_state(task).to_string();
    let id = task.get("id").and_then(Value::as_str).map(str::to_string);
    let status_text = text_of(task.pointer("/status/message/parts"));
    let artifacts: Vec<String> = task
        .get("artifacts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|x| text_of(x.get("parts")))
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let tid = id.clone().unwrap_or_default();
    let (text, is_error) = match st.as_str() {
        state::COMPLETED => {
            let mut t = artifacts.join("\n\n");
            if t.is_empty() {
                t = status_text;
            }
            if t.is_empty() {
                t = "(the agent returned no text)".into();
            }
            (t, false)
        }
        state::INPUT_REQUIRED => (
            format!(
                "The remote agent needs input before it goes on (task_id {tid}). To answer, call this tool again with task_id \"{tid}\" and the answer as input.\n\n{status_text}"
            ),
            false,
        ),
        state::AUTH_REQUIRED => (
            format!(
                "The remote agent needs an authorization the sidecar cannot give (task_id {tid}). {status_text}"
            ),
            true,
        ),
        state::SUBMITTED | state::WORKING => (
            format!("The remote agent is still working on task {tid}; the call's time ran out."),
            true,
        ),
        other => {
            let name = if other.is_empty() {
                "in no known state"
            } else {
                other
            };
            let mut t = format!("The remote task ended {name}");
            if !status_text.is_empty() {
                t.push_str(": ");
                t.push_str(&status_text);
            }
            (t, true)
        }
    };
    Rendered {
        text,
        is_error,
        state: st,
        task_id: id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_tasks_and_messages() {
        let done = json!({"task": {"id": "t1", "status": {"state": state::COMPLETED},
            "artifacts": [{"artifactId": "a", "parts": [{"text": "EUR 380"}, {"data": {"eur": 380}}]}]}});
        let r = render(&done);
        assert_eq!(r.text, "EUR 380\n{\"eur\":380}");
        assert!(!r.is_error);
        assert_eq!(r.task_id.as_deref(), Some("t1"));

        let ask = json!({"task": {"id": "t2", "status": {"state": state::INPUT_REQUIRED,
            "message": {"messageId": "m", "role": ROLE_AGENT, "parts": [{"text": "Which currency?"}]}}}});
        let r = render(&ask);
        assert!(r.text.contains("task_id \"t2\""), "{}", r.text);
        assert!(r.text.ends_with("Which currency?"));
        assert!(!r.is_error);

        let failed = json!({"task": {"id": "t3", "status": {"state": state::REJECTED,
            "message": {"messageId": "m", "role": ROLE_AGENT, "parts": [{"text": "not allowed"}]}}}});
        let r = render(&failed);
        assert_eq!(
            r.text,
            "The remote task ended TASK_STATE_REJECTED: not allowed"
        );
        assert!(r.is_error);

        let msg =
            json!({"message": {"messageId": "m", "role": ROLE_AGENT, "parts": [{"text": "hi"}]}});
        assert_eq!(render(&msg).text, "hi");
        assert!(state::is_terminal(state::CANCELED) && !state::is_terminal(state::INPUT_REQUIRED));
        assert!(version_supported("1.0") && version_supported("1.2") && !version_supported("0.3"));
        assert!(!version_supported(""));
    }

    #[test]
    fn messages_carry_context_and_task() {
        let ctx = json!({"order": 7});
        let s = Send {
            url: "https://a.example/a2a",
            input: "Quote it",
            context: Some(&ctx),
            task_id: Some("t9"),
            bearer: None,
            traceparent: None,
            request_id: None,
            deadline: Instant::now(),
            max_bytes: 1024,
        };
        let m = message_of(&s);
        assert_eq!(m["role"], ROLE_USER);
        assert_eq!(m["taskId"], "t9");
        assert_eq!(m["parts"][0], json!({"text": "Quote it"}));
        assert_eq!(m["parts"][1]["data"], ctx);
    }
}
