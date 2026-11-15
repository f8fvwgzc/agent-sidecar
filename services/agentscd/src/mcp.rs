//! The sidecar's side of `type: mcp` tools (charter schema level 9, docs/design/mcp-tools.md):
//! each server's `tools/list` kept for the pin check, the check itself, the `Mcp-Param-*`
//! headers of a call and the `credential` file. The MCP client is
//! [`agentsc_common::mcp_client`]; the sidecar keeps no connection state per server.
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use agentsc_charter::ToolSpec;
use agentsc_charter::mcp::{self as spec, ParamHeader};
pub use agentsc_common::mcp_client::*;
use serde_json::Value;

use crate::deadline;

/// A cached list that fails a call's check is fetched again if it is at least this old, so a
/// re-pinned tool works at once and a drifted one does not refetch on every call.
pub const RECHECK_AFTER: Duration = Duration::from_secs(30);

/// Every server's `tools/list`, by MCP endpoint URL, for the pin check (design decision 8).
#[derive(Default)]
pub struct Definitions {
    by_url: Mutex<HashMap<String, Listed>>,
}

struct Listed {
    tools: HashMap<String, Value>,
    fetched: Instant,
    ttl: Duration,
}

impl Definitions {
    /// The cached definition of `tool` at `url` while the list is fresh: `Some(None)` when the
    /// list does not have it, `None` when there is no fresh list.
    fn fresh(&self, url: &str, tool: &str) -> Option<(Option<Value>, Instant)> {
        let by_url = self.by_url.lock().unwrap_or_else(PoisonError::into_inner);
        let l = by_url.get(url)?;
        (l.fetched.elapsed() < l.ttl).then(|| (l.tools.get(tool).cloned(), l.fetched))
    }

    /// Drop every kept list: the next call of each server lists its tools again.
    pub fn clear(&self) {
        self.by_url
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn put(&self, url: &str, tools: HashMap<String, Value>, ttl: Duration) {
        self.by_url
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                url.to_string(),
                Listed {
                    tools,
                    fetched: Instant::now(),
                    ttl,
                },
            );
    }

    /// The `x-mcp-header`s of `tool`'s verified definition, or why the call may not go ahead
    /// (`Err(Ok((rule, reason)))`: refuse; `Err(Err(e))`: listing failed). A fresh cached list is
    /// used; one that fails the check is fetched again once it is [`RECHECK_AFTER`] old.
    pub async fn verified(
        &self,
        client: &reqwest::Client,
        tool: &ToolSpec,
        list: ListContext<'_>,
    ) -> Result<Vec<ParamHeader>, Result<(&'static str, String), McpError>> {
        let timeout = move || deadline::budget(list.deadline, deadline::HTTP_TIMEOUT);
        let options = ListOptions {
            bearer: list.bearer,
            traceparent: Some(list.traceparent),
            request_id: Some(list.request_id),
            timeout: &timeout,
            max_bytes: list.max_bytes,
        };
        let url = tool.url.as_deref().unwrap_or("");
        let name = tool.mcp_tool_name();
        if let Some((def, fetched)) = self.fresh(url, name) {
            match check(tool, def.as_ref()) {
                Ok(headers) => return Ok(headers),
                Err(refusal) if fetched.elapsed() < RECHECK_AFTER => return Err(Ok(refusal)),
                Err(_) => {}
            }
        }
        let (tools, ttl) = list_tools(client, url, &options).await.map_err(Err)?;
        let def = tools.get(name).cloned();
        self.put(url, tools, ttl);
        check(tool, def.as_ref()).map_err(Ok)
    }
}

/// What a `tools/list` for the pin check carries from the call it is made for.
#[derive(Clone, Copy)]
pub struct ListContext<'a> {
    pub bearer: Option<&'a str>,
    pub traceparent: &'a str,
    pub request_id: &'a str,
    pub deadline: Option<Instant>,
    pub max_bytes: usize,
}

/// The `Mcp-Param-*` headers of a call, or why the arguments cannot be written in them.
pub fn param_headers_for(
    headers: &[ParamHeader],
    arguments: &Value,
) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for h in headers {
        if let Some(v) = spec::param_header_value(arguments, &h.path)? {
            out.push((h.header_name(), v));
        }
    }
    Ok(out)
}
