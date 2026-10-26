//! The platform's model gateway as an upstream: the LLM connection contract's gateway mode
//! (`LLM_GATEWAY_URL` + `LLM_GATEWAY_TOKEN_FILE`, docs/LLM-CONNECTION.md). A sidecar in this mode
//! holds no provider key: its calls go to the standalone gateway (`agentsc-gateway`), which holds
//! the keys, authenticates the sidecar by its token and meters the call again.
//!
//! The request is the caller's, checked like any other of its wire format, sent to
//! `{root}{wire path}` with the token as a bearer token (the file is read for every request, so
//! a rotated token applies to the next call). Nothing the caller sent as a credential goes out.
use agentsc_common::llm_contract::SecretSource;
use axum::http::HeaderMap;

use super::{Provider, Wire};

pub struct Gateway {
    /// Without a trailing `/` or `/v1`.
    root: String,
    token: SecretSource,
    wire: Wire,
}

impl Gateway {
    pub fn new(root: &str, token: SecretSource, wire: Wire) -> Self {
        Self {
            root: root.trim_end_matches('/').to_string(),
            token,
            wire,
        }
    }
}

impl Provider for Gateway {
    fn name(&self) -> &'static str {
        "gateway"
    }

    fn wire(&self) -> Wire {
        self.wire
    }

    fn request(
        &self,
        client: &reqwest::Client,
        body: Vec<u8>,
        incoming: &HeaderMap,
    ) -> Result<reqwest::RequestBuilder, String> {
        let mut req = client
            .post(format!("{}{}", self.root, self.wire.path()))
            .bearer_auth(self.token.read()?)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(body);
        if self.wire == Wire::Messages {
            req = req.header("anthropic-version", super::anthropic::version(incoming));
        }
        // the run binding travels on, for the gateway's records
        for h in [super::HEADER_REQUEST_ID, super::HEADER_AGENT] {
            if let Some(v) = incoming.get(h) {
                req = req.header(h, v.clone());
            }
        }
        Ok(req)
    }
}
