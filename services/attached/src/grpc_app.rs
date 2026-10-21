//! App-facing gRPC API on localhost, plaintext (CONTRACT.md §4.1).
use std::net::SocketAddr;
use std::sync::Arc;

use attache_common::trace::{TraceContext, new_request_id};
use attache_proto::app_api_server::{AppApi, AppApiServer};
use attache_proto::{
    AgentSummary, Empty, InvokeAgentRequest, InvokeAgentResponse, ListAgentsResponse,
};
use tonic::{Request, Response, Status};

use crate::pipeline::{self, Invocation};
use crate::state::AppState;

pub struct AppApiService {
    state: Arc<AppState>,
}

pub async fn serve(
    state: Arc<AppState>,
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let svc = AppApiServer::new(AppApiService { state });
    let task = tokio::spawn(async move {
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await
        {
            tracing::error!(error = %e, "app grpc server stopped");
        }
    });
    Ok((bound, task))
}

impl AppApiService {
    /// The app API token (design §6.6): `UNAUTHENTICATED` and an `authz` record without it.
    fn authenticate<T>(&self, request: &Request<T>, callee: &str) -> Result<(), Status> {
        let md = request.metadata();
        let get = |k: &str| md.get(k).and_then(|v| v.to_str().ok());
        crate::app_auth::check(
            &self.state,
            get("authorization"),
            get("traceparent"),
            callee,
        )
        .map_err(|v| {
            crate::tools::status_with_rule(tonic::Code::Unauthenticated, &v.rule, &v.reason)
        })
    }
}

#[tonic::async_trait]
impl AppApi for AppApiService {
    async fn invoke_agent(
        &self,
        request: Request<InvokeAgentRequest>,
    ) -> Result<Response<InvokeAgentResponse>, Status> {
        self.authenticate(&request, "AppApi/InvokeAgent")?;
        let tp = request
            .metadata()
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let deadline = crate::deadline::from_metadata(request.metadata());
        let req = request.into_inner();
        let trace = match tp
            .as_deref()
            .or((!req.traceparent.is_empty()).then_some(req.traceparent.as_str()))
        {
            Some(t) => TraceContext::from_traceparent(t),
            None => TraceContext::new_root(),
        };
        let inv = Invocation {
            agent: req.agent,
            input: req.input,
            context_json: req.context_json,
            request_id: new_request_id(),
            trace,
            caller: "local".into(),
            caller_agent: None,
            depth: 0,
            deadline,
        };
        let resp = pipeline::invoke(&self.state, inv).await;
        match pipeline::grpc_status(&resp) {
            Some(st) => Err(st),
            None => Ok(Response::new(resp)),
        }
    }

    async fn list_agents(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<ListAgentsResponse>, Status> {
        self.authenticate(&request, "AppApi/ListAgents")?;
        let snap = self.state.loaded().ok_or_else(|| {
            crate::tools::status_with_rule(
                tonic::Code::Unavailable,
                crate::tools::RULE_NO_CHARTER,
                "no charter is loaded yet",
            )
        })?;
        let agents = snap
            .charter
            .agents
            .iter()
            .map(|a| AgentSummary {
                name: a.name.clone(),
                r#type: format!("{:?}", a.agent_type).to_lowercase(),
                model: a.model.clone(),
                tools: snap.charter.allowed_tools(a),
            })
            .collect();
        Ok(Response::new(ListAgentsResponse { agents }))
    }
}
