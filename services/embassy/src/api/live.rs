//! The graph, recent events, the live stream and the traces (design §10.1, §10.1.1, §10.2).
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use tokio_util::sync::CancellationToken;

use super::error::Fail;
use super::types::{AuditRecordExt, LaggedEvent, ResetEvent, SpanStatus, SseEvent};
use super::{Authed, Query, limit};
use crate::auth::Identity;
use crate::config::Role;
use crate::events::{ClientFilter, ClientQueue, Item};
use crate::hub::Hub;
use crate::traces::{TraceFilter, Visibility};

/// The keep-alive comment interval.
pub const KEEPALIVE: Duration = Duration::from_secs(15);

fn opt(q: &std::collections::HashMap<String, String>, key: &str) -> Option<String> {
    q.get(key).filter(|v| !v.is_empty()).cloned()
}

pub async fn graph(State(hub): State<Arc<Hub>>, Authed(ident): Authed) -> Result<Response, Fail> {
    let allows = move |ns: &str| ident.allows_namespace(ns);
    let g = crate::graph::build(
        hub.store.as_ref(),
        &hub.registry,
        &hub.graph,
        &allows,
        Utc::now(),
    )
    .await
    .map_err(|e| Fail::store(e, ""))?;
    Ok(Json(g).into_response())
}

pub async fn recent(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    let n = limit(&q, 100)?;
    let (ns, svc, agent) = (opt(&q, "namespace"), opt(&q, "service"), opt(&q, "agent"));
    let (trace, request, kind) = (opt(&q, "trace_id"), opt(&q, "request_id"), opt(&q, "kind"));
    let recs = hub.ring.query(
        |r| {
            ident.allows_namespace(&r.namespace)
                && ns.as_ref().is_none_or(|v| *v == r.namespace)
                && svc.as_ref().is_none_or(|v| *v == r.service)
                && agent.as_ref().is_none_or(|v| {
                    r.agent.as_ref() == Some(v) || r.caller_agent.as_ref() == Some(v)
                })
                && trace.as_ref().is_none_or(|v| *v == r.trace_id)
                && request.as_ref().is_none_or(|v| *v == r.request_id)
                && kind.as_ref().is_none_or(|v| *v == r.kind)
        },
        n,
    );
    let out: Vec<_> = recs
        .iter()
        .map(|r| {
            let r = (**r).clone();
            if ident.payloads {
                r
            } else {
                r.without_payloads()
            }
        })
        .collect();
    Ok(Json(out).into_response())
}

/// One SSE event for a client.
fn render(item: Item, payloads: bool) -> Option<Event> {
    let (seq, name, data) = match item {
        Item::Event(ev) => {
            let data = match (&ev.event, payloads) {
                (SseEvent::Audit(a), false) => {
                    let mut a = (**a).clone();
                    a.record = a.record.without_payloads();
                    SseEvent::Audit(Box::new(a)).data()
                }
                (e, _) => e.data(),
            };
            (ev.seq, ev.event.name(), data.ok()?)
        }
        Item::Lagged { dropped, seq } => (
            seq,
            "lagged",
            SseEvent::Lagged(LaggedEvent { dropped }).data().ok()?,
        ),
        Item::Reset { seq } => (seq, "reset", SseEvent::Reset(ResetEvent {}).data().ok()?),
    };
    Some(Event::default().id(seq.to_string()).event(name).data(data))
}

struct Stream {
    hub: Arc<Hub>,
    ident: Identity,
    queue: Arc<ClientQueue>,
    payloads: bool,
    keepalive: tokio::time::Interval,
    shutdown: CancellationToken,
}

pub async fn events(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
    headers: HeaderMap,
) -> Result<Response, Fail> {
    let payloads = match q.get("payloads").map(String::as_str) {
        None | Some("") | Some("true") => true,
        Some("false") => false,
        Some(other) => {
            return Err(Fail::invalid([format!(
                "payloads {other:?} is not true or false"
            )]));
        }
    };
    let last = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().parse::<u64>().unwrap_or(u64::MAX));
    let filter = ClientFilter {
        namespaces: ident.namespaces.clone(),
        admin: ident.role == Role::Admin,
        namespace: opt(&q, "namespace"),
        service: opt(&q, "service"),
        payloads: ident.payloads && payloads,
    };
    let queue = hub.events.subscribe(filter, last);
    let every = hub.opts.keepalive.max(Duration::from_millis(10));
    let start = tokio::time::Instant::now() + every;
    let state = Stream {
        payloads: ident.payloads && payloads,
        shutdown: hub.shutdown.clone(),
        hub,
        ident,
        queue,
        keepalive: tokio::time::interval_at(start, every),
    };
    let stream = futures::stream::unfold(state, |mut st| async move {
        loop {
            tokio::select! {
                item = st.queue.next() => {
                    if let Some(ev) = render(item, st.payloads) {
                        return Some((Ok::<_, Infallible>(ev), st));
                    }
                }
                _ = st.keepalive.tick() => {
                    // a session or token removed from the config ends the stream
                    if !st.hub.auth.still_valid(&st.ident) {
                        return None;
                    }
                    return Some((Ok(Event::default().comment("keepalive")), st));
                }
                () = st.shutdown.cancelled() => return None,
            }
        }
    });
    let mut resp = Sse::new(stream).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

pub async fn traces(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    axum::extract::Query(q): Query,
) -> Result<Response, Fail> {
    let n = limit(&q, 100)?;
    let status = match q.get("status").map(String::as_str) {
        None | Some("") => None,
        Some("running") => Some(SpanStatus::Running),
        Some("ok") => Some(SpanStatus::Ok),
        Some("denied") => Some(SpanStatus::Denied),
        Some("error") => Some(SpanStatus::Error),
        Some(other) => {
            return Err(Fail::invalid([format!(
                "status {other:?} is not running, ok, denied or error"
            )]));
        }
    };
    let filter = TraceFilter {
        namespace: opt(&q, "namespace"),
        service: opt(&q, "service"),
        agent: opt(&q, "agent"),
        status,
    };
    let allows = |ns: &str| ident.allows_namespace(ns);
    let vis = Visibility {
        allows: &allows,
        payloads: ident.payloads,
    };
    Ok(Json(hub.traces.summaries(&vis, &filter, n, Utc::now())).into_response())
}

pub async fn trace(
    State(hub): State<Arc<Hub>>,
    Authed(ident): Authed,
    Path(trace_id): Path<String>,
) -> Result<Response, Fail> {
    let allows = |ns: &str| ident.allows_namespace(ns);
    let vis = Visibility {
        allows: &allows,
        payloads: ident.payloads,
    };
    hub.traces
        .trace(&trace_id, &vis, Utc::now())
        .map(|t| Json(t).into_response())
        .ok_or_else(|| Fail::not_found(format!("no trace {trace_id}")))
}
