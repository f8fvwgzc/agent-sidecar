//! The live events of `GET /events` (design §10.2) and the ring of recent audit records behind
//! `GET /events/recent`.
//!
//! **Ids.** Every event gets the next `seq` of one counter per process. The hub keeps the last
//! [`REPLAY_EVENTS`] events: a client reconnecting with `Last-Event-ID` gets every later event
//! it may see when they are all still there, else one `reset` event (with the current `seq`).
//!
//! **Back-pressure.** Each client has a queue of [`CLIENT_QUEUE`] events. An event that finds
//! the queue full is dropped together with the queued events, and so is every further event
//! until the client has read the `lagged` event `{dropped}` that takes their place (its id is the
//! `seq` of the last dropped event). Filters (namespace scope, `?namespace=`/`?service=`,
//! `cp_audit` for admins only) apply before an event is queued; payload hiding when it is sent.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::Notify;

use crate::api::types::{AuditRecord, SseEvent};
use crate::config::ALL_NAMESPACES;

/// A client's queue.
pub const CLIENT_QUEUE: usize = 1024;
/// Events kept for `Last-Event-ID` replay.
pub const REPLAY_EVENTS: usize = 16 * 1024;
/// At most this many bytes of events (estimated) are kept for replay.
pub const REPLAY_BYTES: usize = 32 * 1024 * 1024;
/// The size an event without a record counts as.
const SMALL_EVENT: usize = 256;

/// Who may see an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Every client (`graph`).
    All,
    /// Clients whose token may see `namespace` and whose query (if any) names it.
    Service { namespace: String, service: String },
    /// Admins only (`cp_audit`); also scoped when the record names a service.
    Admin {
        namespace: Option<String>,
        service: Option<String>,
    },
}

/// One published event.
#[derive(Debug, Clone, PartialEq)]
pub struct HubEvent {
    pub seq: u64,
    pub event: SseEvent,
    pub scope: Scope,
}

/// What one client may and wants to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFilter {
    /// The token's namespaces (`["*"]` = all).
    pub namespaces: Vec<String>,
    pub admin: bool,
    /// `?namespace=`.
    pub namespace: Option<String>,
    /// `?service=`.
    pub service: Option<String>,
    /// Audit payloads visible (`payloads: true` token, and not `?payloads=false`).
    pub payloads: bool,
}

impl ClientFilter {
    fn token_allows(&self, ns: &str) -> bool {
        self.namespaces
            .iter()
            .any(|n| n == ALL_NAMESPACES || n == ns)
    }

    fn query_allows(&self, ns: &str, svc: Option<&str>) -> bool {
        self.namespace.as_deref().is_none_or(|q| q == ns)
            && match (self.service.as_deref(), svc) {
                (Some(q), Some(s)) => q == s,
                _ => true,
            }
    }

    pub fn admits(&self, scope: &Scope) -> bool {
        match scope {
            Scope::All => true,
            Scope::Service { namespace, service } => {
                self.token_allows(namespace) && self.query_allows(namespace, Some(service))
            }
            Scope::Admin { namespace, service } => {
                self.admin
                    && namespace.as_deref().is_none_or(|ns| {
                        self.token_allows(ns) && self.query_allows(ns, service.as_deref())
                    })
            }
        }
    }
}

/// What a client reads next.
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    Event(Arc<HubEvent>),
    /// `event: lagged`, with the id of the last dropped event.
    Lagged {
        dropped: u64,
        seq: u64,
    },
    /// `event: reset`, with the current id.
    Reset {
        seq: u64,
    },
}

#[derive(Debug, Default)]
struct QueueState {
    reset: Option<u64>,
    queue: VecDeque<Arc<HubEvent>>,
    lagged: Option<(u64, u64)>,
}

/// One client's queue; see the module docs.
#[derive(Debug)]
pub struct ClientQueue {
    pub filter: ClientFilter,
    state: Mutex<QueueState>,
    notify: Notify,
}

impl ClientQueue {
    fn new(filter: ClientFilter) -> Self {
        Self {
            filter,
            state: Mutex::new(QueueState::default()),
            notify: Notify::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn push(&self, ev: Arc<HubEvent>) {
        {
            let mut st = self.lock();
            if let Some((dropped, seq)) = st.lagged.as_mut() {
                *dropped += 1;
                *seq = ev.seq;
            } else if st.queue.len() >= CLIENT_QUEUE {
                let dropped = st.queue.len() as u64 + 1;
                st.queue.clear();
                st.lagged = Some((dropped, ev.seq));
            } else {
                st.queue.push_back(ev);
            }
        }
        self.notify.notify_one();
    }

    /// The next item, without waiting.
    pub fn try_next(&self) -> Option<Item> {
        let mut st = self.lock();
        if let Some(seq) = st.reset.take() {
            return Some(Item::Reset { seq });
        }
        if let Some((dropped, seq)) = st.lagged.take() {
            return Some(Item::Lagged { dropped, seq });
        }
        st.queue.pop_front().map(Item::Event)
    }

    /// The next item.
    pub async fn next(&self) -> Item {
        loop {
            if let Some(item) = self.try_next() {
                return item;
            }
            self.notify.notified().await;
        }
    }

    /// Queued events (tests and metrics).
    pub fn len(&self) -> usize {
        self.lock().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Default)]
struct HubInner {
    seq: u64,
    /// Each event with its estimated size.
    ring: VecDeque<(Arc<HubEvent>, usize)>,
    ring_bytes: usize,
    clients: Vec<Weak<ClientQueue>>,
}

/// The publisher of every live event; see the module docs.
#[derive(Debug)]
pub struct EventHub {
    inner: Mutex<HubInner>,
    replay: usize,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::with_replay(REPLAY_EVENTS)
    }
}

impl EventHub {
    /// A hub that keeps the last `replay` events for `Last-Event-ID`.
    pub fn with_replay(replay: usize) -> Self {
        Self {
            inner: Mutex::new(HubInner::default()),
            replay: replay.max(1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HubInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The id of the last published event (0 before the first).
    pub fn current_seq(&self) -> u64 {
        self.lock().seq
    }

    /// Publish an event to every client that may see it; returns its id.
    pub fn publish(&self, event: SseEvent, scope: Scope) -> u64 {
        self.publish_sized(event, scope, SMALL_EVENT)
    }

    /// [`Self::publish`] for an event of about `size` bytes (an audit record's JSON): the
    /// replay ring keeps at most [`REPLAY_EVENTS`] events and [`REPLAY_BYTES`] bytes.
    pub fn publish_sized(&self, event: SseEvent, scope: Scope, size: usize) -> u64 {
        let mut inner = self.lock();
        inner.seq += 1;
        let ev = Arc::new(HubEvent {
            seq: inner.seq,
            event,
            scope,
        });
        let size = size.max(SMALL_EVENT);
        inner.ring.push_back((ev.clone(), size));
        inner.ring_bytes += size;
        while inner.ring.len() > self.replay
            || (inner.ring_bytes > REPLAY_BYTES && inner.ring.len() > 1)
        {
            if let Some((_, s)) = inner.ring.pop_front() {
                inner.ring_bytes = inner.ring_bytes.saturating_sub(s);
            }
        }
        inner.clients.retain(|w| match w.upgrade() {
            Some(c) => {
                if c.filter.admits(&ev.scope) {
                    c.push(ev.clone());
                }
                true
            }
            None => false,
        });
        ev.seq
    }

    /// A new client. With `last_event_id` it first gets the events after that id (or a `reset`
    /// when they are not all in the ring any more, or the id is from the future).
    pub fn subscribe(&self, filter: ClientFilter, last_event_id: Option<u64>) -> Arc<ClientQueue> {
        let mut inner = self.lock();
        let q = Arc::new(ClientQueue::new(filter));
        if let Some(id) = last_event_id {
            let oldest = inner.ring.front().map(|(e, _)| e.seq);
            let replayable =
                id <= inner.seq && (id == inner.seq || oldest.is_some_and(|o| id + 1 >= o));
            if replayable {
                for (ev, _) in inner.ring.iter().filter(|(e, _)| e.seq > id) {
                    if q.filter.admits(&ev.scope) {
                        q.push(ev.clone());
                    }
                }
            } else {
                q.lock().reset = Some(inner.seq);
                q.notify.notify_one();
            }
        }
        inner.clients.push(Arc::downgrade(&q));
        q
    }

    /// Connected clients.
    pub fn clients(&self) -> usize {
        let mut inner = self.lock();
        inner.clients.retain(|w| w.strong_count() > 0);
        inner.clients.len()
    }
}

/// One record of the ring.
#[derive(Debug, Clone)]
pub struct RingRecord {
    pub record: Arc<AuditRecord>,
    pub size: usize,
}

#[derive(Debug, Default)]
struct RingInner {
    records: VecDeque<RingRecord>,
    bytes: usize,
}

/// The recent audit records, at most `events.retain_bytes` of their JSON, oldest evicted first.
#[derive(Debug, Default)]
pub struct AuditRing {
    inner: Mutex<RingInner>,
}

impl AuditRing {
    fn lock(&self) -> std::sync::MutexGuard<'_, RingInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Keep `record` (`size`: its JSON size); returns the records evicted to stay within
    /// `retain_bytes`.
    pub fn push(
        &self,
        record: Arc<AuditRecord>,
        size: usize,
        retain_bytes: u64,
    ) -> Vec<Arc<AuditRecord>> {
        let mut inner = self.lock();
        inner.records.push_back(RingRecord { record, size });
        inner.bytes += size;
        let mut evicted = Vec::new();
        let limit = usize::try_from(retain_bytes).unwrap_or(usize::MAX);
        while inner.bytes > limit && inner.records.len() > 1 {
            if let Some(old) = inner.records.pop_front() {
                inner.bytes = inner.bytes.saturating_sub(old.size);
                evicted.push(old.record);
            }
        }
        evicted
    }

    /// The records `keep` accepts, newest first by `ts`, equal timestamps in reverse arrival
    /// order; at most `limit`.
    pub fn query(
        &self,
        keep: impl Fn(&AuditRecord) -> bool,
        limit: usize,
    ) -> Vec<Arc<AuditRecord>> {
        let inner = self.lock();
        let mut out: Vec<Arc<AuditRecord>> = inner
            .records
            .iter()
            .rev()
            .filter(|r| keep(&r.record))
            .map(|r| r.record.clone())
            .collect();
        drop(inner);
        // stable: equal timestamps keep the reverse arrival order
        out.sort_by(|a, b| b.ts.cmp(&a.ts));
        out.truncate(limit);
        out
    }

    pub fn len(&self) -> usize {
        self.lock().records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{GraphEvent, RegistryEvent, RegistryStatus};

    fn all(admin: bool) -> ClientFilter {
        ClientFilter {
            namespaces: vec!["*".into()],
            admin,
            namespace: None,
            service: None,
            payloads: true,
        }
    }

    fn graph(v: u64) -> SseEvent {
        SseEvent::Graph(GraphEvent {
            version: v.to_string(),
        })
    }

    fn registry(ns: &str, svc: &str) -> (SseEvent, Scope) {
        (
            SseEvent::Registry(RegistryEvent {
                namespace: ns.into(),
                service: svc.into(),
                instance_id: "i".into(),
                pod: "p".into(),
                status: RegistryStatus::Connected,
            }),
            Scope::Service {
                namespace: ns.into(),
                service: svc.into(),
            },
        )
    }

    fn seqs(q: &ClientQueue) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(i) = q.try_next() {
            out.push(match i {
                Item::Event(e) => format!("{}", e.seq),
                Item::Lagged { dropped, seq } => format!("lagged {dropped}@{seq}"),
                Item::Reset { seq } => format!("reset@{seq}"),
            });
        }
        out
    }

    #[test]
    fn filters() {
        let shop = ClientFilter {
            namespaces: vec!["shop".into()],
            admin: false,
            namespace: None,
            service: Some("orders".into()),
            payloads: false,
        };
        let svc = |ns: &str, s: &str| Scope::Service {
            namespace: ns.into(),
            service: s.into(),
        };
        assert!(shop.admits(&Scope::All));
        assert!(shop.admits(&svc("shop", "orders")));
        assert!(!shop.admits(&svc("shop", "billing")));
        assert!(!shop.admits(&svc("other", "orders")));
        let admin_scope = Scope::Admin {
            namespace: None,
            service: None,
        };
        assert!(!shop.admits(&admin_scope));
        let mut admin = all(true);
        admin.namespaces = vec!["shop".into()];
        assert!(admin.admits(&admin_scope));
        assert!(!admin.admits(&Scope::Admin {
            namespace: Some("other".into()),
            service: None
        }));
        assert!(admin.admits(&Scope::Admin {
            namespace: Some("shop".into()),
            service: Some("x".into())
        }));
    }

    #[test]
    fn ids_increase_and_replay_after_last_event_id() {
        let hub = EventHub::with_replay(4);
        for v in 1..=3 {
            hub.publish(graph(v), Scope::All);
        }
        assert_eq!(hub.current_seq(), 3);
        // within the ring: the events after the id
        let q = hub.subscribe(all(false), Some(1));
        assert_eq!(seqs(&q), ["2", "3"]);
        // at the head: nothing
        let q = hub.subscribe(all(false), Some(3));
        assert!(seqs(&q).is_empty());
        // older than the ring
        for v in 4..=8 {
            hub.publish(graph(v), Scope::All);
        }
        let q = hub.subscribe(all(false), Some(2));
        assert_eq!(seqs(&q), ["reset@8"]);
        // the oldest kept event is 5: id 4 can still be replayed
        let q = hub.subscribe(all(false), Some(4));
        assert_eq!(seqs(&q), ["5", "6", "7", "8"]);
        // from the future (a restarted server)
        let q = hub.subscribe(all(false), Some(99));
        assert_eq!(seqs(&q), ["reset@8"]);
        // live after a reset
        hub.publish(graph(9), Scope::All);
        assert_eq!(seqs(&q), ["9"]);
        assert!(hub.clients() >= 1);
    }

    #[test]
    fn the_replay_ring_is_bounded_in_bytes_too() {
        let hub = EventHub::default();
        hub.publish_sized(graph(1), Scope::All, REPLAY_BYTES / 2);
        hub.publish_sized(graph(2), Scope::All, REPLAY_BYTES / 2);
        // a third half fills it over: the first goes
        hub.publish_sized(graph(3), Scope::All, REPLAY_BYTES / 2);
        let q = hub.subscribe(all(false), Some(0));
        assert_eq!(seqs(&q), ["reset@3"]);
        let q = hub.subscribe(all(false), Some(1));
        assert_eq!(seqs(&q), ["2", "3"]);
    }

    #[test]
    fn replay_applies_the_filters() {
        let hub = EventHub::default();
        let (e, s) = registry("shop", "orders");
        hub.publish(e, s);
        let (e, s) = registry("other", "x");
        hub.publish(e, s);
        let mut f = all(false);
        f.namespaces = vec!["shop".into()];
        let q = hub.subscribe(f, Some(0));
        assert_eq!(seqs(&q), ["1"]);
    }

    #[test]
    fn an_overflow_drops_the_queue_and_counts_until_read() {
        let hub = EventHub::default();
        let q = hub.subscribe(all(false), None);
        for v in 0..CLIENT_QUEUE as u64 {
            hub.publish(graph(v), Scope::All);
        }
        assert_eq!(q.len(), CLIENT_QUEUE);
        // the one that does not fit, and 10 more before the client reads
        for v in 0..11 {
            hub.publish(graph(v), Scope::All);
        }
        assert_eq!(q.len(), 0);
        let last = hub.current_seq();
        assert_eq!(
            q.try_next(),
            Some(Item::Lagged {
                dropped: CLIENT_QUEUE as u64 + 11,
                seq: last
            })
        );
        // after the lagged event, events queue again
        hub.publish(graph(1), Scope::All);
        assert_eq!(seqs(&q), [format!("{}", last + 1)]);
        // filtered-out events do not count
        let mut f = all(false);
        f.namespaces = vec!["shop".into()];
        let q = hub.subscribe(f, None);
        for _ in 0..2000 {
            let (e, s) = registry("other", "x");
            hub.publish(e, s);
        }
        assert!(q.try_next().is_none());
    }

    #[tokio::test]
    async fn next_waits_for_an_event() {
        let hub = Arc::new(EventHub::default());
        let q = hub.subscribe(all(false), None);
        let h = hub.clone();
        let task = tokio::spawn(async move { q.next().await });
        tokio::task::yield_now().await;
        h.publish(graph(1), Scope::All);
        match task.await.unwrap() {
            Item::Event(e) => assert_eq!(e.seq, 1),
            other => panic!("{other:?}"),
        }
    }

    fn rec(ts: &str, kind: &str) -> Arc<AuditRecord> {
        Arc::new(
            serde_json::from_value(serde_json::json!({
                "ts": ts, "kind": kind, "request_id": "r", "trace_id": "t", "service": "s",
                "caller": "local", "callee": "c", "direction": "internal", "decision": "allow"
            }))
            .unwrap(),
        )
    }

    #[test]
    fn the_ring_keeps_retain_bytes_and_orders_newest_first() {
        let ring = AuditRing::default();
        assert!(ring.is_empty());
        assert!(
            ring.push(rec("2026-10-21T10:00:01.000Z", "a"), 100, 1000)
                .is_empty()
        );
        ring.push(rec("2026-10-21T10:00:00.000Z", "b"), 100, 1000);
        ring.push(rec("2026-10-21T10:00:01.000Z", "c"), 100, 1000);
        let got: Vec<String> = ring
            .query(|_| true, 10)
            .iter()
            .map(|r| r.kind.clone())
            .collect();
        // equal ts: reverse arrival (c arrived after a)
        assert_eq!(got, ["c", "a", "b"]);
        assert_eq!(ring.query(|r| r.kind != "c", 1)[0].kind, "a");
        let evicted = ring.push(rec("2026-10-21T10:00:02.000Z", "d"), 900, 1000);
        assert_eq!(
            evicted.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(ring.bytes(), 1000);
        assert_eq!(ring.len(), 2);
        // a single record bigger than the budget stays until the next one
        let evicted = ring.push(rec("2026-10-21T10:00:03.000Z", "e"), 5000, 1000);
        assert_eq!(evicted.len(), 2);
        assert_eq!(ring.len(), 1);
    }
}
