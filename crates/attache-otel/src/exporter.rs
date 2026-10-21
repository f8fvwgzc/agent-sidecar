//! The background exporter: audit stream in, OTLP/HTTP JSON out (design §9).
//!
//! Two tasks. The *collector* drains the audit broadcast receiver, batches records for traces
//! ([`ExportTiming::batch_size`] records or every [`ExportTiming::batch_interval`]; a batch
//! becomes spans when it is flushed) and aggregates metrics (pushed every
//! [`ExportTiming::metrics_interval`]). It never awaits the network: a finished batch goes to a
//! small queue with `try_send`, and a batch that does not fit is dropped and counted. The
//! *sender* posts each queued payload with a [`ExportTiming::request_timeout`] timeout and, after
//! any failure, one retry; then it drops and counts it.
//!
//! The audit writer never waits for any of this: `tokio::sync::broadcast` drops the oldest
//! records for a receiver that falls behind, and the collector counts them (`Lagged(n)`) as
//! dropped. The count is [`ExporterHandle::dropped`] and the metric `attache.otel.dropped`.
//!
//! `traces`, `metrics` and `export_payloads` can change while the exporter runs
//! ([`ExporterHandle::set_flags`], for hot reload); the endpoint, headers and resource cannot.
use crate::config::{ExportFlags, OtelConfig, mask_password};
use crate::metrics::MetricsState;
use crate::otlp::{ExportMetricsServiceRequest, ExportTraceServiceRequest, Metric, Span};
use crate::spans::{next_sequence, now_unix_nanos, span_from_record};
use attache_common::audit::AuditRecord;
use attache_common::audit::SUBSCRIBE_CAPACITY;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior, interval_at};

/// Batching, timing and queueing. [`Default`] is the design's values; tests shorten them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportTiming {
    /// Records (spans) per traces request (256).
    pub batch_size: usize,
    /// A partial batch is sent after at most this long (2 s).
    pub batch_interval: Duration,
    /// Cumulative metrics are pushed this often (15 s).
    pub metrics_interval: Duration,
    /// Timeout of each HTTP attempt (5 s).
    pub request_timeout: Duration,
    /// Pause before the one retry (500 ms).
    pub retry_delay: Duration,
    /// Payloads waiting for the sender besides the one in flight (2). Bounds memory when the
    /// collector is slow or down.
    pub queue_capacity: usize,
}

impl Default for ExportTiming {
    fn default() -> Self {
        Self {
            batch_size: 256,
            batch_interval: Duration::from_secs(2),
            metrics_interval: Duration::from_secs(15),
            request_timeout: Duration::from_secs(5),
            retry_delay: Duration::from_millis(500),
            queue_capacity: 2,
        }
    }
}

impl ExportTiming {
    /// The longest [`ExporterHandle::shutdown`] waits for queued payloads after the final flush:
    /// one payload's two attempts and the pause between them.
    fn shutdown_grace(&self) -> Duration {
        self.request_timeout * 2 + self.retry_delay
    }
}

/// Starts exporters. See the module documentation.
pub struct Exporter;

impl Exporter {
    /// Start exporting the records `rx` delivers, with the design's timing. Must be called from
    /// inside a Tokio runtime.
    pub fn spawn(config: OtelConfig, rx: broadcast::Receiver<Arc<AuditRecord>>) -> ExporterHandle {
        Self::spawn_with(config, rx, ExportTiming::default())
    }

    /// [`Exporter::spawn`] with explicit timing.
    pub fn spawn_with(
        config: OtelConfig,
        rx: broadcast::Receiver<Arc<AuditRecord>>,
        timing: ExportTiming,
    ) -> ExporterHandle {
        let counters = Arc::new(Counters::default());
        let flags = Arc::new(SharedFlags::new(config.flags()));
        let (stop_tx, stop_rx) = oneshot::channel();
        let (queue_tx, queue_rx) = mpsc::channel(timing.queue_capacity.max(1));
        let sender = Sender::new(&config, &timing, counters.clone());
        let sender_task = tokio::spawn(sender.run(queue_rx));
        let collector = Collector {
            start_unix_nano: now_unix_nanos(),
            pending: Vec::new(),
            metrics: MetricsState::new(),
            counters: counters.clone(),
            flags: flags.clone(),
            queue: queue_tx,
            timing,
        };
        let task = tokio::spawn(collector.run(rx, stop_rx, sender_task));
        ExporterHandle {
            counters,
            flags,
            stop: Some(stop_tx),
            task: Some(task),
        }
    }
}

/// A running exporter. Dropping the handle detaches it: the exporter keeps running (with the
/// flags it had) until the audit writer (the broadcast sender) is gone, then flushes and stops.
pub struct ExporterHandle {
    counters: Arc<Counters>,
    flags: Arc<SharedFlags>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl ExporterHandle {
    /// Apply a hot reload's `traces`, `metrics` and `export_payloads` without restarting the
    /// exporter: the cumulative metrics and their start time carry on, and the change itself
    /// neither loses nor duplicates a record. It applies to every record not yet handed to the
    /// sender, including the batch being collected (records still in the broadcast channel,
    /// written just before the change, get the new flags too); spans already queued or in
    /// flight are sent as they were built.
    ///
    /// - `traces: false` stops making spans (records already batched are still sent).
    /// - `metrics: false` stops the pushes; aggregation goes on, so turning metrics back on
    ///   reports complete totals over the same cumulative window.
    /// - Both off leaves an idle exporter that keeps draining the audit stream.
    ///
    /// The endpoint, headers and resource are fixed for the exporter's life: the endpoint is a
    /// restart-only field (design §4). The integration contract on reload is therefore: with a
    /// running exporter, call `set_flags(ExportFlags::from_telemetry(new.telemetry.as_ref()))`;
    /// without one (start-up [`OtelConfig::resolve`] returned `None`), resolve again with the
    /// new charter and spawn if it now returns `Some` — that only happens when the start-up
    /// charter had both signals off, since the endpoint inputs cannot change.
    pub fn set_flags(&self, flags: ExportFlags) {
        self.flags.store(flags);
    }

    /// The flags in effect.
    pub fn flags(&self) -> ExportFlags {
        self.flags.load()
    }

    /// Audit records lost so far: missed because the receiver lagged, or in a span batch that
    /// was not delivered (queue full, timeout, or failure after the retry). A failed metrics push
    /// is not counted: metrics are cumulative and the next push carries the same totals.
    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    /// Stop: take the records already in the channel, send the pending spans and a final metrics
    /// push, wait for the queued payloads, and return the final [`ExporterHandle::dropped`]
    /// count. Bounded: with the default timing it takes at most about 21 s (twice the time one
    /// payload may take: two 5 s attempts and the retry pause) even when the collector hangs.
    pub async fn shutdown(mut self) -> u64 {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        self.dropped()
    }
}

/// Shared between the collector, the sender and the handle.
#[derive(Default)]
struct Counters {
    /// Records lost (lagged, or in a span batch that was not delivered).
    dropped: AtomicU64,
    /// Records in span batches handed to the sender and not yet delivered or dropped; counted as
    /// dropped if shutdown has to abort the sender.
    in_flight: AtomicU64,
}

impl Counters {
    fn drop_records(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }
}

/// [`ExportFlags`] in one atomic byte, so a reader never sees half of an update.
struct SharedFlags(AtomicU8);

impl SharedFlags {
    const TRACES: u8 = 1;
    const METRICS: u8 = 2;
    const PAYLOADS: u8 = 4;

    fn new(flags: ExportFlags) -> Self {
        Self(AtomicU8::new(Self::bits(flags)))
    }

    fn bits(f: ExportFlags) -> u8 {
        (if f.traces { Self::TRACES } else { 0 })
            | (if f.metrics { Self::METRICS } else { 0 })
            | (if f.export_payloads { Self::PAYLOADS } else { 0 })
    }

    fn store(&self, flags: ExportFlags) {
        self.0.store(Self::bits(flags), Ordering::Relaxed);
    }

    fn load(&self) -> ExportFlags {
        let b = self.0.load(Ordering::Relaxed);
        ExportFlags {
            traces: b & Self::TRACES != 0,
            metrics: b & Self::METRICS != 0,
            export_payloads: b & Self::PAYLOADS != 0,
        }
    }
}

enum Payload {
    Traces(Vec<Span>),
    Metrics(Vec<Metric>),
}

struct Collector {
    start_unix_nano: u64,
    /// Records of the traces batch being collected; they become spans when it is flushed, with
    /// the `export_payloads` in effect then.
    pending: Vec<Arc<AuditRecord>>,
    metrics: MetricsState,
    counters: Arc<Counters>,
    flags: Arc<SharedFlags>,
    queue: mpsc::Sender<Payload>,
    timing: ExportTiming,
}

impl Collector {
    async fn run(
        mut self,
        mut rx: broadcast::Receiver<Arc<AuditRecord>>,
        mut stop: oneshot::Receiver<()>,
        sender_task: JoinHandle<()>,
    ) {
        let mut batch_tick = ticker(self.timing.batch_interval);
        let mut metrics_tick = ticker(self.timing.metrics_interval);
        let mut detached = false;
        loop {
            tokio::select! {
                r = &mut stop, if !detached => match r {
                    Ok(()) => {
                        self.drain(&mut rx);
                        break;
                    }
                    // The handle was dropped: keep running until the audit writer goes away.
                    Err(_) => detached = true,
                },
                r = rx.recv() => match r {
                    Ok(rec) => self.ingest(rec),
                    Err(RecvError::Lagged(n)) => self.lagged(n),
                    Err(RecvError::Closed) => break,
                },
                _ = batch_tick.tick() => self.flush_spans(),
                _ = metrics_tick.tick() => self.push_metrics(),
            }
        }
        self.finish(sender_task).await;
    }

    fn lagged(&mut self, n: u64) {
        self.counters.drop_records(n);
        tracing::warn!(
            dropped = n,
            "OpenTelemetry exporter fell behind the audit stream; records dropped"
        );
    }

    /// On shutdown, take what was already delivered to the channel (bounded, so a writer that
    /// keeps writing cannot hold shutdown up).
    fn drain(&mut self, rx: &mut broadcast::Receiver<Arc<AuditRecord>>) {
        for _ in 0..=SUBSCRIBE_CAPACITY {
            match rx.try_recv() {
                Ok(rec) => self.ingest(rec),
                Err(TryRecvError::Lagged(n)) => self.lagged(n),
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
            }
        }
    }

    fn ingest(&mut self, rec: Arc<AuditRecord>) {
        // Aggregated whatever `metrics` is, so that turning it on later reports complete totals
        // over the one cumulative window (bounded by `MAX_SERIES` per metric).
        self.metrics.record(&rec);
        if self.flags.load().traces {
            self.pending.push(rec);
            if self.pending.len() >= self.timing.batch_size.max(1) {
                self.flush_spans();
            }
        }
    }

    /// The pending batch as spans, with the `export_payloads` in effect now.
    fn take_spans(&mut self) -> Vec<Span> {
        let export_payloads = self.flags.load().export_payloads;
        std::mem::take(&mut self.pending)
            .iter()
            .map(|rec| span_from_record(rec, next_sequence(), export_payloads))
            .collect()
    }

    fn flush_spans(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let spans = self.take_spans();
        let n = spans.len() as u64;
        // Counted before the send: the sender may finish the batch before `try_send` returns.
        self.counters.in_flight.fetch_add(n, Ordering::Relaxed);
        if self.queue.try_send(Payload::Traces(spans)).is_err() {
            self.counters.in_flight.fetch_sub(n, Ordering::Relaxed);
            self.counters.drop_records(n);
            tracing::debug!(
                spans = n,
                "OpenTelemetry export queue full; span batch dropped"
            );
        }
    }

    fn metrics_payload(&self) -> Payload {
        Payload::Metrics(self.metrics.to_metrics(
            self.start_unix_nano,
            now_unix_nanos(),
            self.counters.dropped.load(Ordering::Relaxed),
        ))
    }

    fn push_metrics(&mut self) {
        if !self.flags.load().metrics {
            return;
        }
        if self.queue.try_send(self.metrics_payload()).is_err() {
            tracing::debug!("OpenTelemetry export queue full; metrics push skipped");
        }
    }

    /// Final flush: wait (bounded) for room in the queue instead of dropping, then let the sender
    /// drain it (bounded too). Whatever is still undelivered when time is up counts as dropped.
    async fn finish(mut self, sender_task: JoinHandle<()>) {
        let deadline = Instant::now() + self.timing.shutdown_grace();
        if !self.pending.is_empty() {
            let spans = self.take_spans();
            let n = spans.len() as u64;
            self.counters.in_flight.fetch_add(n, Ordering::Relaxed);
            let sent =
                tokio::time::timeout_at(deadline, self.queue.send(Payload::Traces(spans))).await;
            if !matches!(sent, Ok(Ok(()))) {
                self.counters.in_flight.fetch_sub(n, Ordering::Relaxed);
                self.counters.drop_records(n);
            }
        }
        if self.flags.load().metrics {
            let payload = self.metrics_payload();
            let _ = tokio::time::timeout_at(deadline, self.queue.send(payload)).await;
        }
        drop(self.queue);
        let abort = sender_task.abort_handle();
        let finished =
            tokio::time::timeout_at(deadline + self.timing.shutdown_grace(), sender_task).await;
        if !matches!(finished, Ok(Ok(()))) {
            abort.abort();
            let lost = self.counters.in_flight.swap(0, Ordering::Relaxed);
            self.counters.drop_records(lost);
            tracing::warn!(
                dropped = lost,
                "OpenTelemetry exporter stopped before every payload was sent"
            );
        }
    }
}

/// A periodic timer whose first tick is one period from now (a zero period is taken as 1 ms).
fn ticker(period: Duration) -> tokio::time::Interval {
    let period = period.max(Duration::from_millis(1));
    let mut t = interval_at(Instant::now() + period, period);
    t.set_missed_tick_behavior(MissedTickBehavior::Delay);
    t
}

struct Sender {
    client: Option<reqwest::Client>,
    traces_url: String,
    metrics_url: String,
    headers: reqwest::header::HeaderMap,
    resource: Vec<(String, String)>,
    retry_delay: Duration,
    counters: Arc<Counters>,
    failing: bool,
}

impl Sender {
    fn new(config: &OtelConfig, timing: &ExportTiming, counters: Arc<Counters>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timing.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| tracing::error!("OpenTelemetry exporter: HTTP client: {e}; export is off"))
            .ok();
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in &config.headers {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                headers.append(name, value);
            }
        }
        let base = config.endpoint.trim_end_matches('/');
        Self {
            client,
            traces_url: format!("{base}/v1/traces"),
            metrics_url: format!("{base}/v1/metrics"),
            headers,
            resource: config.resource.clone(),
            retry_delay: timing.retry_delay,
            counters,
            failing: false,
        }
    }

    async fn run(mut self, mut queue: mpsc::Receiver<Payload>) {
        while let Some(payload) = queue.recv().await {
            let (url, body, records) = match payload {
                Payload::Traces(spans) => {
                    let n = spans.len() as u64;
                    let req = ExportTraceServiceRequest::new(&self.resource, spans);
                    (self.traces_url.clone(), serde_json::to_vec(&req), n)
                }
                Payload::Metrics(metrics) => {
                    let req = ExportMetricsServiceRequest::new(&self.resource, metrics);
                    (self.metrics_url.clone(), serde_json::to_vec(&req), 0)
                }
            };
            let delivered = match body {
                Ok(body) => self.post(&url, body).await,
                Err(e) => {
                    tracing::warn!("OpenTelemetry exporter: encoding: {e}");
                    false
                }
            };
            // No await between these two, so an abort never sees the batch half-accounted.
            if !delivered {
                self.counters.drop_records(records);
            }
            self.counters
                .in_flight
                .fetch_sub(records, Ordering::Relaxed);
        }
    }

    /// One attempt and, after any failure (transport error, timeout or a non-2xx status), one
    /// retry after [`ExportTiming::retry_delay`]; then the payload is given up (design §9: "5 s
    /// timeout; one retry; then drop and count"). This is wider than the OTLP specification's
    /// retryable list (429, 502, 503, 504): a 400 or 500 is retried once too.
    async fn post(&mut self, url: &str, body: Vec<u8>) -> bool {
        if self.client.is_none() {
            return self.failed(url, "no HTTP client");
        }
        let first = match self.attempt(url, body.clone()).await {
            Ok(()) => return self.succeeded(),
            Err(e) => e,
        };
        tracing::debug!(url = %mask_password(url), error = %first, "OpenTelemetry export failed; retrying once");
        tokio::time::sleep(self.retry_delay).await;
        match self.attempt(url, body).await {
            Ok(()) => self.succeeded(),
            Err(e) => self.failed(url, &e),
        }
    }

    async fn attempt(&self, url: &str, body: Vec<u8>) -> Result<(), String> {
        let Some(client) = &self.client else {
            return Err("no HTTP client".into());
        };
        let resp = client
            .post(url)
            .headers(self.headers.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
        match resp {
            Ok(r) if r.status().is_success() => Ok(()),
            Ok(r) => Err(format!("HTTP {}", r.status())),
            Err(e) => Err(e.without_url().to_string()),
        }
    }

    fn succeeded(&mut self) -> bool {
        if self.failing {
            self.failing = false;
            tracing::info!("OpenTelemetry export recovered");
        }
        true
    }

    /// Logged at warn once per failure streak, then at debug.
    fn failed(&mut self, url: &str, error: &str) -> bool {
        if self.failing {
            tracing::debug!(url = %mask_password(url), error, "OpenTelemetry export failed");
        } else {
            self.failing = true;
            tracing::warn!(url = %mask_password(url), error, "OpenTelemetry export failed; dropping and counting");
        }
        false
    }
}
