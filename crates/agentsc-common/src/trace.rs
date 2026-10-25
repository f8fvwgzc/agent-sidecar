//! W3C `traceparent` handling: `00-<32 hex trace id>-<16 hex span id>-<2 hex flags>`.
use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
}

fn hex_bytes(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    let s = hex::encode(buf);
    if s.chars().all(|c| c == '0') {
        "1".repeat(n * 2)
    } else {
        s
    }
}

impl TraceContext {
    /// A brand new trace with a root span.
    pub fn new_root() -> Self {
        Self {
            trace_id: hex_bytes(16),
            span_id: hex_bytes(8),
            parent_span_id: None,
        }
    }

    /// Parse an incoming `traceparent`; invalid or empty → new root.
    pub fn from_traceparent(header: &str) -> Self {
        match Self::parse(header) {
            Some((trace_id, parent)) => Self {
                trace_id,
                span_id: hex_bytes(8),
                parent_span_id: Some(parent),
            },
            None => Self::new_root(),
        }
    }

    pub fn parse(header: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = header.trim().split('-').collect();
        if parts.len() < 4 || parts[0] != "00" {
            return None;
        }
        let (t, s) = (parts[1], parts[2]);
        let is_hex =
            |x: &str| x.chars().all(|c| c.is_ascii_hexdigit()) && !x.chars().all(|c| c == '0');
        if t.len() != 32 || s.len() != 16 || !is_hex(t) || !is_hex(s) {
            return None;
        }
        Some((t.to_lowercase(), s.to_lowercase()))
    }

    /// A child span in the same trace.
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: hex_bytes(8),
            parent_span_id: Some(self.span_id.clone()),
        }
    }

    /// The header value to send downstream (this span becomes the parent).
    pub fn traceparent(&self) -> String {
        format!("00-{}-{}-01", self.trace_id, self.span_id)
    }
}

pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_propagates() {
        let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::from_traceparent(tp);
        assert_eq!(ctx.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.parent_span_id.as_deref(), Some("00f067aa0ba902b7"));
        assert_ne!(ctx.span_id, "00f067aa0ba902b7");
        let child = ctx.child();
        assert_eq!(child.trace_id, ctx.trace_id);
        assert_eq!(child.parent_span_id.as_deref(), Some(ctx.span_id.as_str()));
        assert!(TraceContext::parse(&child.traceparent()).is_some());
    }

    #[test]
    fn garbage_becomes_root() {
        let ctx = TraceContext::from_traceparent("nope");
        assert_eq!(ctx.trace_id.len(), 32);
        assert!(ctx.parent_span_id.is_none());
        assert!(
            TraceContext::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01")
                .is_none()
        );
    }
}
