//! Error responses: an [`ApiError`] body with the status of its code (design §10, Errors).
use axum::Json;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use super::types::{ApiError, ErrorCode};
use crate::store::{ProposalStatus, StoreError};

/// A failed request: the error body and any extra headers (`Retry-After`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    pub body: ApiError,
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl Fail {
    pub fn new(code: ErrorCode, details: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            body: ApiError::new(code, details),
            headers: Vec::new(),
        }
    }

    pub fn invalid(details: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(ErrorCode::Invalid, details)
    }

    pub fn forbidden(details: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(ErrorCode::Forbidden, details)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, [detail.into()])
    }

    pub fn unauthenticated() -> Self {
        Self::new(ErrorCode::Unauthenticated, Vec::<String>::new())
    }

    pub fn conflict(current: impl Into<String>) -> Self {
        Self {
            body: ApiError::version_conflict(current),
            headers: Vec::new(),
        }
    }

    pub fn in_use(details: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(ErrorCode::InUse, details)
    }

    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "request failed");
        Self::new(ErrorCode::Internal, [e.to_string()])
    }

    /// One more detail (a 409 that names what is in the way).
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.body.details.push(detail.into());
        self
    }

    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.body.error
    }

    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.body.error.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// The details joined (for audit reasons).
    pub fn reason(&self) -> String {
        let code = serde_json::to_value(self.body.error)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if self.body.details.is_empty() {
            code
        } else {
            format!("{code}: {}", self.body.details.join("; "))
        }
    }

    /// A store error for the resource `what` (`"no charter for shop/orders"`).
    pub fn store(e: StoreError, what: &str) -> Self {
        match e {
            StoreError::NotFound => Self::not_found(what),
            StoreError::Conflict { current } => Self::conflict(current),
            StoreError::NotPending { status } => {
                let s = match status {
                    ProposalStatus::Pending => "pending",
                    ProposalStatus::Approved => "approved",
                    ProposalStatus::Rejected => "rejected",
                };
                Self::new(
                    ErrorCode::NotPending,
                    [format!("the proposal is already {s}")],
                )
            }
            StoreError::Invalid(d) => Self::invalid(d),
            StoreError::Io(e) => Self::internal(e),
        }
    }
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut resp = (status, Json(self.body)).into_response();
        for (k, v) in self.headers {
            resp.headers_mut().insert(k, v);
        }
        resp
    }
}

impl From<StoreError> for Fail {
    fn from(e: StoreError) -> Self {
        Self::store(e, "not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_and_reasons() {
        let f = Fail::store(
            StoreError::Conflict {
                current: "4".into(),
            },
            "x",
        );
        assert_eq!(f.status(), StatusCode::CONFLICT);
        assert_eq!(f.body.current_version.as_deref(), Some("4"));
        let f = Fail::store(
            StoreError::NotPending {
                status: ProposalStatus::Rejected,
            },
            "x",
        );
        assert_eq!(f.code(), ErrorCode::NotPending);
        assert!(f.reason().contains("already rejected"), "{}", f.reason());
        assert_eq!(
            Fail::store(StoreError::NotFound, "no such thing")
                .body
                .details,
            ["no such thing"]
        );
        assert_eq!(Fail::invalid(["a", "b"]).reason(), "invalid: a; b");
        assert_eq!(
            Fail::new(ErrorCode::MisdirectedRequest, Vec::<String>::new()).status(),
            StatusCode::MISDIRECTED_REQUEST
        );
        let resp = Fail::new(ErrorCode::RateLimited, ["slow down"])
            .with_header(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("3"),
            )
            .into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()["retry-after"], "3");
    }
}
