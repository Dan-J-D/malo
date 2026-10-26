use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use malo_api::ApiError;

#[derive(Debug)]
pub struct ApiErr {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiErr>;

impl ApiErr {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiErr {
            status,
            code,
            message: message.into(),
        }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", m)
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", m)
    }
    pub fn forbidden(m: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", m)
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", m)
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", m)
    }
    pub fn locked() -> Self {
        Self::new(StatusCode::LOCKED, "locked", "Locked — log in to resume")
    }
    pub fn too_many(m: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", m)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiError {
                error: self.message,
                code: self.code.to_string(),
            }),
        )
            .into_response()
    }
}

/// An unexpected failure: the details (paths, SQL, addresses on the server's network) go to the
/// log under a reference the client gets instead.
impl From<anyhow::Error> for ApiErr {
    fn from(e: anyhow::Error) -> Self {
        let reference = hex::encode(rand::random::<[u8; 4]>());
        tracing::warn!(reference, "request failed: {e:#}");
        ApiErr::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            format!("internal error (reference {reference}; the server log has the details)"),
        )
    }
}

impl From<rusqlite::Error> for ApiErr {
    fn from(e: rusqlite::Error) -> Self {
        anyhow::Error::from(e).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_keep_their_details_in_the_log() {
        let e: ApiErr =
            anyhow::anyhow!("cannot open /data/users/u1/index.db: disk I/O error").into();
        assert_eq!(e.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !e.message.contains("/data") && e.message.contains("reference"),
            "{}",
            e.message
        );
    }
}
