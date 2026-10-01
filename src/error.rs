use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    /// 400 Bad Request — the caller sent something the server can prove
    /// is wrong without touching the DB (empty selection, malformed
    /// query parameter, etc). Distinct from `Internal` (500) so the
    /// client can tell "you sent bad input" from "the server broke".
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Reserved for future endpoints that want a 401 rather than redirect.
    /// Currently the auth middleware bounces unauthenticated requests to
    /// `/login` so this variant isn't constructed yet.
    #[allow(dead_code)]
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("database error")]
    Sqlx(#[from] sqlx::Error),

    #[error("template error")]
    Askama(#[from] askama::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal error: {0}")]
    Internal(String),

    /// The database query exceeded its budget. The client can retry
    /// with a tighter filter. Note: the underlying MySQL query may still
    /// be running server-side for a while (sqlx can't KILL QUERY without
    /// owning the connection); dropping this future releases our handle
    /// on it and the pool slot returns immediately.
    #[error("query timed out after {0}s")]
    QueryTimeout(u64),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            AppError::Sqlx(e) => {
                tracing::error!(error = ?e, "sqlx error");
                (StatusCode::INTERNAL_SERVER_ERROR, "database error".to_string())
            }
            AppError::Askama(e) => {
                tracing::error!(error = ?e, "askama error");
                (StatusCode::INTERNAL_SERVER_ERROR, "template error".to_string())
            }
            AppError::Io(e) => {
                tracing::error!(error = ?e, "io error");
                (StatusCode::INTERNAL_SERVER_ERROR, "io error".to_string())
            }
            AppError::Internal(m) => {
                tracing::error!(error = %m, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
            AppError::QueryTimeout(secs) => {
                tracing::warn!(secs, "query timed out");
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    format!("query timed out after {secs}s — try a narrower filter"),
                )
            }
        };
        (status, msg).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Wrap a future with a timeout. On expiry returns `QueryTimeout` (504).
/// The underlying work may keep running; the client-side future is
/// dropped, which releases any pool slot it was holding. Generic over
/// the future's error so it composes with both raw `sqlx::Error` futures
/// and helpers that already wrap them in `AppError`.
///
/// **A timeout of `0` disables the cap.** Without this branch,
/// `tokio::time::timeout(Duration::from_secs(0), …)` returns `Elapsed`
/// on the first poll, so `with_query_timeout(0, fut)` would *always*
/// 504 regardless of `fut`'s actual progress. The two places that pass
/// `0` deliberately (`cdr::ids_for_query_string`) want unbounded
/// execution so a user can fire a "download every matching CDR" job
/// without being raced by a 30s cap.
pub async fn with_query_timeout<F, T, E>(secs: u64, fut: F) -> AppResult<T>
where
    F: std::future::Future<Output = Result<T, E>>,
    AppError: From<E>,
{
    if secs == 0 {
        return fut.await.map_err(AppError::from);
    }
    match tokio::time::timeout(std::time::Duration::from_secs(secs), fut).await {
        Ok(r) => Ok(r?),
        Err(_) => Err(AppError::QueryTimeout(secs)),
    }
}
