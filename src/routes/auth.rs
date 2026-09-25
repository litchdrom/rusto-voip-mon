//! `/auth/token` — long-lived API bearer tokens.
//!
//! Three endpoints:
//!
//! - `POST /auth/tokens`       — exchange username + password for a token
//! - `GET  /auth/tokens`       — list your own active tokens (no secrets)
//! - `DELETE /auth/tokens/:id` — revoke one of your tokens
//!
//! All three require an authenticated user. Token issuance additionally
//! requires a fresh username + password (a user holding a valid token can
//! list / revoke, but cannot mint new ones without re-proving their
//! password). That keeps a stolen session cookie or token from being used
//! to spawn unlimited long-lived tokens.
//!
//! ## Request / response shapes
//!
//! ### Create — `POST /auth/tokens`
//! ```json
//! { "username": "admin", "password": "...", "label": "CI deploy", "ttl_seconds": 7776000 }
//! ```
//! Response 200:
//! ```json
//! { "token": "abc...64hex...def.hmac64hex", "expires_at": 1234567890 }
//! ```
//!
//! ### List — `GET /auth/tokens`
//! Response 200:
//! ```json
//! [
//!   { "id": "abc...64hex...", "label": "CI deploy", "created_at": 1234560000, "expires_at": 1240000000 }
//! ]
//! ```
//! Only tokens belonging to the calling user are returned (admins don't
//! see other users' tokens here; that would be a separate admin-only
//! endpoint if we ever need it).
//!
//! ### Revoke — `DELETE /auth/tokens/:id`
//! 204 No Content on success, 404 if the id doesn't belong to the caller
//! (or doesn't exist), 401 if unauthenticated.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{
        password,
        session::SessionUser,
        token::{SessionUserSnapshot, TokenEntry, MAX_TTL_SECS},
    },
    error::{AppError, AppResult},
    state::AppState,
};

/// Body for `POST /auth/tokens`.
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub username: String,
    pub password: String,
    /// Optional human-readable label. Stored alongside the token so the
    /// `GET /auth/tokens` listing makes it obvious which one to revoke
    /// later ("which one was the prod deploy key again?").
    #[serde(default)]
    pub label: Option<String>,
    /// Time-to-live in seconds. Defaults to 90 days; capped at 5 years.
    /// We refuse to mint "forever" tokens because every active token is
    /// a future revocation job; an unbounded one would be a footgun.
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

/// Response body for `POST /auth/tokens`.
#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    pub token: String,
    pub expires_at: i64,
}

/// One entry in the `GET /auth/tokens` response. Never includes the
/// token value itself — only the id (first half, used as a stable
/// identifier) and metadata.
#[derive(Debug, Serialize)]
pub struct TokenSummary {
    pub id: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
}

impl From<TokenEntry> for TokenSummary {
    fn from(e: TokenEntry) -> Self {
        Self {
            id: e.id,
            label: e.label,
            created_at: e.created_at,
            expires_at: e.expires_at,
        }
    }
}

/// Exchange username + password for a long-lived API token.
pub async fn create_token(
    State(state): State<AppState>,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<Response> {
    // Verify the password. `verify_login` already normalises the username
    // lookup + bcrypt/MD5 handling — we don't need to duplicate that.
    let verified = password::verify_login(&state.pool, &req.username, &req.password)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let user = verified.user;

    // Cap the TTL. A typo in a config file shouldn't mint a 1000-year
    // token, so we clamp to a sane upper bound regardless of what the
    // caller asked for.
    let ttl = req
        .ttl_seconds
        .unwrap_or(crate::auth::token::DEFAULT_TTL_SECS)
        .clamp(60, MAX_TTL_SECS);

    let (token, entry) = state.tokens.create(&user, req.label, ttl);
    tracing::info!(
        user_id = user.user_id,
        username = %user.username,
        token_id = %entry.id,
        ttl_seconds = ttl,
        "issued API bearer token"
    );

    Ok((
        StatusCode::OK,
        Json(CreateTokenResponse {
            token,
            expires_at: entry.expires_at,
        }),
    )
        .into_response())
}

/// List the calling user's active API tokens. The token secrets are
/// never returned — only the metadata needed to identify which one
/// to revoke.
pub async fn list_tokens(
    State(state): State<AppState>,
    user: SessionUser,
) -> AppResult<Response> {
    let entries = state.tokens.list_for_user(user.user_id);
    let summaries: Vec<TokenSummary> = entries.into_iter().map(TokenSummary::from).collect();
    Ok(Json(summaries).into_response())
}

/// Revoke one of the calling user's tokens by its id. Returns 404 if
/// the id doesn't exist OR belongs to someone else — we don't leak the
/// existence of other users' tokens via a 403/404 split.
pub async fn revoke_token(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    // Look up first so a caller can't revoke tokens that aren't theirs
    // (the store's `revoke` is owner-agnostic by design — it's used by
    // admin flows too).
    let owner_entries = state.tokens.list_for_user(user.user_id);
    let owned = owner_entries.iter().any(|e| e.id == id);
    if !owned {
        return Err(AppError::NotFound);
    }
    let removed = state.tokens.revoke(&id);
    debug_assert!(removed, "token existed per list but wasn't revoked");
    tracing::info!(
        user_id = user.user_id,
        username = %user.username,
        token_id = %id,
        "revoked API bearer token"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

// Compile-time sanity: ensure `SessionUserSnapshot` continues to be
// constructible from `SessionUser` (used in token create + tests).
// Cheap because the types are newtypes; if this stops compiling the
// storage shape has drifted and we want to know.
#[allow(dead_code)]
fn _session_user_snapshot_from_compiles(u: &SessionUser) -> SessionUserSnapshot {
    SessionUserSnapshot::from(u)
}
