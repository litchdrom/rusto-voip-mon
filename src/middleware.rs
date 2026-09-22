//! HTTP middleware.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use crate::auth::session::COOKIE_NAME;

/// Redirect to `/login` if the request has no session cookie. If a cookie
/// is present, the actual signature verification is still done by the
/// `SessionUser` extractor inside the handler — this middleware is just a
/// UX shortcut so anonymous users land on the login page instead of seeing
/// a 401.
pub async fn require_login(
    axum_extra::TypedHeader(cookies): axum_extra::TypedHeader<
        axum_extra::headers::Cookie,
    >,
    req: Request<Body>,
    next: Next,
) -> Response {
    if cookies.get(COOKIE_NAME).is_some() {
        next.run(req).await
    } else {
        // Preserve the originally-requested URL so we can bounce back after login.
        let target = req
            .uri()
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_else(|| "/".to_string());
        let next_param = if target == "/" {
            String::new()
        } else {
            format!("?next={}", urlencode(&target))
        };
        Redirect::to(&format!("/login{next_param}")).into_response()
    }
}

/// Best-effort URL encoding for the `next` query param. We keep it simple —
/// percent-encode anything outside the unreserved set.
fn urlencode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

// Used to silence unused-imports warnings when the module is built
// conditionally on a feature flag later.
#[allow(dead_code)]
const STATUS_OK: StatusCode = StatusCode::OK;
