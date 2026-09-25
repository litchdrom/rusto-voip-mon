use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum::Form;
use serde::Deserialize;

use crate::{
    auth::{
        password,
        session::{encode_cookie, SessionUser, COOKIE_NAME, TTL_SECS},
    },
    error::AppResult,
    state::AppState,
};

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
    pub next: Option<String>,
    pub user: Option<SessionUser>,
}

pub async fn login_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Response {
    // If a session cookie is present, send the user to the home page; the
    // home page will bounce them to /login if the session is invalid.
    if parse_session_cookie(&headers).is_some() {
        return Redirect::to(q.next.as_deref().unwrap_or("/")).into_response();
    }
    let _ = state.config.cookie_secret_if_present();
    let tmpl = LoginTemplate {
        error: None,
        next: q.next,
        user: None,
    };
    let body = tmpl.render().unwrap_or_else(|e| {
        tracing::error!(error = ?e, "login template render failed");
        "login render error".into()
    });
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub next: Option<String>,
}

pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> AppResult<Response> {
    // Single source of truth for "is this (username, password) valid?".
    // The token endpoint (`POST /auth/tokens`) uses the same helper so
    // a future change to password rules / blocking applies to both
    // paths at once. Returns Ok(None) for any failure — bad username,
    // wrong password, blocked, expired — so the caller can show one
    // "invalid credentials" message and not leak which check failed.
    let verified = match password::verify_login(
        &state.pool,
        &form.username,
        &form.password,
    )
    .await?
    {
        Some(v) => v,
        None => {
            return Ok(render_login_error(
                "Invalid username or password",
                form.next,
                StatusCode::UNAUTHORIZED,
            ));
        }
    };

    if verified.hash_was_legacy_md5 {
        tracing::warn!(
            user_id = verified.user.user_id,
            "user is using legacy unsalted-MD5 password hash; consider rotating"
        );
    }

    let session = verified.user;
    let value = encode_cookie(&session, state.config.cookie_secret.as_bytes());
    let cookie_header = format_set_cookie(
        COOKIE_NAME,
        &value,
        "/",
        Some(crate::auth::session::TTL_SECS),
    );

    let next = sanitize_next(form.next.as_deref());
    let mut resp = Redirect::to(&next).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie_header)
            .map_err(|e| crate::error::AppError::Internal(format!("cookie header: {e}")))?,
    );
    Ok(resp)
}

/// `next` is taken straight from a query/form field, so we must defend
/// against open-redirect attacks. Only relative paths starting with `/`
/// (and not `//`) are allowed; anything else falls back to `/`.
fn sanitize_next(next: Option<&str>) -> String {
    match next {
        Some(s) if s.starts_with('/') && !s.starts_with("//") => s.to_string(),
        _ => "/".to_string(),
    }
}

pub async fn logout() -> Response {
    let cookie_header = format_set_cookie(COOKIE_NAME, "", "/", Some(0));
    let mut resp = Redirect::to("/login").into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie_header) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// Update the session-stored timezone and redirect back. Accepts form
/// fields:
///   `tz_offset_hours`  — required, integer in [-12, 14]. Empty / 0
///                        clears the override and falls back to the
///                        server's `APP_TZ_OFFSET_HOURS`.
///   `next`             — relative URL to bounce back to.
pub async fn set_tz(
    State(state): State<crate::state::AppState>,
    user: SessionUser,
    Form(form): Form<SetTzForm>,
) -> AppResult<Response> {
    // Parse + range-check, then collapse "0 means clear" so we return
    // Option<i8> instead of Option<Option<i8>>: 0 = clear (None), any
    // other valid hour = Some(h).
    let parsed: Option<i8> = form
        .tz_offset_hours
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<i8>().ok())
        .filter(|&h| (-12..=14).contains(&h))
        .and_then(|h| if h == 0 { None } else { Some(h) });

    let new_session = user.with_tz(parsed);
    let value = encode_cookie(&new_session, state.config.cookie_secret.as_bytes());
    let cookie_header = format_set_cookie(COOKIE_NAME, &value, "/", Some(TTL_SECS));

    let next = sanitize_next(form.next.as_deref());
    let mut resp = Redirect::to(&next).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie_header)
            .map_err(|e| crate::error::AppError::Internal(format!("cookie header: {e}")))?,
    );
    Ok(resp)
}

#[derive(Debug, Deserialize)]
pub struct SetTzForm {
    pub tz_offset_hours: Option<String>,
    pub next: Option<String>,
}

/// Request body for `POST /cdr/select`. The JS on the CDR list page
/// sends the full current selection (every checked row, across all
/// pages the operator has visited) on each toggle; the server stores it
/// verbatim, capped at `SESSION_SELECTION_CAP`.
#[derive(Debug, Deserialize)]
pub struct SelectCdrsRequest {
    #[serde(default)]
    pub ids: Vec<u64>,
}

/// Update the operator's batch-download selection. Returns 204 with a
/// refreshed session cookie. The JS calls this on every checkbox toggle
/// (debounced) so the selection survives page navigation.
pub async fn select_cdrs(
    State(state): State<crate::state::AppState>,
    user: SessionUser,
    Json(req): Json<SelectCdrsRequest>,
) -> AppResult<Response> {
    let new_session = user.with_selection(req.ids);
    let value = encode_cookie(&new_session, state.config.cookie_secret.as_bytes());
    let cookie_header = format_set_cookie(COOKIE_NAME, &value, "/", Some(TTL_SECS));
    let mut resp = (StatusCode::NO_CONTENT, "").into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie_header) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    Ok(resp)
}

/// Build a Set-Cookie header value with HttpOnly + SameSite=Lax.
/// `max_age_secs = Some(0)` clears the cookie.
fn format_set_cookie(name: &str, value: &str, path: &str, max_age_secs: Option<i64>) -> String {
    let mut s = format!("{name}={value}; Path={path}; HttpOnly; SameSite=Lax");
    if let Some(age) = max_age_secs {
        s.push_str(&format!("; Max-Age={age}"));
    }
    s
}

fn render_login_error(msg: &str, next: Option<String>, status: StatusCode) -> Response {
    let tmpl = LoginTemplate {
        error: Some(msg.into()),
        next,
        user: None,
    };
    let body = tmpl.render().unwrap_or_else(|e| {
        tracing::error!(error = ?e, "login template render failed");
        "login render error".into()
    });
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response()
}

fn parse_session_cookie(headers: &HeaderMap) -> Option<cookie::Cookie<'static>> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Ok(c) = cookie::Cookie::parse(part.to_owned()) {
            if c.name() == COOKIE_NAME {
                return Some(c);
            }
        }
    }
    None
}
