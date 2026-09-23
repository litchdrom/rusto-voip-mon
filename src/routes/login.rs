use askama::Template;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use sqlx::FromRow;

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

#[derive(Debug, FromRow)]
struct UserRow {
    id: i32,
    username: String,
    password: String,
    is_admin: i8,
    can_cdr: Option<i8>,
    can_pcap: Option<i8>,
    blocked: Option<i8>,
    password_expired: Option<i8>,
}

pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> AppResult<Response> {
    let row: Option<UserRow> = sqlx::query_as(
        "SELECT id, username, password, is_admin, can_cdr, can_pcap, \
                blocked, password_expired \
           FROM users WHERE username = ? LIMIT 1",
    )
    .bind(&form.username)
    .fetch_optional(&state.pool)
    .await?;

    let Some(user) = row else {
        return Ok(render_login_error(
            "Invalid username or password",
            form.next,
            StatusCode::UNAUTHORIZED,
        ));
    };

    if user.blocked.unwrap_or(0) != 0 {
        return Ok(render_login_error("Account blocked", form.next, StatusCode::FORBIDDEN));
    }
    if user.password_expired.unwrap_or(0) != 0 {
        return Ok(render_login_error(
            "Password expired \u{2014} change it via the VoIPmonitor GUI",
            form.next,
            StatusCode::FORBIDDEN,
        ));
    }
    if !password::verify(&user.password, &form.password) {
        return Ok(render_login_error(
            "Invalid username or password",
            form.next,
            StatusCode::UNAUTHORIZED,
        ));
    }

    if password::detect(&user.password) == Some(password::HashFormat::Md5) {
        tracing::warn!(
            user_id = user.id,
            "user is using legacy unsalted-MD5 password hash; consider rotating"
        );
    }

    let session = SessionUser::new(
        user.id as u32,
        user.username,
        user.is_admin != 0,
        user.can_cdr.unwrap_or(1) != 0,
        user.can_pcap.unwrap_or(1) != 0,
    );

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
