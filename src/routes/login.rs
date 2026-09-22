use askama::Template;
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use sqlx::FromRow;

use crate::{
    auth::{
        password,
        session::{encode_cookie, SessionUser, COOKIE_NAME},
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
) -> Response {
    // If a session cookie is present, send the user to the home page; the
    // home page will bounce them to /login if the session is invalid.
    if parse_session_cookie(&headers).is_some() {
        return Redirect::to("/").into_response();
    }
    let _ = state.config.cookie_secret_if_present();
    let tmpl = LoginTemplate {
        error: None,
        next: None,
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

#[derive(Debug, FromRow)]
struct UserRow {
    id: u32,
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
        user.id,
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

    let next = form.next.unwrap_or_else(|| "/".to_string());
    let mut resp = Redirect::to(&next).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie_header)
            .map_err(|e| crate::error::AppError::Internal(format!("cookie header: {e}")))?,
    );
    Ok(resp)
}

pub async fn logout() -> Response {
    let cookie_header = format_set_cookie(COOKIE_NAME, "", "/", Some(0));
    let mut resp = Redirect::to("/login").into_response();
    if let Ok(v) = HeaderValue::from_str(&cookie_header) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
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
