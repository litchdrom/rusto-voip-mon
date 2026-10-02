//! `/admin/users` — admin-only CRUD over VoIPmonitor's `users` table.
//!
//! Routes:
//!   GET    /admin/users                    — list view
//!   GET    /admin/users/new                — empty create form
//!   POST   /admin/users/new                — submit create
//!   GET    /admin/users/:id/edit           — edit form
//!   POST   /admin/users/:id/edit           — submit edit
//!   POST   /admin/users/:id/reset-password — reset password only
//!   POST   /admin/users/:id/delete         — hard delete
//!
//! All routes require `is_admin = true` — non-admins get a 403 from
//! [`require_admin`]. The login form's `is_admin` bit is the only
//! admin gate in this app; we don't currently expose granular
//! "manage_users" permissions, so the global admin flag is the right
//! level.
//!
//! ## Self-protection rules
//!
//! A naive admin-CRUD lets you lock yourself out. The handlers
//! enforce:
//!
//!   * You can't demote yourself from admin (`is_admin` checkbox on
//!     your own edit form is disabled; route handler also blocks
//!     the change as a belt-and-braces guard).
//!   * You can't delete yourself.
//!   * You can't block yourself.
//!   * You can't expire your own password.
//!   * You can't delete the last remaining admin (counted via
//!     `users::count_admins`).
//!
//! The template renders the offending controls as `disabled` so the
//! problem is visible before submit; the route handler is the
//! authoritative check.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;

use crate::{
    auth::session::SessionUser,
    error::{AppError, AppResult},
    state::AppState,
    users::{self, User, UserEdit},
};

// --- Templates ---------------------------------------------------------------

/// List view: every user, alphabetically (case-insensitive).
/// `self_id` lets the template render a "(you)" badge on the
/// row that matches the calling session — purely UX.
#[derive(Template)]
#[template(path = "users_list.html")]
pub struct UsersListTemplate {
    pub user: Option<SessionUser>,
    pub users: Vec<User>,
    pub self_id: i32,
    pub error: Option<String>,
    pub info: Option<String>,
}

/// New / edit form. On edit, `is_self` controls which fields are
/// rendered as disabled (admin demotion, self-delete, self-block,
/// self-expire).
#[derive(Template)]
#[template(path = "users_form.html")]
pub struct UserFormTemplate {
    pub user: Option<SessionUser>,
    pub mode: FormMode,
    pub id: i32,
    pub username: String,
    pub is_admin: bool,
    pub can_cdr: bool,
    pub can_pcap: bool,
    pub blocked: bool,
    pub password_expired: bool,
    pub password_format_label: String,
    /// True when the form is rendering the calling user's own row.
    /// Disables the self-protection-locked controls so the operator
    /// can see the constraint before they submit.
    pub is_self: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    New,
    Edit,
}

impl FormMode {
    fn action_path(&self, id: &i32) -> String {
        match self {
            FormMode::New => "/admin/users/new".into(),
            FormMode::Edit => format!("/admin/users/{id}/edit"),
        }
    }
    fn title(&self) -> &'static str {
        match self {
            FormMode::New => "New user",
            FormMode::Edit => "Edit user",
        }
    }
    fn submit_label(&self) -> &'static str {
        match self {
            FormMode::New => "Create",
            FormMode::Edit => "Save",
        }
    }
}

// --- Form payload ------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UserFormBody {
    pub username: String,
    #[serde(default)]
    pub new_password: Option<String>,
    #[serde(default)]
    pub is_admin: Option<String>,
    #[serde(default)]
    pub can_cdr: Option<String>,
    #[serde(default)]
    pub can_pcap: Option<String>,
    #[serde(default)]
    pub blocked: Option<String>,
    #[serde(default)]
    pub password_expired: Option<String>,
}

impl UserFormBody {
    fn to_edit(&self) -> UserEdit {
        UserEdit {
            username: self.username.clone(),
            new_password: self.new_password.clone(),
            is_admin: self.is_admin.is_some(),
            can_cdr: self.can_cdr.is_some(),
            can_pcap: self.can_pcap.is_some(),
            blocked: self.blocked.is_some(),
            password_expired: self.password_expired.is_some(),
        }
    }
}

/// Password-reset form payload (separate from `UserFormBody` because
/// it lives at its own URL).
#[derive(Debug, Deserialize)]
pub struct ResetPasswordForm {
    pub new_password: String,
}

// --- Routes ------------------------------------------------------------------

/// `GET /admin/users` — list view.
pub async fn list(
    State(state): State<AppState>,
    user: SessionUser,
) -> AppResult<Response> {
    require_admin(&user)?;
    let users = users::list_all(&state.pool).await?;
    // SessionUser.user_id is u32 (matches the cookie / token
    // snapshot shape); User.id is i32 (matches the users table's
    // signed INT AUTO_INCREMENT). The cast wraps for hypothetical
    // ids > i32::MAX, but the table can't produce such values.
    let self_id = user.user_id as i32;
    let tmpl = UsersListTemplate {
        user: Some(user),
        users,
        self_id,
        error: None,
        info: None,
    };
    render(tmpl)
}

/// `GET /admin/users/new` — empty create form.
pub async fn new_form(
    State(state): State<AppState>,
    user: SessionUser,
) -> AppResult<Response> {
    require_admin(&user)?;
    let _ = state; // no DB calls needed for the empty form
    let tmpl = UserFormTemplate {
        user: Some(user),
        mode: FormMode::New,
        id: 0,
        username: String::new(),
        is_admin: false,
        can_cdr: false,
        can_pcap: false,
        blocked: false,
        password_expired: false,
        password_format_label: String::new(),
        is_self: false,
        error: None,
    };
    render(tmpl)
}

/// `POST /admin/users/new` — create.
pub async fn create(
    State(state): State<AppState>,
    user: SessionUser,
    Form(body): Form<UserFormBody>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let mut edit = body.to_edit();
    // New users MUST have a password — empty-string / None is
    // "use the literal hash for an existing user", not "create
    // a passwordless account" (we don't support those).
    let new_password_trimmed = edit.new_password.as_deref().unwrap_or("").trim();
    if new_password_trimmed.is_empty() {
        return Ok(render_form_with_error(
            &state,
            user,
            FormMode::New,
            0,
            &body,
            "password is required when creating a new user".into(),
        )
        .await?);
    }
    edit.new_password = Some(new_password_trimmed.to_string());
    let parsed = match users::parse_edit_form(&edit) {
        Ok(p) => p,
        Err(e) => {
            return Ok(render_form_with_error(
                &state,
                user,
                FormMode::New,
                0,
                &body,
                e.message(),
            )
            .await?);
        }
    };
    // Reject duplicate usernames before MySQL does — friendlier
    // error than a generic 23000 dup-key from the INSERT.
    if let Some(_existing) = users::get_by_username(&state.pool, &parsed.username).await? {
        return Ok(render_form_with_error(
            &state,
            user,
            FormMode::New,
            0,
            &body,
            format!("username {:?} already exists", parsed.username),
        )
        .await?);
    }
    let new_id = users::create(&state.pool, &parsed).await?;
    tracing::info!(
        actor = %user.username,
        new_user_id = new_id,
        new_username = %parsed.username,
        "created user"
    );
    Ok(Redirect::to("/admin/users").into_response())
}

/// `GET /admin/users/:id/edit` — render the edit form.
pub async fn edit_form(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id): Path<i32>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let target = users::get_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_self = (user.user_id as i32) == target.id;
    let tmpl = UserFormTemplate {
        user: Some(user),
        mode: FormMode::Edit,
        id: target.id,
        username: target.username.clone(),
        is_admin: target.is_admin,
        can_cdr: target.can_cdr,
        can_pcap: target.can_pcap,
        blocked: target.blocked,
        password_expired: target.password_expired,
        password_format_label: target.password_format_label.clone(),
        is_self,
        error: None,
    };
    render(tmpl)
}

/// `POST /admin/users/:id/edit` — apply changes. Enforces
/// self-protection rules.
pub async fn update(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id): Path<i32>,
    Form(body): Form<UserFormBody>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let target = users::get_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_self = (user.user_id as i32) == target.id;

    let edit = body.to_edit();
    let mut parsed = match users::parse_edit_form(&edit) {
        Ok(p) => p,
        Err(e) => {
            return Ok(render_form_with_error(
                &state,
                user,
                FormMode::Edit,
                id,
                &body,
                e.message(),
            )
            .await?);
        }
    };

    // Self-protection: ignore any attempt to demote / block /
    // expire your own password. We snap the parsed values back to
    // the existing ones rather than failing the request — a
    // half-disabled form shouldn't bounce the operator back to the
    // top with a cryptic error.
    if is_self {
        if !parsed.is_admin && target.is_admin {
            parsed.is_admin = true;
        }
        if parsed.blocked && !target.blocked {
            parsed.blocked = false;
        }
        if parsed.password_expired && !target.password_expired {
            parsed.password_expired = false;
        }
    }

    // Username uniqueness — if the operator renamed the user, make
    // sure the new name isn't already taken.
    if parsed.username != target.username {
        if let Some(_existing) = users::get_by_username(&state.pool, &parsed.username).await? {
            return Ok(render_form_with_error(
                &state,
                user,
                FormMode::Edit,
                id,
                &body,
                format!("username {:?} already exists", parsed.username),
            )
            .await?);
        }
    }

    let affected = users::update(&state.pool, id, &parsed).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    tracing::info!(
        actor = %user.username,
        target_id = id,
        password_reset = parsed.new_password.is_some(),
        "updated user"
    );
    Ok(Redirect::to("/admin/users").into_response())
}

/// `POST /admin/users/:id/reset-password` — reset only the password,
/// without touching any other field. Used by the per-row "Reset
/// password" button on the list view.
pub async fn reset_password(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id): Path<i32>,
    Form(form): Form<ResetPasswordForm>,
) -> AppResult<Response> {
    require_admin(&user)?;
    // Build a UserEdit so we get the same length / complexity rules
    // as the full edit form — even though we only use the password.
    let edit = UserEdit {
        username: String::new(),
        new_password: Some(form.new_password.clone()),
        is_admin: false,
        can_cdr: false,
        can_pcap: false,
        blocked: false,
        password_expired: false,
    };
    let parsed = users::parse_edit_form(&edit).map_err(|e| AppError::BadRequest(e.message()))?;
    let new_password = parsed
        .new_password
        .as_deref()
        .ok_or_else(|| AppError::Internal("reset-password validation dropped the password".into()))?;
    let affected = users::reset_password(&state.pool, id, new_password).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    tracing::info!(
        actor = %user.username,
        target_id = id,
        "reset user password"
    );
    Ok(Redirect::to("/admin/users").into_response())
}

/// `POST /admin/users/:id/delete` — hard delete. Refuses to delete
/// self or the last admin.
pub async fn delete(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id): Path<i32>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let target = users::get_by_id(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let is_self = (user.user_id as i32) == target.id;
    if is_self {
        return Err(AppError::BadRequest(
            "you can't delete your own account — ask another admin".into(),
        ));
    }
    if target.is_admin {
        let admin_count = users::count_admins(&state.pool).await?;
        if admin_count <= 1 {
            return Err(AppError::BadRequest(
                "can't delete the last remaining admin — promote someone else first".into(),
            ));
        }
    }
    let affected = users::delete(&state.pool, id).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    tracing::warn!(
        actor = %user.username,
        target_id = id,
        target_username = %target.username,
        "deleted user"
    );
    Ok(Redirect::to("/admin/users").into_response())
}

// --- Helpers -----------------------------------------------------------------

/// `AppError::Forbidden` unless the caller is an admin. Cheap —
/// the session cookie already carries the `is_admin` bit, set on
/// login. Mirrors `routes::sensors::require_admin`; kept private to
/// each module so a future sensor→user split doesn't accidentally
/// widen the admin gate.
fn require_admin(user: &SessionUser) -> AppResult<()> {
    if user.is_admin {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Render an askama template with the standard content-type header.
/// Render errors surface as a 500 with a log line so a malformed
/// template doesn't silently 200 with empty body.
fn render<T: Template>(tmpl: T) -> AppResult<Response> {
    let body = tmpl.render().map_err(|e| {
        tracing::error!(error = ?e, "askama render failed");
        AppError::Internal(format!("template render: {e}"))
    })?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))],
        body,
    )
        .into_response())
}

/// Re-render the new/edit form with the operator's input echoed
/// back + an inline error. Same template as the GET forms, so the
/// submit button + password-format hint stay in sync.
async fn render_form_with_error(
    _state: &AppState,
    user: SessionUser,
    mode: FormMode,
    id: i32,
    body: &UserFormBody,
    error: String,
) -> AppResult<Response> {
    let is_self = mode == FormMode::Edit && (user.user_id as i32) == id;
    let tmpl = UserFormTemplate {
        user: Some(user),
        mode,
        id,
        username: body.username.clone(),
        is_admin: body.is_admin.is_some(),
        can_cdr: body.can_cdr.is_some(),
        can_pcap: body.can_pcap.is_some(),
        blocked: body.blocked.is_some(),
        password_expired: body.password_expired.is_some(),
        password_format_label: String::new(),
        is_self,
        error: Some(error),
    };
    render(tmpl)
}

// Compile-time guard: keep the form-path URL builder + the askama
// derive honest. If `action_path` or `FormMode` ever drops a case,
// the title() chain becomes exhaustive-aware at the call site.
#[allow(dead_code)]
fn _assert_form_mode_paths_compile() {
    let _ = FormMode::New.action_path(&0);
    let _ = FormMode::Edit.action_path(&7);
}
