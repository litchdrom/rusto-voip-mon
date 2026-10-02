//! `/admin/sensors` — admin-only CRUD over the VoIPmonitor `sensors`
//! table.
//!
//! Routes:
//!   GET    /admin/sensors                    — list view
//!   GET    /admin/sensors/new                — empty create form
//!   POST   /admin/sensors/new                — submit create
//!   GET    /admin/sensors/:id_sensor/edit    — edit form (full row)
//!   POST   /admin/sensors/:id_sensor/edit    — submit edit
//!   POST   /admin/sensors/:id_sensor/delete  — delete (with confirm)
//!
//! All routes require `is_admin = true` — non-admins get a 403 from
//! [`require_admin`]. The login form's "is_admin" bit is the only
//! admin gate in this app: we don't currently expose granular
//! "manage_sensors" / "manage_users" permissions, so the global
//! admin flag is the right level.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use sqlx::Row;

use crate::{
    auth::session::SessionUser,
    error::{AppError, AppResult},
    sensors::{self, Sensor, SensorEdit},
    state::AppState,
};

// --- Templates ---------------------------------------------------------------

/// List view: every sensor, ordered by id_sensor, with a count of
/// how many CDR rows each sensor has produced (so the operator can
/// see at a glance which sensors are actually live).
#[derive(Template)]
#[template(path = "sensors_list.html")]
pub struct SensorsListTemplate {
    pub user: Option<SessionUser>,
    pub sensors: Vec<SensorListRow>,
    pub error: Option<String>,
    pub info: Option<String>,
}

/// One row in the list view — `Sensor` plus a per-sensor CDR count
/// from a sidecar query. Keeping the count off the `Sensor` struct
/// means the model layer doesn't need to know about the CDR table.
#[derive(Debug, Clone)]
pub struct SensorListRow {
    pub sensor: Sensor,
    pub cdr_count: i64,
}

/// Edit form: full sensor row (with extras for the "advanced"
/// section) + a list of distinct `id_sensor` integers seen in
/// recent CDRs but missing from the sensors table. The latter is
/// shown as a hint to make the "new" form less typing.
#[derive(Template)]
#[template(path = "sensors_form.html")]
pub struct SensorFormTemplate {
    pub user: Option<SessionUser>,
    pub mode: FormMode,
    pub id_sensor: u16,
    pub name: String,
    pub host: String,
    pub port: String,
    pub disable: bool,
    pub local_spool: String,
    /// Full row's `extras` map — only populated on edit, empty on
    /// new. Rendered as the "Advanced" key/value table.
    pub extras: Vec<(String, String)>,
    pub error: Option<String>,
    /// id_sensor values seen in cdr but missing from sensors. Sourced
    /// from a sidecar query at render time.
    pub missing_id_sensors: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    New,
    Edit,
}

impl FormMode {
    fn action_path(&self, id_sensor: &u16) -> String {
        match self {
            FormMode::New => "/admin/sensors/new".into(),
            FormMode::Edit => format!("/admin/sensors/{id_sensor}/edit"),
        }
    }
    fn title(&self) -> &'static str {
        match self {
            FormMode::New => "New sensor",
            FormMode::Edit => "Edit sensor",
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

/// Body of the new/edit POST. `id_sensor` is only meaningful on
/// `new` — on edit it's read from the URL path. We keep it in the
/// form too because the new form renders it next to the input, and
/// reposts it back to the same handler for a one-shot echo.
#[derive(Debug, Deserialize)]
pub struct SensorFormBody {
    #[serde(default)]
    pub id_sensor: Option<String>,
    pub name: String,
    pub host: String,
    pub port: String,
    #[serde(default)]
    pub disable: Option<String>,
    #[serde(default)]
    pub local_spool: String,
}

impl SensorFormBody {
    fn to_edit(&self) -> SensorEdit {
        SensorEdit {
            name: Some(self.name.clone()),
            host: Some(self.host.clone()),
            port_text: Some(self.port.clone()),
            disable: self.disable.is_some(),
            local_spool: Some(self.local_spool.clone()),
        }
    }
}

// --- Routes ------------------------------------------------------------------

/// `GET /admin/sensors` — list view. Backfills missing sensors from
/// the CDR table before rendering so the operator sees every
/// `id_sensor` that's actually producing traffic, even if no row was
/// ever created for it. Backfill is idempotent and fast (one INSERT
/// IGNORE), so doing it on every render is fine.
pub async fn list(
    State(state): State<AppState>,
    user: SessionUser,
) -> AppResult<Response> {
    require_admin(&user)?;
    let backfilled = sensors::backfill_from_cdr(&state.pool).await?;
    if backfilled > 0 {
        tracing::info!(count = backfilled, "backfilled missing sensors from cdr");
    }
    let sensors = sensors::list_all(&state.pool).await?;
    let cdr_counts = count_cdrs_by_sensor(&state.pool).await?;
    let rows: Vec<SensorListRow> = sensors
        .into_iter()
        .map(|s| {
            let cdr_count = *cdr_counts.get(&(s.id_sensor as i32)).unwrap_or(&0);
            SensorListRow { sensor: s, cdr_count }
        })
        .collect();
    let tmpl = SensorsListTemplate {
        user: Some(user),
        sensors: rows,
        error: None,
        info: None,
    };
    render(tmpl)
}

/// `GET /admin/sensors/new` — render an empty form.
pub async fn new_form(
    State(state): State<AppState>,
    user: SessionUser,
) -> AppResult<Response> {
    require_admin(&user)?;
    let missing = missing_id_sensors(&state.pool).await?;
    let tmpl = SensorFormTemplate {
        user: Some(user),
        mode: FormMode::New,
        id_sensor: 0,
        name: String::new(),
        host: String::new(),
        port: String::new(),
        disable: false,
        local_spool: String::new(),
        extras: Vec::new(),
        error: None,
        missing_id_sensors: missing,
    };
    render(tmpl)
}

/// `POST /admin/sensors/new` — create. Re-renders the form on
/// validation failure so the operator can correct in place.
pub async fn create(
    State(state): State<AppState>,
    user: SessionUser,
    Form(body): Form<SensorFormBody>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let id_sensor = match parse_id_sensor(body.id_sensor.as_deref()) {
        Ok(n) => n,
        Err(msg) => {
            return Ok(render_form_with_error(
                &state,
                user,
                FormMode::New,
                0,
                &body,
                msg,
            )
            .await?);
        }
    };
    let edit = body.to_edit();
    let parsed = match sensors::parse_edit_form(&edit) {
        Ok(p) => p,
        Err(e) => {
            return Ok(render_form_with_error(
                &state,
                user,
                FormMode::New,
                id_sensor,
                &body,
                e.message(),
            )
            .await?);
        }
    };
    if let Err(e) = sensors::create(&state.pool, id_sensor, &parsed).await {
        let msg = match &e {
            AppError::Sqlx(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23000") => {
                format!("id_sensor {id_sensor} already exists")
            }
            other => format!("database error: {other}"),
        };
        return Ok(render_form_with_error(&state, user, FormMode::New, id_sensor, &body, msg).await?);
    }
    tracing::info!(
        actor = %user.username,
        id_sensor,
        "created sensor"
    );
    Ok(Redirect::to("/admin/sensors").into_response())
}

/// `GET /admin/sensors/:id_sensor/edit` — render the edit form with
/// every column pre-filled. Returns 404 if the sensor doesn't exist.
pub async fn edit_form(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id_sensor): Path<u16>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let sensor = sensors::get_by_id_sensor(&state.pool, id_sensor)
        .await?
        .ok_or(AppError::NotFound)?;
    let missing = missing_id_sensors(&state.pool).await?;
    let tmpl = SensorFormTemplate {
        user: Some(user),
        mode: FormMode::Edit,
        id_sensor: sensor.id_sensor,
        name: sensor.name.clone().unwrap_or_default(),
        host: sensor.host.clone().unwrap_or_default(),
        port: sensor.port.map(|p| p.to_string()).unwrap_or_default(),
        disable: sensor.disable,
        local_spool: sensor.local_spool.clone().unwrap_or_default(),
        extras: sensor.extras.into_iter().collect(),
        error: None,
        missing_id_sensors: missing,
    };
    render(tmpl)
}

/// `POST /admin/sensors/:id_sensor/edit` — apply changes.
pub async fn update(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id_sensor): Path<u16>,
    Form(body): Form<SensorFormBody>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let edit = body.to_edit();
    let parsed = match sensors::parse_edit_form(&edit) {
        Ok(p) => p,
        Err(e) => {
            return Ok(render_form_with_error(
                &state,
                user,
                FormMode::Edit,
                id_sensor,
                &body,
                e.message(),
            )
            .await?);
        }
    };
    let affected = sensors::update(&state.pool, id_sensor, &parsed).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    tracing::info!(
        actor = %user.username,
        id_sensor,
        "updated sensor"
    );
    Ok(Redirect::to("/admin/sensors").into_response())
}

/// `POST /admin/sensors/:id_sensor/delete` — hard delete. Returns
/// 404 if no row matched (e.g. someone deleted it in another tab).
pub async fn delete(
    State(state): State<AppState>,
    user: SessionUser,
    Path(id_sensor): Path<u16>,
) -> AppResult<Response> {
    require_admin(&user)?;
    let affected = sensors::delete(&state.pool, id_sensor).await?;
    if affected == 0 {
        return Err(AppError::NotFound);
    }
    tracing::warn!(
        actor = %user.username,
        id_sensor,
        "deleted sensor"
    );
    Ok(Redirect::to("/admin/sensors").into_response())
}

// --- Helpers -----------------------------------------------------------------

/// Return `AppError::Forbidden` unless the caller is an admin. Cheap
/// — we don't do a DB lookup here because the session cookie already
/// carries the `is_admin` bit, set on login.
fn require_admin(user: &SessionUser) -> AppResult<()> {
    if user.is_admin {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Render an askama template with the standard content-type header.
/// Surfaces render errors as a 500 with a log line so a malformed
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

/// Sidecar query: how many CDR rows has each sensor produced?
/// Returned as `id_sensor → count` so the list view can do an
/// in-memory lookup per row. Limited to the last 7 days of traffic
/// so a sensor that's been silent for a month doesn't dominate.
async fn count_cdrs_by_sensor(pool: &sqlx::MySqlPool) -> AppResult<std::collections::HashMap<i32, i64>> {
    let rows = sqlx::query(
        "SELECT id_sensor, COUNT(*) AS n FROM cdr \
          WHERE calldate >= (NOW() - INTERVAL 7 DAY) \
            AND id_sensor IS NOT NULL \
          GROUP BY id_sensor",
    )
    .fetch_all(pool)
    .await?;
    let mut out = std::collections::HashMap::with_capacity(rows.len());
    for r in rows {
        let id: i32 = r.try_get("id_sensor")?;
        let n: i64 = r.try_get("n")?;
        out.insert(id, n);
    }
    Ok(out)
}

/// Distinct `id_sensor` values seen in the CDR table over the last
/// 7 days that aren't yet in the `sensors` table. Surfaced on the
/// new-sensor form as clickable hints.
async fn missing_id_sensors(pool: &sqlx::MySqlPool) -> AppResult<Vec<u16>> {
    let rows = sqlx::query(
        "SELECT DISTINCT cdr.id_sensor FROM cdr \
            LEFT JOIN sensors ON sensors.id_sensor = cdr.id_sensor \
          WHERE cdr.calldate >= (NOW() - INTERVAL 7 DAY) \
            AND cdr.id_sensor IS NOT NULL \
            AND sensors.id_sensor IS NULL \
          ORDER BY cdr.id_sensor ASC LIMIT 50",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id: u16 = r.try_get("id_sensor")?;
        out.push(id);
    }
    Ok(out)
}

/// Parse the `id_sensor` field from the new-sensor form. Accepts a
/// leading/trailing whitespace tolerance for hand-typed inputs.
fn parse_id_sensor(raw: Option<&str>) -> Result<u16, String> {
    let s = raw.unwrap_or("").trim();
    if s.is_empty() {
        return Err("id_sensor is required".into());
    }
    s.parse::<u16>()
        .map_err(|e| format!("id_sensor: {e}"))
}

/// Re-render the form (new or edit) with the operator's input echoed
/// back plus an inline error. Same template as the GET forms, so the
/// submit button + advanced section + missing-sensor hints all stay
/// in sync.
async fn render_form_with_error(
    state: &AppState,
    user: SessionUser,
    mode: FormMode,
    id_sensor: u16,
    body: &SensorFormBody,
    error: String,
) -> AppResult<Response> {
    let missing = missing_id_sensors(&state.pool).await?;
    let extras = if mode == FormMode::Edit {
        sensors::get_by_id_sensor(&state.pool, id_sensor)
            .await?
            .map(|s| s.extras.into_iter().collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let tmpl = SensorFormTemplate {
        user: Some(user),
        mode,
        id_sensor,
        name: body.name.clone(),
        host: body.host.clone(),
        port: body.port.clone(),
        disable: body.disable.is_some(),
        local_spool: body.local_spool.clone(),
        extras,
        error: Some(error),
        missing_id_sensors: missing,
    };
    render(tmpl)
}

// Compile-time guards: keep the form-path URL builder + the askama
// derive honest. If `action_path` or `FormMode` ever drops a case
// the title() chain becomes exhaustive-aware at the call site.
#[allow(dead_code)]
fn _assert_form_mode_paths_compile() {
    let _ = FormMode::New.action_path(&0);
    let _ = FormMode::Edit.action_path(&7);
}
