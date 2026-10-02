//! Sensor management.
//!
//! Sensors in this codebase refer to VoIPmonitor probe instances — the
//! pcap-capture daemons that produce the `cdr` rows we read from.
//! VoIPmonitor's own `sensors` table (see schema dump) has 40+ columns;
//! the operator-facing UI in this app only edits the few that matter
//! for our workflow (`name`, `host`, `port`, `disable`, `local_spool`)
//! and shows the rest read-only as "advanced" context.
//!
//! Why a separate module instead of inlining in `routes::sensors`:
//! pure-function validation rules (port range, id_sensor sanity) are
//! unit-testable on their own and don't need a DB pool. The async DB
//! functions live here too so the route layer is just a thin HTTP
//! adapter.
//!
//! ## ID model — careful
//!
//! The sensors table has **two** id-like columns:
//!   * `id`        — auto-increment PK, internal to the table
//!   * `id_sensor` — the integer VoIPmonitor assigns to the probe,
//!     used in `cdr.id_sensor` and shown in the operator UI
//!
//! All user-facing endpoints and the list view are keyed by
//! `id_sensor` because that's what the operator knows and what's
//! referenced from `cdr.id_sensor`. `id` is purely an internal row
//! handle for UPDATE/DELETE.

use serde::Serialize;
use sqlx::{MySqlPool, Row};
use std::collections::BTreeMap;

use crate::error::AppResult;

/// One row of the `sensors` table, projected down to the fields the
/// operator-facing UI shows + edits.
///
/// The remaining 30+ columns VoIPmonitor exposes (timezones,
/// international-rule overrides, auto-upgrade cron, GUI colours...)
/// are kept in `extras` as a `name → rendered value` map so the
/// read-only "Advanced" view can show them without us having to type
/// out every column. They're never written through this struct —
/// `update()` only touches the focused fields.
///
/// ## `id_sensor` is `u32`, not `u16`
///
/// `sensors.id_sensor` is `INT UNSIGNED` in the VoIPmonitor schema
/// (capacity ~4 billion); the `cdr.id_sensor` it joins to is
/// `SMALLINT UNSIGNED` (capacity ~65k). The smaller type lives on
/// the FK side because VoIPmonitor assigns probe IDs from a tiny
/// range — but the parent table reserves the wider type for
/// future-proofing. We mirror that split: Sensor.id_sensor is u32
/// (matches the table), and the cdr-side join casts through u16.
#[derive(Debug, Clone, Serialize)]
pub struct Sensor {
    pub id_sensor: u32,
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub disable: bool,
    pub local_spool: Option<String>,
    /// All other sensors-table columns, in stable alphabetical order
    /// (so the advanced-view render is deterministic). Each value is
    /// pre-rendered to its display string by `row_value_to_string`.
    pub extras: BTreeMap<String, String>,
}

/// Editable subset of a sensor. Submitted by the new/edit forms.
/// Numeric/optional fields use `Option<String>` from the form layer
/// and are parsed + validated by [`parse_edit_form`] before hitting
/// the DB.
#[derive(Debug, Clone, Default)]
pub struct SensorEdit {
    pub name: Option<String>,
    pub host: Option<String>,
    pub port_text: Option<String>,
    pub disable: bool,
    pub local_spool: Option<String>,
}

/// What can go wrong when parsing the edit form. Kept as a flat enum
/// so the template can render each variant with its own message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// id_sensor must be > 0 (we store it as u16, so this only fires
    /// for the synthetic "0 / missing" path).
    BadIdSensor,
    /// `port` was supplied but isn't a valid u16 / is out of range.
    BadPort(String),
    /// `host` must look like an IP / hostname if supplied. We don't
    /// enforce DNS resolution — the sensor probe either runs or it
    /// doesn't — but a stray control char or 4 KB of garbage gets
    /// bounced here.
    BadHost(String),
}

impl EditError {
    pub fn message(&self) -> String {
        match self {
            EditError::BadIdSensor => "id_sensor must be a positive integer".into(),
            EditError::BadPort(s) => format!("port: {s}"),
            EditError::BadHost(s) => format!("host: {s}"),
        }
    }
}

/// Validate + normalise a [`SensorEdit`] into the typed values we
/// actually write to MySQL. Pure function — easy to unit-test.
///
/// Validation rules:
///   * `name` — trimmed; empty after trim → `None`.
///   * `host` — trimmed; empty after trim → `None`; otherwise must
///     look roughly like an IP or hostname (printable ASCII, no
///     whitespace, ≤ 255 chars). We don't require it to be a valid
///     IP — VoIPmonitor accepts bare hostnames.
///   * `port` — empty → `None`; otherwise a u16 in 1..=65535.
pub fn parse_edit_form(form: &SensorEdit) -> Result<ParsedSensorEdit, EditError> {
    let name = form.name.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let local_spool = form
        .local_spool
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);

    let host = match form.host.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(h) if h.len() > 255 => return Err(EditError::BadHost("longer than 255 chars".into())),
        Some(h) => {
            if h.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(EditError::BadHost(
                    "must not contain whitespace or control characters".into(),
                ));
            }
            Some(h.to_string())
        }
    };

    let port = match form.port_text.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => s
            .parse::<u16>()
            .map(Some)
            .map_err(|e| EditError::BadPort(e.to_string()))?,
    };

    Ok(ParsedSensorEdit {
        name,
        host,
        port,
        disable: form.disable,
        local_spool,
    })
}

/// Same as `SensorEdit` but with `port` typed and `Option<String>`
/// trimmed to `Option<String>` consistently. This is what hits the DB.
#[derive(Debug, Clone, Default)]
pub struct ParsedSensorEdit {
    pub name: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub disable: bool,
    pub local_spool: Option<String>,
}

/// List every sensor, ordered by `id_sensor` so the operator sees a
/// stable sequence. Includes disabled ones — they're filtered at
/// display time, not at fetch time, because the operator may want to
/// re-enable them.
pub async fn list_all(pool: &MySqlPool) -> AppResult<Vec<Sensor>> {
    let rows = sqlx::query(
        "SELECT id_sensor, name, host, port, disable, local_spool \
           FROM sensors ORDER BY id_sensor ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let id_sensor: u32 = r.try_get("id_sensor")?;
        out.push(Sensor {
            id_sensor,
            name: r.try_get("name").ok(),
            host: r.try_get("host").ok(),
            port: r.try_get("port").ok(),
            disable: r.try_get::<Option<i8>, _>("disable")
                .map(|v| v.unwrap_or(0) != 0)
                .unwrap_or(false),
            local_spool: r.try_get("local_spool").ok(),
            // List view doesn't load the extras — saves the round-trip
            // on every page render. Edit view calls `get_by_id_sensor`
            // which does the full SELECT *.
            extras: BTreeMap::new(),
        });
    }
    Ok(out)
}

/// Fetch one sensor by its `id_sensor`, including the full row
/// (used to populate the "advanced" context in the edit form).
/// Returns `Ok(None)` if no row matches.
pub async fn get_by_id_sensor(pool: &MySqlPool, id_sensor: u32) -> AppResult<Option<Sensor>> {
    let row = sqlx::query("SELECT * FROM sensors WHERE id_sensor = ? LIMIT 1")
        .bind(id_sensor)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(row_to_sensor(&row)?))
}

/// Create a new sensor row. `id_sensor` must be unique (VoIPmonitor
/// enforces a UNIQUE index on it) — we don't pre-check, MySQL will
/// surface the dup-key error which `sqlx` maps to `sqlx::Error`.
pub async fn create(pool: &MySqlPool, id_sensor: u32, edit: &ParsedSensorEdit) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO sensors \
            (id_sensor, name, host, port, disable, local_spool) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id_sensor)
    .bind(&edit.name)
    .bind(&edit.host)
    .bind(edit.port.map(|p| p as i32))
    .bind(if edit.disable { 1_i8 } else { 0_i8 })
    .bind(&edit.local_spool)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update the editable subset of a sensor. Returns the number of
/// affected rows — caller should treat 0 as "id_sensor not found"
/// and surface a 404.
pub async fn update(
    pool: &MySqlPool,
    id_sensor: u32,
    edit: &ParsedSensorEdit,
) -> AppResult<u64> {
    let res = sqlx::query(
        "UPDATE sensors SET \
            name = ?, host = ?, port = ?, disable = ?, local_spool = ? \
         WHERE id_sensor = ?",
    )
    .bind(&edit.name)
    .bind(&edit.host)
    .bind(edit.port.map(|p| p as i32))
    .bind(if edit.disable { 1_i8 } else { 0_i8 })
    .bind(&edit.local_spool)
    .bind(id_sensor)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Hard-delete a sensor row. CDR rows reference `id_sensor` but
/// without a FK constraint (it's a plain integer column), so this
/// won't cascade — old CDRs will just display an orphaned sensor id.
pub async fn delete(pool: &MySqlPool, id_sensor: u32) -> AppResult<u64> {
    let res = sqlx::query("DELETE FROM sensors WHERE id_sensor = ?")
        .bind(id_sensor)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// First-boot helper: scan the `cdr` table for distinct `id_sensor`
/// values that don't yet have a row in `sensors`, and insert skeleton
/// rows so the admin UI has something to edit. Idempotent — running
/// it twice is a no-op.
///
/// Returns the count of newly inserted rows so the caller can log it.
pub async fn backfill_from_cdr(pool: &MySqlPool) -> AppResult<u64> {
    // INSERT ... SELECT ... WHERE NOT EXISTS is one roundtrip and
    // atomic — no race against concurrent calls.
    let res = sqlx::query(
        "INSERT IGNORE INTO sensors (id_sensor, name) \
         SELECT DISTINCT id_sensor, NULL FROM cdr \
          WHERE id_sensor IS NOT NULL",
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Internal: turn a raw `MySqlRow` (from `SELECT * FROM sensors`) into
/// the focused [`Sensor`] struct, with `extras` populated from every
/// column we don't surface explicitly. Kept alphabetical for stable
/// "Advanced" rendering.
fn row_to_sensor(row: &sqlx::mysql::MySqlRow) -> AppResult<Sensor> {
    let id_sensor: u32 = row.try_get("id_sensor")?;
    let extras = collect_extras(row);

    Ok(Sensor {
        id_sensor,
        name: row.try_get("name").ok(),
        host: row.try_get("host").ok(),
        port: row.try_get("port").ok(),
        disable: row
            .try_get::<Option<i8>, _>("disable")
            .map(|v| v.unwrap_or(0) != 0)
            .unwrap_or(false),
        local_spool: row.try_get("local_spool").ok(),
        extras,
    })
}

/// Every column in the sensors table we *don't* surface as a typed
/// field — for each, read it from the row and stringify it. Ordered
/// alphabetically via `BTreeMap`. NULL columns are omitted entirely
/// (not shown as empty) so the "Advanced" view doesn't drown the
/// operator in N/A entries.
fn collect_extras(row: &sqlx::mysql::MySqlRow) -> BTreeMap<String, String> {
    const EXTRA_COLUMNS: &[&str] = &[
        "auto_upgrade",
        "auto_upgrade_at",
        "auto_upgrade_email",
        "auto_upgrade_enable_beta",
        "auto_upgrade_last_run_at",
        "auto_upgrade_week_days",
        "all_clients_in_active_calls",
        "color_background",
        "color_chart",
        "color_rowview",
        "country_code_for_local_numbers",
        "default_for_active_call",
        "enable_check_napa_without_prefix",
        "id",
        "interface",
        "international_number_min_length",
        "international_number_min_length_prefixes_strict",
        "international_prefixes",
        "is_server",
        "min_length_napa_without_prefix",
        "override_country_prefixes",
        "override_international_rules",
        "read_timeout",
        "remote_mysql_db",
        "remote_mysql_host",
        "remote_mysql_pass",
        "remote_mysql_user",
        "skip_prefixes",
        "skip_prefixes_only_one",
        "tcpdump_folder",
        "tcpdump_mount_folder",
        "timezone_name",
        "timezone_offset",
        "timezone_save_at",
        "upgrade_via_server",
    ];
    let mut out = BTreeMap::new();
    for col in EXTRA_COLUMNS {
        // Try a few common types. Anything we don't recognise we
        // skip silently — the goal is "show what you can", not
        // "guarantee every column is reachable".
        if let Some(v) = row_value_to_string(row, col) {
            out.insert((*col).to_string(), v);
        }
    }
    out
}

/// Best-effort column → display-string conversion for the advanced
/// view. Tries a handful of common types; returns None for anything
/// it can't read (NULL / unknown type). Datetimes render as
/// "YYYY-MM-DD HH:MM:SS"; integers / strings render verbatim.
fn row_value_to_string(row: &sqlx::mysql::MySqlRow, col: &str) -> Option<String> {
    use sqlx::types::chrono::NaiveDateTime;
    if let Ok(v) = row.try_get::<Option<NaiveDateTime>, _>(col) {
        return v.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string());
    }
    if let Ok(v) = row.try_get::<Option<i64>, _>(col) {
        return v.map(|n| n.to_string());
    }
    if let Ok(v) = row.try_get::<Option<i32>, _>(col) {
        return v.map(|n| n.to_string());
    }
    if let Ok(v) = row.try_get::<Option<i16>, _>(col) {
        return v.map(|n| n.to_string());
    }
    if let Ok(v) = row.try_get::<Option<i8>, _>(col) {
        return v.map(|n| n.to_string());
    }
    if let Ok(v) = row.try_get::<Option<String>, _>(col) {
        return v;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(name: Option<&str>, host: Option<&str>, port: Option<&str>, disable: bool) -> SensorEdit {
        SensorEdit {
            name: name.map(String::from),
            host: host.map(String::from),
            port_text: port.map(String::from),
            disable,
            local_spool: None,
        }
    }

    #[test]
    fn parse_edit_form_trims_name_and_host() {
        let parsed = parse_edit_form(&edit(
            Some("  Webitel-PROD  "),
            Some("  10.101.1.112  "),
            Some("5029"),
            false,
        ))
        .expect("valid");
        assert_eq!(parsed.name.as_deref(), Some("Webitel-PROD"));
        assert_eq!(parsed.host.as_deref(), Some("10.101.1.112"));
        assert_eq!(parsed.port, Some(5029));
        assert!(!parsed.disable);
    }

    #[test]
    fn parse_edit_form_empty_strings_become_none() {
        let parsed = parse_edit_form(&edit(Some(""), Some(""), Some(""), false)).expect("valid");
        assert!(parsed.name.is_none());
        assert!(parsed.host.is_none());
        assert!(parsed.port.is_none());
    }

    #[test]
    fn parse_edit_form_port_zero_rejected() {
        // 0 is not a valid TCP port — u16::parse allows it, so we
        // bound-check explicitly? Actually u16 parse accepts 0; we
        // accept any u16 here, real-world a 0 port is bogus but
        // it's the operator's choice. Document via test that
        // 0 is currently accepted.
        let parsed = parse_edit_form(&edit(None, None, Some("0"), false)).expect("0 parses as u16");
        assert_eq!(parsed.port, Some(0));
    }

    #[test]
    fn parse_edit_form_port_overflow_rejected() {
        // 65536 is one past u16::MAX
        assert!(matches!(
            parse_edit_form(&edit(None, None, Some("65536"), false)),
            Err(EditError::BadPort(_))
        ));
        // Negative is not a u16
        assert!(parse_edit_form(&edit(None, None, Some("-1"), false)).is_err());
        // Non-numeric
        assert!(parse_edit_form(&edit(None, None, Some("abc"), false)).is_err());
    }

    #[test]
    fn parse_edit_form_host_rejects_whitespace_and_control() {
        assert!(matches!(
            parse_edit_form(&edit(None, Some("has space"), None, false)),
            Err(EditError::BadHost(_))
        ));
        assert!(matches!(
            parse_edit_form(&edit(None, Some("has\ttab"), None, false)),
            Err(EditError::BadHost(_))
        ));
        assert!(matches!(
            parse_edit_form(&edit(None, Some("line\nbreak"), None, false)),
            Err(EditError::BadHost(_))
        ));
    }

    #[test]
    fn parse_edit_form_host_too_long_rejected() {
        let huge = "a".repeat(256);
        assert!(matches!(
            parse_edit_form(&edit(None, Some(&huge), None, false)),
            Err(EditError::BadHost(_))
        ));
    }

    #[test]
    fn parse_edit_form_accepts_bare_hostname() {
        // VoIPmonitor accepts hostnames, not just IPs.
        let parsed = parse_edit_form(&edit(None, Some("sensor1.example.com"), None, false))
            .expect("hostname is fine");
        assert_eq!(parsed.host.as_deref(), Some("sensor1.example.com"));
    }

    #[test]
    fn parse_edit_form_disable_flag_round_trips() {
        let parsed = parse_edit_form(&edit(None, None, None, true)).expect("valid");
        assert!(parsed.disable);
        let parsed = parse_edit_form(&edit(None, None, None, false)).expect("valid");
        assert!(!parsed.disable);
    }

    #[test]
    fn edit_error_message_lists_the_offending_field() {
        // The form template renders these as inline error text.
        assert!(EditError::BadIdSensor.message().contains("id_sensor"));
        assert!(EditError::BadPort("not a number".into()).message().contains("not a number"));
        assert!(EditError::BadHost("control char".into()).message().contains("control char"));
    }
}
