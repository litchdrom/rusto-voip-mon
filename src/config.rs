use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::FixedOffset;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub database_url: String,
    pub pcap_dir: PathBuf,
    pub cookie_secret: String,
    /// Hard cap on rows returned per CSV export. Prevents accidental
    /// multi-GB downloads from "all time" filters.
    pub csv_export_limit: usize,
    /// Display/filter timezone offset from UTC, in **seconds**. Defaults
    /// to 0 (UTC) so behavior is unchanged when unset. Set via
    /// `APP_TZ_OFFSET_SECS` to shift the "today" window and labels to
    /// match the operator's local time when the server clock is in UTC
    /// but the human isn't. Seconds (not hours) so non-whole-hour
    /// zones work — e.g. `28800` for UTC+8, `19800` for IST +5:30,
    /// `20700` for Nepal +5:45.
    pub tz_offset_secs: i32,
    /// Timezone offset of the **stored** `calldate` values, in
    /// **seconds** from UTC. Defaults to 0 (UTC) for the standard
    /// VoIPmonitor convention.
    ///
    /// Set via `APP_DB_TZ_OFFSET_SECS` to a non-zero value when the
    /// server's MySQL session stores `DATETIME` in server-local
    /// time rather than UTC. Seconds (not hours) so non-whole-hour
    /// storage TZs work the same way the operator-display TZ does:
    /// `19800` if calldate comes back as IST wall-clock, `28800`
    /// for UTC+8 storage, `-18000` for US Eastern. Range
    /// `-43200..=50400`.
    ///
    /// The conversion is applied at the SQL→view boundary in
    /// `CdrSummary::from_row` so every consumer (template, CSV,
    /// detail page) renders in the operator's resolved offset
    /// without each having to know the storage TZ; the inverse
    /// shift is applied at the filter-bind layer (`to_where`,
    /// `distinct_values`) so naive `from`/`to` filter bounds
    /// stay in operator-TZ semantics end-to-end.
    pub db_tz_offset_secs: i32,
    /// Per-query timeout in seconds. Bounds how long a single sqlx call
    /// (CDR list setup, detail page, distinct-values lookup, pcap parts
    /// query, etc.) is allowed to run before the client gets a 504 and
    /// the connection is released back to the pool. 0 disables the cap.
    pub query_timeout_secs: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            listen: std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?,
            pcap_dir: PathBuf::from(
                std::env::var("PCAP_DIR").unwrap_or_else(|_| "/var/spool/voipmonitor".to_string()),
            ),
            cookie_secret: std::env::var("APP_COOKIE_SECRET")
                .context("APP_COOKIE_SECRET not set")?,
            csv_export_limit: std::env::var("CSV_EXPORT_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000),
            tz_offset_secs: std::env::var("APP_TZ_OFFSET_SECS")
                .ok()
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0),
            db_tz_offset_secs: std::env::var("APP_DB_TZ_OFFSET_SECS")
                .ok()
                .and_then(|v| v.parse::<i32>().ok())
                .unwrap_or(0),
            query_timeout_secs: std::env::var("APP_QUERY_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
        })
    }

    /// Convenience for callers that just want to know if the secret exists.
    pub fn cookie_secret_if_present(&self) -> Option<&str> {
        Some(self.cookie_secret.as_str())
    }

    /// Build a `FixedOffset` matching the configured timezone. Always
    /// returns a value (UTC if no offset is set).
    pub fn tz(&self) -> FixedOffset {
        FixedOffset::east_opt(self.tz_offset_secs)
            .unwrap_or_else(|| FixedOffset::east_opt(0).unwrap())
    }
}
