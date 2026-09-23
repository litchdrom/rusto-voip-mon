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
    /// Display/filter timezone offset from UTC, in seconds. Defaults to 0
    /// (UTC) so behavior is unchanged when unset. Set via
    /// `APP_TZ_OFFSET_HOURS` to shift the "today" window and labels to
    /// match the operator's local time when the server clock is in UTC
    /// but the human isn't.
    pub tz_offset_secs: i32,
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
            tz_offset_secs: std::env::var("APP_TZ_OFFSET_HOURS")
                .ok()
                .and_then(|v| v.parse::<i32>().ok())
                .map(|h| h.saturating_mul(3600))
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
