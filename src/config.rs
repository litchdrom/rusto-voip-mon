use std::path::PathBuf;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub database_url: String,
    pub pcap_dir: PathBuf,
    pub cookie_secret: String,
    /// Hard cap on rows returned per CSV export. Prevents accidental
    /// multi-GB downloads from "all time" filters.
    pub csv_export_limit: usize,
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
        })
    }

    /// Convenience for callers that just want to know if the secret exists.
    pub fn cookie_secret_if_present(&self) -> Option<&str> {
        Some(self.cookie_secret.as_str())
    }
}
