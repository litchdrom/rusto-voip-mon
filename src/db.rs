use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;

pub async fn create_pool(database_url: &str) -> Result<MySqlPool> {
    MySqlPoolOptions::new()
        .max_connections(16)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(600)))
        .connect(database_url)
        .await
        .context("failed to connect to MySQL")
}

/// Shape of the IP columns in the VoIPmonitor `cdr` / `sip_msg` tables.
///
/// VoIPmonitor ships a one-shot `scripts/ipv6_alter.sql` migration that
/// converts every IP column from `INT UNSIGNED` (legacy IPv4-only) to
/// `VARBINARY(16)` (raw 4-byte IPv4 / 16-byte IPv6). When the operator
/// runs that script, sqlx refuses to decode the new column as `u32`.
///
/// This app supports both shapes at runtime by detecting which shape
/// the live DB has at startup and branching the read/write SQL on the
/// result — see [`detect_ip_column_shape`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpColumnShape {
    /// Legacy `INT UNSIGNED` columns. Read as `u32` (network byte
    /// order), write with `INET_ATON()`. IPv4 only.
    LegacyInt,
    /// Post-ipv6-alter `VARBINARY(16)` columns. Read as `Vec<u8>`
    /// (4 bytes = IPv4, 16 bytes = IPv6), write with `INET6_ATON()`.
    /// INET6_ATON auto-detects dotted-quad strings.
    Varbinary,
}

impl IpColumnShape {
    /// SQL function for converting a textual IP into the column's
    /// native type. Used by the filter path (`WHERE sipcallerip IN
    /// (?, ?, ...)` becomes `WHERE sipcallerip IN (FN(STRING), ...)`).
    pub fn inet_function(&self) -> &'static str {
        match self {
            IpColumnShape::LegacyInt => "INET_ATON",
            IpColumnShape::Varbinary => "INET6_ATON",
        }
    }

    /// SQL function for converting a column value into its textual
    /// representation. Used by the read path (`SELECT sipcallerip`
    /// becomes `SELECT FN(sipcallerip)` so we get a string back).
    pub fn inet_to_string_function(&self) -> &'static str {
        match self {
            IpColumnShape::LegacyInt => "INET_NTOA",
            IpColumnShape::Varbinary => "INET6_NTOA",
        }
    }
}

/// Detect whether the live database has legacy `INT UNSIGNED` IP
/// columns or post-ipv6-alter `VARBINARY(16)` columns. Result is
/// process-wide stable (the schema doesn't change at runtime in
/// normal operation), so this is called once at startup and the
/// result is cached in `AppState`.
///
/// We probe the `cdr.sipcallerip` column specifically — if it's
/// `varbinary`, we know the operator ran `ipv6_alter.sql`. If it's
/// `int` (or `int unsigned`), they haven't. Other IP columns
/// (`sipcalledip`, `a_saddr`, `b_saddr`, `sip_msg.ip_src`,
/// `sip_msg.ip_dst`) are converted in the same migration, so
/// probing one is sufficient.
///
/// Returns `LegacyInt` on error so the app falls back to the
/// long-standing SQL rather than refusing to start — better to ship
/// CDRs in a known shape than to refuse to boot on a transient DB
/// blip.
pub async fn detect_ip_column_shape(pool: &MySqlPool) -> IpColumnShape {
    let row = sqlx::query(
        "SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS \
          WHERE TABLE_SCHEMA = DATABASE() \
            AND TABLE_NAME = 'cdr' \
            AND COLUMN_NAME = 'sipcallerip' \
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await;

    match row {
        Ok(Some(row)) => {
            let data_type: Option<String> = row.try_get("DATA_TYPE").ok().flatten();
            match data_type.as_deref() {
                Some("varbinary") => IpColumnShape::Varbinary,
                _ => IpColumnShape::LegacyInt,
            }
        }
        _ => IpColumnShape::LegacyInt,
    }
}
