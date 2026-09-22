//! CDR domain types and queries against VoIPmonitor's `cdr` table.
//!
//! All queries are read-only. The `cdr` table is partitioned by `calldate`
//! (range partitioning), so date filters are essential to avoid full scans.
//!
//! We split the row into two structs:
//!
//! - [`CdrRow`]      — fields that come directly from SQL (`FromRow` derive).
//! - [`CdrSummary`]  — the same data plus pre-formatted display strings
//!                     (`mos_str`, `src_ip_str`, `dst_ip_str`). Templates
//!                     consume this one.

use chrono::{Duration, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, MySqlPool};

/// Raw row straight from the `cdr` table.
#[derive(Debug, Clone, FromRow)]
pub struct CdrRow {
    pub id: u64,
    pub calldate: NaiveDateTime,
    pub callend: NaiveDateTime,
    pub duration: Option<u32>,
    pub connect_duration: Option<u32>,
    pub caller: Option<String>,
    pub callername: Option<String>,
    pub called: Option<String>,
    pub sipcallerip: Option<u32>,
    pub sipcalledip: Option<u32>,
    pub last_sip_response_num: Option<u16>,
    pub mos_min_mult10: Option<u8>,
    pub a_lost: Option<u32>,
    pub b_lost: Option<u32>,
    pub id_sensor: Option<u16>,
}

/// View struct used by templates and the CSV exporter.
#[derive(Debug, Clone, Serialize)]
pub struct CdrSummary {
    pub id: u64,
    pub calldate: NaiveDateTime,
    pub callend: NaiveDateTime,
    pub duration: Option<u32>,
    pub connect_duration: Option<u32>,
    pub caller: Option<String>,
    pub callername: Option<String>,
    pub called: Option<String>,
    pub src_ip_str: String,
    pub dst_ip_str: String,
    pub last_sip_response_num: Option<u16>,
    pub mos_str: String,
    pub a_lost: Option<u32>,
    pub b_lost: Option<u32>,
    pub id_sensor: Option<u16>,
}

impl From<CdrRow> for CdrSummary {
    fn from(row: CdrRow) -> Self {
        let mos_str = row
            .mos_min_mult10
            .map(|m| format!("{:.1}", m as f32 / 10.0))
            .unwrap_or_default();
        let src_ip_str = row.sipcallerip.map(int_to_ipv4).unwrap_or_default();
        let dst_ip_str = row.sipcalledip.map(int_to_ipv4).unwrap_or_default();
        Self {
            id: row.id,
            calldate: row.calldate,
            callend: row.callend,
            duration: row.duration,
            connect_duration: row.connect_duration,
            caller: row.caller,
            callername: row.callername,
            called: row.called,
            src_ip_str,
            dst_ip_str,
            last_sip_response_num: row.last_sip_response_num,
            mos_str,
            a_lost: row.a_lost,
            b_lost: row.b_lost,
            id_sensor: row.id_sensor,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CdrFilters {
    pub from: Option<NaiveDateTime>,
    pub to: Option<NaiveDateTime>,
    pub caller: Option<String>,
    pub called: Option<String>,
    /// Caller-side IPs (matches `sipcallerip`). Comma-separated in the form.
    pub src_ip: Option<String>,
    /// Callee-side IPs (matches `sipcalledip`). Comma-separated in the form.
    pub dst_ip: Option<String>,
    /// SIP response codes. Comma-separated in the form.
    pub sip_code: Option<String>,
    /// Sensor IDs. Comma-separated in the form.
    pub id_sensor: Option<String>,
    pub mos_min: Option<u8>,
    pub mos_max: Option<u8>,
    pub min_duration: Option<u32>,
    pub max_duration: Option<u32>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl CdrFilters {
    pub fn normalized(&self) -> NormalizedFilters {
        let page = self.page.unwrap_or(1).max(1);
        let page_size = self.page_size.unwrap_or(50).clamp(1, 500);

        // Default the time window to **today** (00:00:00 .. 23:59:59 UTC)
        // when the caller didn't specify one.
        let (from, to) = match (self.from, self.to) {
            (None, None) => {
                let now = Utc::now().naive_utc();
                let day: NaiveDate = now.date();
                (
                    Some(day.and_hms_opt(0, 0, 0).unwrap()),
                    Some(day.and_hms_opt(23, 59, 59).unwrap()),
                )
            }
            (Some(f), None) => (Some(f), None),
            (None, Some(t)) => (None, Some(t)),
            (Some(f), Some(t)) => (Some(f), Some(t)),
        };

        NormalizedFilters {
            from,
            to,
            caller: self.caller.clone(),
            called: self.called.clone(),
            src_ips: parse_ip_list(self.src_ip.as_deref()),
            dst_ips: parse_ip_list(self.dst_ip.as_deref()),
            sip_codes: parse_u16_list(self.sip_code.as_deref()),
            sensor_ids: parse_u16_list(self.id_sensor.as_deref()),
            mos_min_mult10: self.mos_min.map(|m| (m as u16) * 10),
            mos_max_mult10: self.mos_max.map(|m| (m as u16) * 10),
            min_duration: self.min_duration,
            max_duration: self.max_duration,
            page,
            page_size,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedFilters {
    pub from: Option<NaiveDateTime>,
    pub to: Option<NaiveDateTime>,
    pub caller: Option<String>,
    pub called: Option<String>,
    pub src_ips: Vec<u32>,
    pub dst_ips: Vec<u32>,
    pub sip_codes: Vec<u16>,
    pub sensor_ids: Vec<u16>,
    pub mos_min_mult10: Option<u16>,
    pub mos_max_mult10: Option<u16>,
    pub min_duration: Option<u32>,
    pub max_duration: Option<u32>,
    pub page: u32,
    pub page_size: u32,
}

impl NormalizedFilters {
    pub fn offset(&self) -> u32 {
        (self.page - 1) * self.page_size
    }

    /// Build the WHERE-clause SQL fragment + matching bind values.
    pub fn to_where(&self) -> (String, Vec<FilterBind>) {
        let mut parts: Vec<String> = Vec::new();
        let mut binds: Vec<FilterBind> = Vec::new();

        if let Some(from) = self.from {
            parts.push("calldate >= ?".into());
            binds.push(FilterBind::DateTime(from));
        }
        if let Some(to) = self.to {
            parts.push("calldate <= ?".into());
            binds.push(FilterBind::DateTime(to));
        }
        if let Some(c) = &self.caller {
            parts.push("caller LIKE ?".into());
            binds.push(FilterBind::Str(format!("%{c}%")));
        }
        if let Some(c) = &self.called {
            parts.push("called LIKE ?".into());
            binds.push(FilterBind::Str(format!("%{c}%")));
        }
        if !self.src_ips.is_empty() {
            parts.push(format!(
                "sipcallerip IN ({})",
                placeholders(self.src_ips.len())
            ));
            for v in &self.src_ips {
                binds.push(FilterBind::U32(*v));
            }
        }
        if !self.dst_ips.is_empty() {
            parts.push(format!(
                "sipcalledip IN ({})",
                placeholders(self.dst_ips.len())
            ));
            for v in &self.dst_ips {
                binds.push(FilterBind::U32(*v));
            }
        }
        if !self.sip_codes.is_empty() {
            parts.push(format!(
                "lastSIPresponseNum IN ({})",
                placeholders(self.sip_codes.len())
            ));
            for v in &self.sip_codes {
                binds.push(FilterBind::U16(*v));
            }
        }
        if !self.sensor_ids.is_empty() {
            parts.push(format!(
                "id_sensor IN ({})",
                placeholders(self.sensor_ids.len())
            ));
            for v in &self.sensor_ids {
                binds.push(FilterBind::U16(*v));
            }
        }
        if let Some(m) = self.mos_min_mult10 {
            parts.push("mos_min_mult10 >= ?".into());
            binds.push(FilterBind::U16(m));
        }
        if let Some(m) = self.mos_max_mult10 {
            parts.push("mos_min_mult10 <= ?".into());
            binds.push(FilterBind::U16(m));
        }
        if let Some(d) = self.min_duration {
            parts.push("duration >= ?".into());
            binds.push(FilterBind::U32(d));
        }
        if let Some(d) = self.max_duration {
            parts.push("duration <= ?".into());
            binds.push(FilterBind::U32(d));
        }

        let where_sql = if parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", parts.join(" AND "))
        };
        (where_sql, binds)
    }
}

pub enum FilterBind {
    DateTime(NaiveDateTime),
    Str(String),
    U32(u32),
    U16(u16),
}

fn placeholders(n: usize) -> String {
    std::iter::repeat("?")
        .take(n)
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse a comma-separated list of IPv4 strings, dropping invalid/empty
/// entries. Returns an empty Vec when no valid IPs are present.
fn parse_ip_list(s: Option<&str>) -> Vec<u32> {
    let Some(s) = s else { return Vec::new() };
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter_map(ipv4_to_int)
        .collect()
}

/// Parse a comma-separated list of u16s, dropping invalid/empty entries.
fn parse_u16_list(s: Option<&str>) -> Vec<u16> {
    let Some(s) = s else { return Vec::new() };
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<u16>().ok())
        .collect()
}

/// Page of CDRs plus a flag indicating whether at least one more page
/// likely exists (used by the prev/next pagination links).
#[derive(Debug, Clone)]
pub struct CdrPage {
    pub rows: Vec<CdrSummary>,
    pub has_more: bool,
}

/// Fetch a single page of CDRs. We over-fetch by one row beyond the page
/// size to cheaply detect "there's a next page" without a separate COUNT.
pub async fn list(pool: &MySqlPool, f: &NormalizedFilters) -> Result<CdrPage, sqlx::Error> {
    let (where_sql, binds) = f.to_where();
    let limit = f.page_size + 1;
    let sql = format!(
        "SELECT ID AS `id`, calldate, callend, duration, connect_duration, \
                caller, callername, called, sipcallerip, sipcalledip, \
                lastSIPresponseNum AS `last_sip_response_num`, \
                mos_min_mult10, a_lost, b_lost, id_sensor \
           FROM cdr \
           {where_sql} \
          ORDER BY calldate DESC, ID DESC \
          LIMIT ? OFFSET ?",
    );
    let mut q = sqlx::query_as::<_, CdrRow>(&sql);
    for b in &binds {
        q = match b {
            FilterBind::DateTime(d) => q.bind(d),
            FilterBind::Str(s) => q.bind(s),
            FilterBind::U32(v) => q.bind(*v),
            FilterBind::U16(v) => q.bind(*v),
        };
    }
    q = q.bind(limit).bind(f.offset());
    let mut rows = q.fetch_all(pool).await?;
    let has_more = rows.len() as u32 > f.page_size;
    if has_more {
        rows.truncate(f.page_size as usize);
    }
    let summaries = rows.into_iter().map(CdrSummary::from).collect();
    Ok(CdrPage { rows: summaries, has_more })
}

/// Distinct values from the last N days, used to populate the filter
/// `<datalist>` pickers so users can choose from observed values OR type
/// custom ones (the text input + datalist combo).
#[derive(Debug, Clone)]
pub struct DistinctValues {
    pub sip_codes: Vec<u16>,
    pub sensor_ids: Vec<u16>,
    pub src_ips: Vec<u32>,
    pub dst_ips: Vec<u32>,
}

/// Returns up to `limit` distinct values per field, scoped to the last
/// `lookback_days` days so the dropdown stays relevant.
pub async fn distinct_values(
    pool: &MySqlPool,
    lookback_days: i64,
    limit: u32,
) -> Result<DistinctValues, sqlx::Error> {
    let since = Utc::now().naive_utc() - Duration::days(lookback_days);

    let sip_codes: Vec<u16> = sqlx::query_scalar(
        "SELECT DISTINCT lastSIPresponseNum FROM cdr \
          WHERE calldate >= ? AND lastSIPresponseNum IS NOT NULL \
          ORDER BY lastSIPresponseNum ASC LIMIT ?",
    )
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let sensor_ids: Vec<u16> = sqlx::query_scalar(
        "SELECT DISTINCT id_sensor FROM cdr \
          WHERE calldate >= ? AND id_sensor IS NOT NULL \
          ORDER BY id_sensor ASC LIMIT ?",
    )
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let src_ips: Vec<u32> = sqlx::query_scalar(
        "SELECT DISTINCT sipcallerip FROM cdr \
          WHERE calldate >= ? AND sipcallerip IS NOT NULL \
          ORDER BY sipcallerip DESC LIMIT ?",
    )
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let dst_ips: Vec<u32> = sqlx::query_scalar(
        "SELECT DISTINCT sipcalledip FROM cdr \
          WHERE calldate >= ? AND sipcalledip IS NOT NULL \
          ORDER BY sipcalledip DESC LIMIT ?",
    )
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(DistinctValues {
        sip_codes,
        sensor_ids,
        src_ips,
        dst_ips,
    })
}

/// Parse an IPv4 string ("1.2.3.4") into VoIPmonitor's int representation
/// (host byte order). Returns None on invalid input.
pub fn ipv4_to_int(ip: &str) -> Option<u32> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a = parts[0].parse::<u32>().ok()?;
    let b = parts[1].parse::<u32>().ok()?;
    let c = parts[2].parse::<u32>().ok()?;
    let d = parts[3].parse::<u32>().ok()?;
    if a > 255 || b > 255 || c > 255 || d > 255 {
        return None;
    }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

pub fn int_to_ipv4(n: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (n >> 24) & 0xff,
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    )
}
