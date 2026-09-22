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

use chrono::{Duration, NaiveDateTime, Utc};
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
    pub src_ip: Option<String>,
    pub sip_code: Option<u16>,
    pub mos_min: Option<u8>,
    pub mos_max: Option<u8>,
    pub min_duration: Option<u32>,
    pub max_duration: Option<u32>,
    pub id_sensor: Option<u16>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl CdrFilters {
    pub fn normalized(&self) -> NormalizedFilters {
        let page = self.page.unwrap_or(1).max(1);
        let page_size = self.page_size.unwrap_or(50).clamp(1, 500);

        // Default the time window to "last 24h" when the caller didn't
        // specify one — keeps COUNT(*) cheap on the partitioned table.
        let (from, to) = match (self.from, self.to) {
            (None, None) => {
                let now = Utc::now().naive_utc();
                let from = now - Duration::hours(24);
                (Some(from), Some(now))
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
            src_ip: self.src_ip.clone(),
            sip_code: self.sip_code,
            mos_min_mult10: self.mos_min.map(|m| (m as u16) * 10),
            mos_max_mult10: self.mos_max.map(|m| (m as u16) * 10),
            min_duration: self.min_duration,
            max_duration: self.max_duration,
            id_sensor: self.id_sensor,
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
    pub src_ip: Option<String>,
    pub sip_code: Option<u16>,
    pub mos_min_mult10: Option<u16>,
    pub mos_max_mult10: Option<u16>,
    pub min_duration: Option<u32>,
    pub max_duration: Option<u32>,
    pub id_sensor: Option<u16>,
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
        if let Some(ip) = &self.src_ip {
            if let Some(int_ip) = ipv4_to_int(ip) {
                parts.push("(sipcallerip = ? OR sipcalledip = ?)".into());
                binds.push(FilterBind::U32(int_ip));
                binds.push(FilterBind::U32(int_ip));
            }
        }
        if let Some(code) = self.sip_code {
            parts.push("lastSIPresponseNum = ?".into());
            binds.push(FilterBind::U16(code));
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
        if let Some(s) = self.id_sensor {
            parts.push("id_sensor = ?".into());
            binds.push(FilterBind::U16(s));
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

pub async fn list(pool: &MySqlPool, f: &NormalizedFilters) -> Result<Vec<CdrSummary>, sqlx::Error> {
    let rows = list_raw(pool, f).await?;
    Ok(rows.into_iter().map(CdrSummary::from).collect())
}

async fn list_raw(pool: &MySqlPool, f: &NormalizedFilters) -> Result<Vec<CdrRow>, sqlx::Error> {
    let (where_sql, binds) = f.to_where();
    let sql = format!(
        "SELECT ID AS `id`, calldate, callend, duration, connect_duration, \
                caller, callername, called, sipcallerip, sipcalledip, \
                lastSIPresponseNum AS `last_sip_response_num`, \
                mos_min_mult10, a_lost, b_lost, id_sensor \
           FROM cdr \
           {where_sql} \
          ORDER BY calldate DESC \
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
    q = q.bind(f.page_size).bind(f.offset());
    q.fetch_all(pool).await
}

pub async fn count(pool: &MySqlPool, f: &NormalizedFilters) -> Result<u64, sqlx::Error> {
    let (where_sql, binds) = f.to_where();
    let sql = format!("SELECT COUNT(*) AS c FROM cdr {where_sql}");
    let mut q = sqlx::query_scalar::<_, i64>(&sql);
    for b in &binds {
        q = match b {
            FilterBind::DateTime(d) => q.bind(d),
            FilterBind::Str(s) => q.bind(s),
            FilterBind::U32(v) => q.bind(*v),
            FilterBind::U16(v) => q.bind(*v),
        };
    }
    let c = q.fetch_one(pool).await?;
    Ok(c.max(0) as u64)
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
