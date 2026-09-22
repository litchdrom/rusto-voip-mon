use askama::Template;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::NaiveDateTime;
use serde::Deserialize;

use crate::{
    auth::session::SessionUser,
    cdr::{self, CdrFilters, CdrRow, CdrSummary},
    error::{AppError, AppResult},
    state::AppState,
};

#[derive(Template)]
#[template(path = "cdr_list.html")]
pub struct CdrListTemplate {
    pub user: Option<SessionUser>,
    pub cdrs: Vec<CdrSummary>,
    pub page: u32,
    pub page_size: u32,
    pub has_more: bool,
    pub has_prev: bool,
    pub filters: FiltersView,
    pub distinct: DistinctView,
    pub export_url: String,
    pub next_url: String,
    pub prev_url: String,
    pub day_label: String,
}

/// Stringified versions of the distinct values, ready for the template.
#[derive(Debug, Default, Clone)]
pub struct DistinctView {
    pub sip_codes: Vec<String>,
    pub sensor_ids: Vec<String>,
    pub src_ips: Vec<String>,
    pub dst_ips: Vec<String>,
}

impl DistinctView {
    fn from(d: cdr::DistinctValues) -> Self {
        Self {
            sip_codes: d.sip_codes.iter().map(|v| v.to_string()).collect(),
            sensor_ids: d.sensor_ids.iter().map(|v| v.to_string()).collect(),
            src_ips: d.src_ips.iter().map(|&v| cdr::int_to_ipv4(v)).collect(),
            dst_ips: d.dst_ips.iter().map(|&v| cdr::int_to_ipv4(v)).collect(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct FiltersView {
    pub from_str: String,
    pub to_str: String,
    pub caller: String,
    pub called: String,
    /// Comma-separated input shown in the form.
    pub src_ip: String,
    /// Comma-separated input shown in the form.
    pub dst_ip: String,
    /// Comma-separated input shown in the form.
    pub sip_code_str: String,
    pub mos_min_str: String,
    pub mos_max_str: String,
    /// Comma-separated input shown in the form.
    pub id_sensor_str: String,
    pub yesterday_from: String,
    pub yesterday_to: String,
}

impl FiltersView {
    fn from(f: &CdrFilters) -> Self {
        use chrono::Utc;
        let now = Utc::now().naive_utc();
        let yesterday = now.date().pred_opt().unwrap();
        Self {
            from_str: f.from.map(dt_input).unwrap_or_default(),
            to_str: f.to.map(dt_input).unwrap_or_default(),
            caller: f.caller.clone().unwrap_or_default(),
            called: f.called.clone().unwrap_or_default(),
            src_ip: f.src_ip.clone().unwrap_or_default(),
            dst_ip: f.dst_ip.clone().unwrap_or_default(),
            sip_code_str: f.sip_code.clone().unwrap_or_default(),
            mos_min_str: f
                .mos_min
                .map(|m| format!("{:.1}", m as f32 / 10.0))
                .unwrap_or_default(),
            mos_max_str: f
                .mos_max
                .map(|m| format!("{:.1}", m as f32 / 10.0))
                .unwrap_or_default(),
            id_sensor_str: f.id_sensor.clone().unwrap_or_default(),
            yesterday_from: format!("{}T00:00", yesterday),
            yesterday_to: format!("{}T23:59", yesterday),
        }
    }

    fn export_query(&self) -> String {
        let mut parts: Vec<(String, String)> = Vec::new();
        if !self.from_str.is_empty() {
            parts.push(("from".into(), self.from_str.clone()));
        }
        if !self.to_str.is_empty() {
            parts.push(("to".into(), self.to_str.clone()));
        }
        if !self.caller.is_empty() {
            parts.push(("caller".into(), self.caller.clone()));
        }
        if !self.called.is_empty() {
            parts.push(("called".into(), self.called.clone()));
        }
        if !self.src_ip.is_empty() {
            parts.push(("src_ip".into(), self.src_ip.clone()));
        }
        if !self.dst_ip.is_empty() {
            parts.push(("dst_ip".into(), self.dst_ip.clone()));
        }
        if !self.sip_code_str.is_empty() {
            parts.push(("sip_code".into(), self.sip_code_str.clone()));
        }
        if !self.mos_min_str.is_empty() {
            parts.push(("mos_min".into(), self.mos_min_str.clone()));
        }
        if !self.mos_max_str.is_empty() {
            parts.push(("mos_max".into(), self.mos_max_str.clone()));
        }
        if !self.id_sensor_str.is_empty() {
            parts.push(("id_sensor".into(), self.id_sensor_str.clone()));
        }
        let qs = parts
            .iter()
            .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        if qs.is_empty() {
            String::new()
        } else {
            format!("?{qs}")
        }
    }
}

fn url_encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub caller: Option<String>,
    pub called: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    // Numeric fields are taken as raw strings so an empty form value
    // (e.g. `mos_min=`) doesn't fail deserialization. We parse them
    // manually in `build_filters`.
    pub sip_code: Option<String>,
    pub mos_min: Option<String>,
    pub mos_max: Option<String>,
    pub id_sensor: Option<String>,
    pub page: Option<String>,
    pub page_size: Option<String>,
}

pub async fn cdr_list(
    State(state): State<AppState>,
    user: SessionUser,
    Query(q): Query<ListQuery>,
) -> AppResult<Response> {
    let filters = build_filters(&q);
    let normalized = filters.normalized();

    // Fetch the rows + distinct values for the dropdowns in parallel.
    let (page_result, distinct_result) = tokio::join!(
        cdr::list(&state.pool, &normalized),
        cdr::distinct_values(&state.pool, 7, 100),
    );
    let page = page_result?;
    let distinct = DistinctView::from(distinct_result?);

    let view = FiltersView::from(&filters);
    let export_url = format!("/cdr/export.csv{}", view.export_query());

    let has_prev = normalized.page > 1;
    let has_more = page.has_more;
    let day_label = label_for_window(normalized.from, normalized.to);

    let mut page_q = view.export_query();
    if !page_q.is_empty() {
        page_q.push('&');
    }

    let next_url = if has_more {
        format!("/?{page_q}page={}", normalized.page + 1)
    } else {
        String::new()
    };
    let prev_url = if has_prev {
        format!("/?{page_q}page={}", normalized.page - 1)
    } else {
        String::new()
    };

    let tmpl = CdrListTemplate {
        user: Some(user),
        cdrs: page.rows,
        page: normalized.page,
        page_size: normalized.page_size,
        has_more,
        has_prev,
        filters: view,
        distinct,
        export_url,
        next_url,
        prev_url,
        day_label,
    };
    let body = tmpl
        .render()
        .map_err(|e| AppError::Internal(format!("render: {e}")))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

pub async fn cdr_detail(
    State(state): State<AppState>,
    _user: SessionUser,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> AppResult<Response> {
    let row: Option<CdrRow> = sqlx::query_as(
        "SELECT ID AS `id`, calldate, callend, duration, connect_duration, \
                caller, callername, called, sipcallerip, sipcalledip, \
                lastSIPresponseNum AS `last_sip_response_num`, \
                mos_min_mult10, a_lost, b_lost, id_sensor \
           FROM cdr WHERE ID = ? LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;

    let Some(cdr) = row else {
        return Ok((StatusCode::NOT_FOUND, "CDR not found").into_response());
    };
    let cdr = CdrSummary::from(cdr);

    let body = format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>CDR #{id}</title>
<link rel="stylesheet" href="/static/css/style.css"></head>
<body><main class="content">
  <h1>CDR #{id}</h1>
  <p><a href="/">&larr; back to list</a></p>
  <table class="cdrs">
    <tr><th>calldate</th><td>{calldate}</td></tr>
    <tr><th>callend</th><td>{callend}</td></tr>
    <tr><th>caller</th><td>{caller}</td></tr>
    <tr><th>called</th><td>{called}</td></tr>
    <tr><th>duration</th><td>{duration}s</td></tr>
    <tr><th>last SIP</th><td>{sip}</td></tr>
    <tr><th>src IP</th><td>{srcip}</td></tr>
    <tr><th>dst IP</th><td>{dstip}</td></tr>
    <tr><th>MOS</th><td>{mos}</td></tr>
    <tr><th>lost (a/b)</th><td>{al} / {bl}</td></tr>
    <tr><th>sensor</th><td>{sensor}</td></tr>
  </table>
  <p><a class="button" href="/pcap/{id}">Download PCAP</a></p>
</main></body></html>"#,
        id = cdr.id,
        calldate = cdr.calldate.format("%Y-%m-%d %H:%M:%S"),
        callend = cdr.callend.format("%Y-%m-%d %H:%M:%S"),
        caller = cdr.caller.clone().unwrap_or_default(),
        called = cdr.called.clone().unwrap_or_default(),
        duration = cdr.duration.unwrap_or(0),
        sip = cdr.last_sip_response_num.unwrap_or(0),
        srcip = cdr.src_ip_str,
        dstip = cdr.dst_ip_str,
        mos = if cdr.mos_str.is_empty() { "-".to_string() } else { cdr.mos_str },
        al = cdr.a_lost.unwrap_or(0),
        bl = cdr.b_lost.unwrap_or(0),
        sensor = cdr.id_sensor.unwrap_or(0),
    );
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

pub async fn cdr_export_csv(
    State(state): State<AppState>,
    _user: SessionUser,
    Query(q): Query<ListQuery>,
) -> AppResult<Response> {
    let filters = CdrFilters {
        from: parse_dt(&q.from),
        to: parse_dt(&q.to),
        caller: q.caller.filter(|s| !s.is_empty()),
        called: q.called.filter(|s| !s.is_empty()),
        src_ip: q.src_ip.filter(|s| !s.is_empty()),
        dst_ip: q.dst_ip.filter(|s| !s.is_empty()),
        sip_code: q.sip_code.filter(|s| !s.is_empty()),
        mos_min: parse_opt(q.mos_min.as_deref()),
        mos_max: parse_opt(q.mos_max.as_deref()),
        min_duration: None,
        max_duration: None,
        id_sensor: q.id_sensor.filter(|s| !s.is_empty()),
        page: None,
        page_size: Some(10_000),
    };
    let normalized = filters.normalized();
    let page = cdr::list(&state.pool, &normalized).await?;

    let mut out = String::with_capacity(page.rows.len() * 200);
    out.push_str("id,calldate,callend,duration,caller,called,last_sip,mos,id_sensor\n");
    for r in &page.rows {
        let mos = if r.mos_str.is_empty() { String::new() } else { r.mos_str.clone() };
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            r.id,
            r.calldate.format("%Y-%m-%d %H:%M:%S"),
            r.callend.format("%Y-%m-%d %H:%M:%S"),
            r.duration.unwrap_or(0),
            csv_field(&r.caller),
            csv_field(&r.called),
            r.last_sip_response_num.unwrap_or(0),
            mos,
            r.id_sensor.unwrap_or(0),
        ));
    }
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"cdr.csv\"",
            ),
        ],
        out,
    )
        .into_response())
}

fn build_filters(q: &ListQuery) -> CdrFilters {
    CdrFilters {
        from: parse_dt(&q.from),
        to: parse_dt(&q.to),
        caller: q.caller.clone().filter(|s| !s.is_empty()),
        called: q.called.clone().filter(|s| !s.is_empty()),
        src_ip: q.src_ip.clone().filter(|s| !s.is_empty()),
        dst_ip: q.dst_ip.clone().filter(|s| !s.is_empty()),
        sip_code: q.sip_code.clone().filter(|s| !s.is_empty()),
        mos_min: parse_opt(q.mos_min.as_deref()),
        mos_max: parse_opt(q.mos_max.as_deref()),
        min_duration: None,
        max_duration: None,
        id_sensor: q.id_sensor.clone().filter(|s| !s.is_empty()),
        page: parse_opt(q.page.as_deref()),
        page_size: parse_opt(q.page_size.as_deref()),
    }
}

/// Parse an optional form field. Empty / whitespace → None.
/// Non-empty but unparseable → also None (we log it as a warning).
fn parse_opt<T: std::str::FromStr>(s: Option<&str>) -> Option<T> {
    let s = s?.trim();
    if s.is_empty() {
        return None;
    }
    match s.parse::<T>() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(value = s, "ignored unparseable query field");
            None
        }
    }
}

fn csv_field(s: &Option<String>) -> String {
    match s {
        Some(v) => {
            if v.contains(',') || v.contains('"') || v.contains('\n') {
                format!("\"{}\"", v.replace('"', "\"\""))
            } else {
                v.clone()
            }
        }
        None => String::new(),
    }
}

fn parse_dt(s: &Option<String>) -> Option<NaiveDateTime> {
    let s = s.as_deref()?;
    if s.is_empty() {
        return None;
    }
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M").ok()
}

fn dt_input(d: NaiveDateTime) -> String {
    d.format("%Y-%m-%dT%H:%M").to_string()
}

/// Build a human-readable label for the active time window, shown above
/// the CDR list. Examples: "Today", "Yesterday", "2026-09-21", "Last 7 days".
fn label_for_window(from: Option<NaiveDateTime>, to: Option<NaiveDateTime>) -> String {
    use chrono::Utc;
    let now = Utc::now().naive_utc();
    let today = now.date();
    match (from, to) {
        (Some(f), Some(t)) if f.date() == t.date() => {
            let d = f.date();
            if d == today {
                "Today".to_string()
            } else if d == today.pred_opt().unwrap() {
                "Yesterday".to_string()
            } else {
                d.format("%Y-%m-%d").to_string()
            }
        }
        (Some(_), Some(_)) => format!(
            "{} \u{2192} {}",
            from.unwrap().format("%Y-%m-%d %H:%M"),
            to.unwrap().format("%Y-%m-%d %H:%M")
        ),
        (Some(f), None) => format!("from {}", f.format("%Y-%m-%d %H:%M")),
        (None, Some(t)) => format!("until {}", t.format("%Y-%m-%d %H:%M")),
        (None, None) => "All time".to_string(),
    }
}
