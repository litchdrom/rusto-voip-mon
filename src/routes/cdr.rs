use askama::Template;
use axum::{
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum::body::Bytes;
use chrono::NaiveDateTime;
use futures_util::StreamExt;
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
    pub sip_codes: Vec<DistinctItem>,
    pub sensor_ids: Vec<DistinctItem>,
    pub src_ips: Vec<DistinctItem>,
    pub dst_ips: Vec<DistinctItem>,
    /// Total selected across all fields, for the header badge.
    pub total_selected: usize,
}

/// One distinct value with an `is_checked` flag for the checkbox widget.
/// Concrete (non-generic) so Askama's derive can compile the template.
#[derive(Debug, Clone)]
pub struct DistinctItem {
    pub value: String,
    pub is_checked: bool,
}

impl DistinctView {
    fn from(
        d: cdr::DistinctValues,
        selected_src_ips: &[u32],
        selected_dst_ips: &[u32],
        selected_sip_codes: &[u16],
        selected_sensor_ids: &[u16],
    ) -> Self {
        let src_ips: Vec<DistinctItem> = d
            .src_ips
            .iter()
            .map(|&v| DistinctItem {
                value: cdr::int_to_ipv4(v),
                is_checked: selected_src_ips.contains(&v),
            })
            .collect();
        let dst_ips: Vec<DistinctItem> = d
            .dst_ips
            .iter()
            .map(|&v| DistinctItem {
                value: cdr::int_to_ipv4(v),
                is_checked: selected_dst_ips.contains(&v),
            })
            .collect();
        let sip_codes: Vec<DistinctItem> = d
            .sip_codes
            .iter()
            .map(|v| DistinctItem {
                value: v.to_string(),
                is_checked: selected_sip_codes.contains(v),
            })
            .collect();
        let sensor_ids: Vec<DistinctItem> = d
            .sensor_ids
            .iter()
            .map(|v| DistinctItem {
                value: v.to_string(),
                is_checked: selected_sensor_ids.contains(v),
            })
            .collect();
        let total_selected = src_ips.iter().filter(|i| i.is_checked).count()
            + dst_ips.iter().filter(|i| i.is_checked).count()
            + sip_codes.iter().filter(|i| i.is_checked).count()
            + sensor_ids.iter().filter(|i| i.is_checked).count();
        Self {
            sip_codes,
            sensor_ids,
            src_ips,
            dst_ips,
            total_selected,
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
    /// Resolved display strings for the multi-select summary headers.
    pub src_ip_display: String,
    pub dst_ip_display: String,
    pub sip_code_display: String,
    pub id_sensor_display: String,
    pub yesterday_from: String,
    pub yesterday_to: String,
}

impl FiltersView {
    fn from(f: &CdrFilters) -> Self {
        use chrono::Utc;
        let now = Utc::now().naive_utc();
        let yesterday = now.date().pred_opt().unwrap();
        let src_ip = f.src_ip.clone().unwrap_or_default();
        let dst_ip = f.dst_ip.clone().unwrap_or_default();
        let sip_code = f.sip_code.clone().unwrap_or_default();
        let id_sensor = f.id_sensor.clone().unwrap_or_default();
        Self {
            from_str: f.from.map(dt_input).unwrap_or_default(),
            to_str: f.to.map(dt_input).unwrap_or_default(),
            caller: f.caller.clone().unwrap_or_default(),
            called: f.called.clone().unwrap_or_default(),
            src_ip_display: if src_ip.is_empty() { "any".into() } else { src_ip.clone() },
            dst_ip_display: if dst_ip.is_empty() { "any".into() } else { dst_ip.clone() },
            sip_code_display: if sip_code.is_empty() { "any".into() } else { sip_code.clone() },
            id_sensor_display: if id_sensor.is_empty() { "any".into() } else { id_sensor.clone() },
            src_ip,
            dst_ip,
            sip_code_str: sip_code,
            mos_min_str: f
                .mos_min
                .map(|m| format!("{:.1}", m as f32 / 10.0))
                .unwrap_or_default(),
            mos_max_str: f
                .mos_max
                .map(|m| format!("{:.1}", m as f32 / 10.0))
                .unwrap_or_default(),
            id_sensor_str: id_sensor,
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
    // Multi-value fields arrive as repeated query params or comma-separated
    // text input — we accept Vec<String> and merge both in build_filters.
    pub src_ip: Option<Vec<String>>,
    pub dst_ip: Option<Vec<String>>,
    pub sip_code: Option<Vec<String>>,
    pub id_sensor: Option<Vec<String>>,
    // Numeric fields are taken as raw strings so an empty form value
    // (e.g. `mos_min=`) doesn't fail deserialization. We parse them
    // manually in `build_filters`.
    pub mos_min: Option<String>,
    pub mos_max: Option<String>,
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
    let distinct = DistinctView::from(
        distinct_result?,
        &normalized.src_ips,
        &normalized.dst_ips,
        &normalized.sip_codes,
        &normalized.sensor_ids,
    );

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
        src_ip: merge_csv(q.src_ip.as_deref()).filter(|s| !s.is_empty()),
        dst_ip: merge_csv(q.dst_ip.as_deref()).filter(|s| !s.is_empty()),
        sip_code: merge_csv(q.sip_code.as_deref()).filter(|s| !s.is_empty()),
        mos_min: parse_opt(q.mos_min.as_deref()),
        mos_max: parse_opt(q.mos_max.as_deref()),
        min_duration: None,
        max_duration: None,
        id_sensor: merge_csv(q.id_sensor.as_deref()).filter(|s| !s.is_empty()),
        page: None,
        // `normalized_for_export` doesn't clamp the page size — CSV wants
        // every matching row. We still apply offset=0, no pagination.
        page_size: Some(50),
    };
    let normalized = filters.normalized_for_export();

    // Stream of raw CDRs (each row in its own message).
    let row_stream = cdr::list_stream(&state.pool, &normalized);

    // Channel of formatted CSV byte chunks for the HTTP response.
    let (csv_tx, csv_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);

    tokio::spawn(async move {
        // Header row first.
        if csv_tx
            .send(Ok(Bytes::from_static(
                b"id,calldate,callend,duration,caller,called,last_sip,mos,id_sensor\n",
            )))
            .await
            .is_err()
        {
            return;
        }

        let mut row_stream = row_stream;
        while let Some(row_result) = row_stream.next().await {
            match row_result {
                Ok(r) => {
                    let summary = CdrSummary::from(r);
                    let line = format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        summary.id,
                        summary.calldate.format("%Y-%m-%d %H:%M:%S"),
                        summary.callend.format("%Y-%m-%d %H:%M:%S"),
                        summary.duration.unwrap_or(0),
                        csv_field(&summary.caller),
                        csv_field(&summary.called),
                        summary.last_sip_response_num.unwrap_or(0),
                        summary.mos_str,
                        summary.id_sensor.unwrap_or(0),
                    );
                    if csv_tx.send(Ok(Bytes::from(line))).await.is_err() {
                        break; // client disconnected
                    }
                }
                Err(e) => {
                    tracing::error!(error = ?e, "CSV stream error");
                    break;
                }
            }
        }
    });

    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(csv_rx));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            "attachment; filename=\"cdr.csv\"",
        )
        .body(body)
        .map_err(|e| AppError::Internal(format!("response build: {e}")))?)
}

fn build_filters(q: &ListQuery) -> CdrFilters {
    CdrFilters {
        from: parse_dt(&q.from),
        to: parse_dt(&q.to),
        caller: q.caller.clone().filter(|s| !s.is_empty()),
        called: q.called.clone().filter(|s| !s.is_empty()),
        // Merge all forms of each multi-value field (repeated checkboxes
        // + comma-separated custom input) into a single canonical string.
        src_ip: merge_csv(q.src_ip.as_deref()).filter(|s| !s.is_empty()),
        dst_ip: merge_csv(q.dst_ip.as_deref()).filter(|s| !s.is_empty()),
        sip_code: merge_csv(q.sip_code.as_deref()).filter(|s| !s.is_empty()),
        mos_min: parse_opt(q.mos_min.as_deref()),
        mos_max: parse_opt(q.mos_max.as_deref()),
        min_duration: None,
        max_duration: None,
        id_sensor: merge_csv(q.id_sensor.as_deref()).filter(|s| !s.is_empty()),
        page: parse_opt(q.page.as_deref()),
        page_size: parse_opt(q.page_size.as_deref()),
    }
}

/// Take repeated query values (from checkboxes) and split each one on
/// commas (from a text input). Return a single deduped, comma-joined string.
fn merge_csv(values: Option<&[String]>) -> Option<String> {
    let vals = values?;
    if vals.is_empty() {
        return None;
    }
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for v in vals {
        for part in v.split(',') {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            if seen.insert(t.to_string()) {
                out.push(t.to_string());
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out.join(","))
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
