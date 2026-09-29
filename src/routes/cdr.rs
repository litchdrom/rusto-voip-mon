use askama::Template;
use axum::{
    body::Body,
    extract::{RawQuery, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum::body::Bytes;
use chrono::NaiveDateTime;
use futures_util::StreamExt;
use percent_encoding::percent_decode_str;
use std::collections::HashMap;

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
    /// Stored for template symmetry; not currently rendered. Could
    /// power a "X rows of Y" header in the future.
    #[allow(dead_code)]
    pub page_size: u32,
    pub has_more: bool,
    pub has_prev: bool,
    pub filters: FiltersView,
    pub distinct: DistinctView,
    pub export_url: String,
    /// Same filter as `export_url`, aimed at GET /pcap/batch — used by
    /// the <noscript> fallback link for "Download zip of all matching".
    /// When no filter is set, this is just `/pcap/batch` (which the
    /// server will 400 on, but the link is harmless and honest).
    pub pcap_zip_all_url: String,
    pub next_url: String,
    pub prev_url: String,
    pub day_label: String,
    /// Active TZ offset hours (the one driving the page), for the
    /// dropdown's `selected` attribute.
    pub tz_offset_hours: i8,
    /// Server default TZ offset hours, so the dropdown can label
    /// "Server default (-3h)" distinctly from "user override".
    pub tz_default_hours: i8,
    /// Full operator selection (every CDR ID ticked across all visited
    /// pages). Serialised into a `<script type="application/json">` tag
    /// in the template so the JS state mirrors the session without a
    /// round-trip on every page load.
    pub selected_cdr_ids: Vec<u64>,
    /// Parallel to `cdrs` (same length, same order). `selected_flags[i]`
    /// is true iff `cdrs[i].id` is in the operator's session-persisted
    /// batch selection. Asked for as a Vec<bool> rather than a HashSet
    /// because askama 0.12's expression parser can't call `contains`
    /// on user types in an `{% if %}`; indexing into a Vec works fine.
    pub selected_flags: Vec<bool>,
    /// Total size of the operator's selection (across all visited
    /// pages). Drives the "(N selected)" badge on the batch button.
    pub selected_count: usize,
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
    pub duration_min_str: String,
    pub duration_max_str: String,
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
    fn from(f: &CdrFilters, tz: chrono::FixedOffset) -> Self {
        use chrono::Utc;
        let now = Utc::now().with_timezone(&tz);
        let yesterday = now.date_naive().pred_opt().unwrap();
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
            duration_min_str: f
                .min_duration
                .map(|v| v.to_string())
                .unwrap_or_default(),
            duration_max_str: f
                .max_duration
                .map(|v| v.to_string())
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
        if !self.duration_min_str.is_empty() {
            parts.push(("duration_min".into(), self.duration_min_str.clone()));
        }
        if !self.duration_max_str.is_empty() {
            parts.push(("duration_max".into(), self.duration_max_str.clone()));
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

// (No ListQuery struct — multi-value fields don't work with serde_urlencoded,
// so we parse the raw query string ourselves via RawQuery.)

pub async fn cdr_list(
    State(state): State<AppState>,
    user: SessionUser,
    raw_query: RawQuery,
) -> AppResult<Response> {
    // We can't use `Query<ListQuery>` alone because serde_urlencoded
    // doesn't aggregate repeated query keys into Vec<String>. Parse
    // manually with `RawQuery` instead.
    let params = parse_query_params(raw_query.0.as_deref().unwrap_or(""));
    let q = SingleParams {
        from: params.first("from"),
        to: params.first("to"),
        caller: params.first("caller"),
        called: params.first("called"),
        mos_min: params.first("mos_min"),
        mos_max: params.first("mos_max"),
        duration_min: params.first("duration_min"),
        duration_max: params.first("duration_max"),
        page: params.first("page"),
        page_size: params.first("page_size"),
    };
    let filters = build_filters(&q, &params);
    // Per-request TZ override wins, then session-stored, then env default.
    let query_tz: Option<i8> = params
        .first("tz_offset_hours")
        .as_deref()
        .and_then(|s| s.parse().ok());
    let (tz, _) = state.resolve_tz(&user, query_tz);
    let normalized = filters.normalized(tz);
    let timeout = state.config.query_timeout_secs;

    // Fetch the rows + distinct values for the dropdowns in parallel,
    // each capped at `timeout` so a slow scan doesn't lock up the page.
    let (page_result, distinct_result) = tokio::join!(
        crate::error::with_query_timeout(timeout, cdr::list(&state.pool, &normalized)),
        crate::error::with_query_timeout(timeout, cdr::distinct_values(&state.pool, 7, 100, tz)),
    );
    let page = page_result?;
    let distinct = DistinctView::from(
        distinct_result?,
        &normalized.src_ips,
        &normalized.dst_ips,
        &normalized.sip_codes,
        &normalized.sensor_ids,
    );

    let view = FiltersView::from(&filters, tz);
    let export_url = format!("/cdr/export.csv{}", view.export_query());
    // Same filter, different endpoint — the <noscript> fallback "Download
    // zip of all matching" link. Built server-side so the template can
    // emit a plain <a href="/pcap/batch?filter=..."> without trying to
    // strip the leading `?` or url-encode in askama.
    let pcap_zip_all_url = {
        let qs = view.export_query();
        let inner = qs.trim_start_matches('?');
        if inner.is_empty() {
            "/pcap/batch".to_string()
        } else {
            format!("/pcap/batch?filter={}", url_encode(inner))
        }
    };

    let has_prev = normalized.page > 1;
    let has_more = page.has_more;
    let day_label = label_for_window(normalized.from, normalized.to, tz);

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
        user: Some(user.clone()),
        cdrs: page.rows.clone(),
        selected_cdr_ids: user.selected_cdr_ids.clone(),
        selected_flags: page.rows.iter().map(|c| user.selected_cdr_ids.contains(&c.id)).collect(),
        page: normalized.page,
        page_size: normalized.page_size,
        has_more,
        has_prev,
        filters: view,
        distinct,
        export_url,
        pcap_zip_all_url,
        next_url,
        prev_url,
        day_label,
        tz_offset_hours: (tz.local_minus_utc() / 3600) as i8,
        tz_default_hours: (state.config.tz_offset_secs / 3600) as i8,
        selected_count: user.selected_cdr_ids.len(),
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
    let timeout = state.config.query_timeout_secs;
    // Try the full SELECT first (with per-leg RTP stats). If the live
    // install is missing any of the new columns (older VoIPmonitor
    // version, custom cdr table, etc.) fall back to a minimal SELECT
    // so the page still renders — the RTP panel is omitted (it hides
    // itself when every leg is unpopulated). One warning per process is
    // plenty; we don't want to spam the log every page load.
    let full_select = format!(
        "SELECT {} FROM cdr WHERE ID = ? LIMIT 1",
        cdr::CDR_FULL_SELECT_COLUMNS,
    );
    // Fallback for installs where some RTP columns are missing —
    // pre-`a_mos_lqo_mult10` schema. The minimal SELECT still satisfies
    // sqlx's `FromRow` derive because every remaining column on
    // CdrRow is Option<_> — sqlx fills missing columns with None.
    //
    // NOTE: this assumes the live cdr table at minimum has all the
    // pre-RTP columns. If a column in that minimal set is also
    // missing, we hit ColumnNotFound again — at which point the
    // operator needs to fall back to a much older binary or patch
    // their schema.
    let minimal_select = "SELECT ID AS `id`, calldate, callend, duration, connect_duration, \
                           caller, callername, called, sipcallerip, sipcalledip, \
                           lastSIPresponseNum AS `last_sip_response_num`, \
                           mos_min_mult10, a_lost, b_lost, id_sensor \
                      FROM cdr WHERE ID = ? LIMIT 1";
    let row_result = crate::error::with_query_timeout(
        timeout,
        sqlx::query_as::<_, CdrRow>(&full_select)
            .bind(id)
            .fetch_optional(&state.pool),
    )
    .await;
    let row: Option<CdrRow> = match row_result {
        Ok(r) => r,
        Err(AppError::Sqlx(sqlx::Error::ColumnNotFound(col))) => {
            // Live cdr table is missing at least one of the new RTP
            // columns. Log once per occurrence (not per page load —
            // the operator needs to know but we don't want to flood)
            // and fall back to the minimal SELECT.
            tracing::warn!(
                cdr_id = id,
                missing_column = %col,
                "cdr table is missing RTP column — falling back to minimal SELECT"
            );
            crate::error::with_query_timeout(
                timeout,
                sqlx::query_as::<_, CdrRow>(minimal_select)
                    .bind(id)
                    .fetch_optional(&state.pool),
            )
            .await?
        }
        Err(e) => return Err(e),
    };

    let Some(cdr) = row else {
        return Ok((StatusCode::NOT_FOUND, "CDR not found").into_response());
    };
    // Capture the caller IP before the CdrSummary conversion drops it
    // — used as the direction marker for the SIP timeline (an outgoing
    // request is one whose `sipcallerip` matches the CDR's own).
    let sipcallerip = cdr.sipcallerip;
    let cdr = CdrSummary::from(cdr);

    // Pull the optional extension tables in parallel — all three are tiny.
    let (next, branches, sip_messages) = tokio::join!(
        crate::error::with_query_timeout(timeout, cdr::fetch_cdr_next(&state.pool, id)),
        crate::error::with_query_timeout(timeout, cdr::fetch_cdr_branches(&state.pool, id)),
        crate::error::with_query_timeout(
            timeout,
            cdr::fetch_sip_messages(&state.pool, id, sipcallerip, 500),
        ),
    );
    let next = next?;
    let branches = branches?;
    // SIP fetch failure is non-fatal — we just render the page without
    // the timeline. Logging uses Debug (not Display) so the underlying
    // sqlx DatabaseError message + column name show up in the log line;
    // Display on `sqlx::Error` collapses to the generic "database error"
    // and gives the operator nothing to debug against.
    let mut sip_messages = match sip_messages {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(cdr_id = id, error = ?e, "sip_msg fetch failed");
            Vec::new()
        }
    };

    // Fallback: if the sip_msg table didn't yield anything (install
    // doesn't populate it, schema doesn't match, or the rows were
    // purged), parse the SIP messages straight out of the merged
    // pcap archive. VoIPmonitor always writes the SIP wire format
    // there — it's the source of truth. Cost: one pcap extraction
    // per page load, bounded by the user's existing pcap_dir I/O.
    if sip_messages.is_empty() {
        match crate::routes::pcap::build_pcap_bytes(&state, id).await {
            Ok(pcap_bytes) => {
                let parsed = cdr::sip_pcap::parse_sip_messages_from_pcap(
                    &pcap_bytes, 500,
                );
                if !parsed.is_empty() {
                    tracing::info!(
                        cdr_id = id,
                        count = parsed.len(),
                        "sip timeline sourced from pcap (sip_msg table empty)"
                    );
                    sip_messages = parsed;
                }
            }
            Err(e) => {
                tracing::warn!(
                    cdr_id = id, error = ?e,
                    "pcap fallback also failed; timeline stays empty"
                );
            }
        }
    }

    // Apply direction marker now that we have the final message list.
    // `parse_sip_messages_from_pcap` doesn't know the CDR's caller IP
    // (it's outside the cdr module), so we set direction here based
    // on the message's source IP matching the CDR's sipcallerip.
    if let Some(marker) = sipcallerip {
        for m in sip_messages.iter_mut() {
            if m.direction.is_empty() {
                let src_int = cdr::ipv4_to_int(&m.src_ip_str);
                m.direction = if src_int == Some(marker) {
                    "out".to_string()
                } else {
                    "in".to_string()
                };
            }
        }
    }

    let static_fields = next.static_fields.as_ref();
    let fbasename = static_fields
        .and_then(|n| n.fbasename.as_deref())
        .unwrap_or("");
    let match_header = static_fields
        .and_then(|n| n.match_header.as_deref())
        .unwrap_or("");
    let digest_username = static_fields
        .and_then(|n| n.digest_username.as_deref())
        .unwrap_or("");
    let geo_position = static_fields
        .and_then(|n| n.geo_position.as_deref())
        .unwrap_or("");
    let hold = static_fields
        .and_then(|n| n.hold.as_deref())
        .unwrap_or("");
    let spool_index = static_fields
        .and_then(|n| n.spool_index)
        .map(|v| v.to_string())
        .unwrap_or_default();
    // Build the custom-headers table dynamically.
    let custom_header_rows: String = next
        .custom_headers
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(col, v)| {
            format!(
                "<tr><th>{}</th><td><code>{}</code></td></tr>",
                html_escape(col),
                html_escape(v)
            )
        })
        .collect();

    let body = format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>CDR #{id}</title>
<link rel="stylesheet" href="/static/css/style.css"></head>
<body><main class="content">
  <h1>CDR #{id}</h1>
  <p><a href="/">&larr; back to list</a></p>
  <h2>Call</h2>
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

  <h2>Custom headers &amp; PCAP linking</h2>
  <table class="cdrs">
    <tr><th>fbasename</th><td><code>{fbasename}</code> <span class="muted small">(derived from SIP Call-ID; matches the inner pcap filename)</span></td></tr>
    <tr><th>match_header</th><td><code>{match_header}</code> <span class="muted small">(custom header used to link call legs)</span></td></tr>
    <tr><th>digest_username</th><td><code>{digest_username}</code></td></tr>
    <tr><th>GeoPosition</th><td>{geo_position}</td></tr>
    <tr><th>hold</th><td>{hold}</td></tr>
    <tr><th>spool_index</th><td>{spool_index} <span class="muted small">(tar.zst type bucket: 0=SIP, 1=RTP, вЂ¦)</span></td></tr>
  </table>
  {custom_headers_html}
  {branches_html}
  {rtp_html}
  {flow_html}
  {sip_html}

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
        fbasename = html_escape(fbasename),
        match_header = html_escape(match_header),
        digest_username = html_escape(digest_username),
        geo_position = html_escape(geo_position),
        hold = html_escape(hold),
        spool_index = spool_index,
        custom_headers_html = if custom_header_rows.is_empty() {
            String::new()
        } else {
            format!(
                "<h3>Custom headers</h3><table class=\"cdrs\">{custom_header_rows}</table>"
            )
        },
        branches_html = render_branches(&branches),
        // sngrep-style call flow sits between the call-leg / RTP
        // panels and the SIP message timeline — the eye reads it as
        // "what shape did the call have?" before drilling into the
        // per-message details below. Reuses the same SipMessage
        // vector; no extra fetch.
        flow_html = render_sngrep_flow(
            &sip_messages,
            cdr.rtp_a.received,
            if cdr.rtp_a.codec_name.is_empty() { None } else { Some(cdr.rtp_a.codec_name.clone()) },
            &cdr.rtp_a.src_ip_str,
            &cdr.rtp_a.dst_ip_str,
            cdr.rtp_b.received,
            if cdr.rtp_b.codec_name.is_empty() { None } else { Some(cdr.rtp_b.codec_name.clone()) },
            &cdr.rtp_b.src_ip_str,
            &cdr.rtp_b.dst_ip_str,
        ),
        sip_html = render_sip_timeline(&sip_messages),
        rtp_html = render_rtp_stats(&cdr.rtp_a, &cdr.rtp_b),
    );
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

/// Render the per-leg RTP statistics panel — a two-column "A leg /
/// Render the SIP message timeline in the classic `sngrep` style:
/// two horizontal rows (outgoing from us, incoming to us), each
/// message rendered as a small chip showing `method + response
/// code`, colour-coded by the response class, connected by `→`
/// arrows in time order. Reuses the same `SipMessage` vector the
/// SIP timeline below the panel uses — no extra fetch.
///
/// One glance shows the dialog shape: an INVITE that gets through
/// to 200 OK in 300 ms looks very different from an INVITE that
/// spends 8 seconds bouncing between 100/180. With `direction`
/// known (we set it from the CDR's `sipcallerip` against each
/// message's `ip_src`), the two-lane layout naturally shows the
/// caller → callee → caller → caller round-trips.
///
/// Each row is one SIP message: time offset on the left, an arrow
/// running from caller (left actor) to callee (right actor) or vice
/// versa, with method/response code rendered inside the arrow.
/// Between setup (last 2xx/ACK) and teardown (first BYE) we render
/// an RTP-flow row showing the negotiated codec and per-direction
/// packet counts — same visual idiom as Wireshark's
/// Telephony > SIP Flows view.
///
/// Returns "" when `messages` is empty (the section is then omitted).
fn render_sngrep_flow(
    messages: &[cdr::SipMessage],
    rtp_a_pkts: Option<u32>,
    rtp_a_codec: Option<String>,
    rtp_a_src: &str,
    rtp_a_dst: &str,
    rtp_b_pkts: Option<u32>,
    rtp_b_codec: Option<String>,
    rtp_b_src: &str,
    rtp_b_dst: &str,
) -> String {
    if messages.is_empty() {
        return String::new();
    }

    // Caller / callee endpoint labels — derived from the first
    // outgoing message we see (its src/dst IPs are the two endpoints).
    let first = messages.iter().find(|m| !m.src_ip_str.is_empty());
    let (caller_ip, callee_ip) = first.map_or((String::new(), String::new()), |m| {
        (m.src_ip_str.clone(), m.dst_ip_str.clone())
    });

    // Time axis: relative to the first message's timestamp.
    let t_min = messages.iter().map(|m| m.calldate).min().unwrap();

    // Walk messages, emitting one <tr> per row. Each row has four
    // cells: time, caller-arrow, message, callee-arrow. Outgoing
    // messages get an outgoing arrow on the caller side; incoming
    // messages get an incoming arrow on the callee side. RTP rows
    // (inserted between last 2xx/ACK and first BYE) use the same
    // 4-column shape with bidirectional arrows.
    let mut rows: Vec<String> = Vec::with_capacity(messages.len() + 2);
    let mut media_started = false;
    let mut media_inserted = false;

    for m in messages.iter() {
        let offset_ms = (m.calldate - t_min).num_milliseconds();
        let rel_time = format!("+{:.1}s", offset_ms as f64 / 1000.0);
        let is_out = m.direction != "in";
        let method_class = sip_method_class(&m.method);
        let code_class = sip_code_class(m.response_num);

        let method_disp = if m.method.is_empty() {
            String::new()
        } else {
            format!(
                "<span class=\"seq-method {method_class}\">{}</span>",
                html_escape(&m.method)
            )
        };
        let code_disp = if m.response_num == 0 {
            String::new()
        } else {
            format!(
                "<span class=\"seq-code {code_class}\">{}</span>",
                m.response_num
            )
        };
        let src_esc = html_escape(&m.src_ip_str);
        let dst_esc = html_escape(&m.dst_ip_str);
        let title = format!(
            "{} {} {} → {} @ {}",
            m.method,
            m.response_text,
            src_esc,
            dst_esc,
            m.calldate.format("%H:%M:%S%.3f"),
        );

        // Build the 4 cells: time | caller-arrow | message | callee-arrow.
        // Outgoing: caller side shows "►───", callee side empty.
        // Incoming: caller side empty, callee side shows "───◄".
        let caller_cell = if is_out {
            r#"<td class="seq-arrow-cell seq-arrow-out">►───</td>"#
        } else {
            r#"<td class="seq-arrow-cell"></td>"#
        };
        let callee_cell = if is_out {
            r#"<td class="seq-arrow-cell"></td>"#
        } else {
            r#"<td class="seq-arrow-cell seq-arrow-in">───◄</td>"#
        };
        rows.push(format!(
            "<tr class=\"seq-row seq-row-{}\" title=\"{}\">\
             <td class=\"seq-time\">{}</td>\
             {}\
             <td class=\"seq-msg-cell\">{}{}</td>\
             {}\
             </tr>",
            if is_out { "out" } else { "in" },
            title,
            rel_time,
            caller_cell,
            method_disp,
            code_disp,
            callee_cell,
        ));

        // Mark media_started at first 2xx or ACK.
        if !media_started {
            let ack_or_2xx =
                (!m.method.is_empty() && m.method == "ACK") ||
                (m.response_num >= 200 && m.response_num < 300);
            if ack_or_2xx {
                media_started = true;
            }
        }
        // Insert RTP rows right before the first BYE/CANCEL after media.
        if media_started && !media_inserted && (m.method == "BYE" || m.method == "CANCEL") {
            rows.push(rtp_row_html(
                rtp_a_pkts,
                rtp_a_codec.as_deref(),
                rtp_a_src,
                rtp_a_dst,
                rtp_b_pkts,
                rtp_b_codec.as_deref(),
                rtp_b_src,
                rtp_b_dst,
            ));
            media_inserted = true;
        }
    }
    if media_started && !media_inserted {
        rows.push(rtp_row_html(
            rtp_a_pkts,
            rtp_a_codec.as_deref(),
            rtp_a_src,
            rtp_a_dst,
            rtp_b_pkts,
            rtp_b_codec.as_deref(),
            rtp_b_src,
            rtp_b_dst,
        ));
    }

    let total = messages.len();

    format!(
        "<h2>Call flow</h2>\
         <p class=\"muted small\">\
           {total} SIP messages, time top-to-bottom. \
           Arrows in the caller / callee columns point in the message direction; \
           RTP rows show the negotiated codec and packet counts per direction.\
         </p>\
         <div class=\"seq-diagram\">\
           <table class=\"seq-table\">\
             <thead><tr>\
               <th class=\"seq-time\">time</th>\
               <th class=\"seq-actor\">caller<br><small>{caller_ip}</small></th>\
               <th class=\"seq-msg-col\">message</th>\
               <th class=\"seq-actor\">callee<br><small>{callee_ip}</small></th>\
             </tr></thead>\
             <tbody>{rows}</tbody>\
           </table>\
         </div>",
        rows = rows.join("\n"),
    )
}

/// Render the RTP-flow rows that live between the last 2xx/ACK and
/// the first BYE. Each row is a `<tr>` matching the column layout
/// in `render_sngrep_flow` (time | caller-arrow | message |
/// callee-arrow). We emit ONE row per direction (caller→callee and
/// callee→caller) rather than collapsing both into one — RTP can
/// take a different network path than SIP (proxy scenarios, NAT
/// pinholes, media relays), so each leg needs its own row showing
/// the actual RTP endpoints and packet count.
fn rtp_row_html(
    a_pkts: Option<u32>,
    a_codec: Option<&str>,
    a_src: &str,
    a_dst: &str,
    b_pkts: Option<u32>,
    b_codec: Option<&str>,
    b_src: &str,
    b_dst: &str,
) -> String {
    let a_codec = a_codec.unwrap_or("").trim();
    let b_codec = b_codec.unwrap_or("").trim();
    let codec = if !a_codec.is_empty() {
        a_codec.to_string()
    } else if !b_codec.is_empty() {
        b_codec.to_string()
    } else {
        "RTP".to_string()
    };
    let a_count = a_pkts
        .map(|n| format!("{} pkts", n))
        .unwrap_or_else(|| "—".to_string());
    let b_count = b_pkts
        .map(|n| format!("{} pkts", n))
        .unwrap_or_else(|| "—".to_string());

    // Two table rows: outgoing (caller → callee) and incoming
    // (callee → caller). Each shows its actual RTP endpoints, which
    // can differ from the SIP endpoints when RTP traverses a relay
    // / NAT.
    let a_esc = html_escape(a_src);
    let a_dst_esc = html_escape(a_dst);
    let b_esc = html_escape(b_src);
    let b_dst_esc = html_escape(b_dst);

    let outgoing = format!(
        "<tr class=\"seq-row seq-row-out seq-row-rtp\">\
         <td class=\"seq-time\">RTP</td>\
         <td class=\"seq-arrow-cell seq-arrow-out\">═══►</td>\
         <td class=\"seq-msg-cell\">RTP {codec} ({a_count})<br><small class=\"muted\">{a_esc} → {a_dst_esc}</small></td>\
         <td class=\"seq-arrow-cell\"></td>\
         </tr>",
    );
    let incoming = format!(
        "<tr class=\"seq-row seq-row-in seq-row-rtp\">\
         <td class=\"seq-time\">RTP</td>\
         <td class=\"seq-arrow-cell\"></td>\
         <td class=\"seq-msg-cell\">RTP {codec} ({b_count})<br><small class=\"muted\">{b_esc} → {b_dst_esc}</small></td>\
         <td class=\"seq-arrow-cell seq-arrow-in\">◄═══</td>\
         </tr>",
    );
    format!("{outgoing}{incoming}")
}

/// B leg" table with the most useful VoIPmonitor-derived quality
/// metrics. Returns "" when neither leg has any data (failed calls,
/// early hangups) so the section is omitted entirely.
fn render_rtp_stats(rtp_a: &cdr::RtpLeg, rtp_b: &cdr::RtpLeg) -> String {
    fn dim_or_dash(v: &str) -> &str {
        if v.is_empty() { "<span class=\"muted\">—</span>" } else { v }
    }
    if !rtp_a.is_populated() && !rtp_b.is_populated() {
        return String::new();
    }
    // Sub-header line per leg showing the RTP-level source IP and the
    // other leg's source IP joined with a bidirectional arrow. VoIP-
    // monitor's `a_saddr` / `b_saddr` are the hosts that sent RTP in
    // each direction — they can differ from `sipcallerip` / `sipcalledip`
    // when media traverses a relay, which is the exact case where the
    // analyst most needs to see them.
    fn ip_subhead(leg: &cdr::RtpLeg) -> String {
        if leg.src_ip_str.is_empty() && leg.dst_ip_str.is_empty() {
            return String::from("<small class=\"muted\">no RTP endpoints</small>");
        }
        let src = html_escape(&leg.src_ip_str);
        let dst = html_escape(&leg.dst_ip_str);
        match (leg.src_ip_str.is_empty(), leg.dst_ip_str.is_empty()) {
            (true, false) => format!("<small>&rarr; {dst}</small>"),
            (false, true) => format!("<small>{src}</small>"),
            (false, false) => format!("<small>{src} &harr; {dst}</small>"),
            _ => unreachable!(),
        }
    }
    let mut out = String::from("<h2>RTP statistics</h2>");
    out.push_str(&format!(
        "<table class=\"cdrs rtp-stats\"><thead>\
         <tr><th>metric</th><th>A leg (caller)<br>{}</th>\
         <th>B leg (callee)<br>{}</th></tr>\
         </thead><tbody>",
        ip_subhead(rtp_a),
        ip_subhead(rtp_b),
    ));
    let row = |label: &str, a: &str, b: &str| -> String {
        format!(
            "<tr><th>{label}</th><td>{}</td><td>{}</td></tr>",
            dim_or_dash(a),
            dim_or_dash(b),
        )
    };
    // VoIPmonitor's "jitter" columns (a_avgjitter_mult10, a_maxjitter)
    // are interarrival times, not RFC 3550 smoothed jitter — explain
    // it via the `title` attribute so the label can stay short.
    // "Max packet gap" is renamed from "Max jitter" because the value
    // (typically tens or hundreds of ms during a burst-loss event) is
    // the worst single packet-to-packet gap, NOT sustained jitter —
    // and showing "Max jitter: 992 ms" next to MOS 4.5 contradicts the
    // operator's intuition. The cell is rendered with `.muted` class
    // to make it visually subordinate to the RTCP max jitter row below,
    // which carries the RFC 3550 smoothed value that actually maps to
    // Wireshark.
    let jitter_tooltip = "VoIPmonitor's avg/max \"jitter\" is the \
         average / worst packet-to-packet interarrival time, not RFC \
         3550 smoothed jitter. See \"RTCP max jitter\" for the RFC 3550 \
         estimate that matches Wireshark.";
    out.push_str(&row(
        "MOS LQO",
        &rtp_a.mos_str(),
        &rtp_b.mos_str(),
    ));
    out.push_str(&row(
        "Codec",
        if rtp_a.codec_name.is_empty() { "" } else { &rtp_a.codec_name },
        if rtp_b.codec_name.is_empty() { "" } else { &rtp_b.codec_name },
    ));
    out.push_str(&row(
        "Packetisation (ptime)",
        &rtp_a.ptime.map(|p| format!("{p} ms")).unwrap_or_default(),
        &rtp_b.ptime.map(|p| format!("{p} ms")).unwrap_or_default(),
    ));
    out.push_str(&row("Loss", &rtp_a.loss_str(), &rtp_b.loss_str()));
    out.push_str(&format!(
        "<tr><th title=\"{jt}\">Avg interarrival</th><td>{} ms</td><td>{} ms</td></tr>",
        rtp_a.avg_jitter_ms(),
        rtp_b.avg_jitter_ms(),
        jt = jitter_tooltip,
    ));
    // "Max packet gap" (VoIPmonitor's a_maxjitter) is rendered with
    // the muted class on the cells — it spikes during packet loss
    // (because the next packet arrives after the lost one would have)
    // and is NOT sustained jitter, so a value of 992 ms alongside
    // MOS 4.5 is normal, not alarming. The tooltip carries the full
    // explanation; the cell de-emphasis keeps the table from reading
    // as a quality failure at a glance.
    out.push_str(&format!(
        "<tr><th title=\"{jt}\">Max packet gap</th>\
         <td class=\"muted\" title=\"{jt}\">{} ms</td>\
         <td class=\"muted\" title=\"{jt}\">{} ms</td></tr>",
        rtp_a.max_jitter_ms(),
        rtp_b.max_jitter_ms(),
        jt = jitter_tooltip,
    ));
    out.push_str(&row(
        "Avg one-way delay",
        &format!("{} ms", rtp_a.delay_ms()),
        &format!("{} ms", rtp_b.delay_ms()),
    ));
    out.push_str(&row(
        "RTCP cumulative loss",
        &rtp_a.rtcp_loss.map(|n| n.to_string()).unwrap_or_default(),
        &rtp_b.rtcp_loss.map(|n| n.to_string()).unwrap_or_default(),
    ));
    // RTCP max jitter collapses VoIPmonitor's 65535 (u16 max) sentinel
    // for "no RTCP report received" — short calls, mid-stream SSRC
    // changes, and certain NAT pinholes that drop RTCP. The helper
    // returns "" for the sentinel so the cell renders as a muted
    // em-dash instead of an impossible "65535 ms" next to a clean
    // 0.4 ms on the other leg.
    out.push_str(&row(
        "RTCP max jitter",
        &rtp_a.rtcp_max_jitter_ms(),
        &rtp_b.rtcp_max_jitter_ms(),
    ));
    out.push_str("</tbody></table>");
    // Footnote: explain where these come from. Analysts often want
    // to know "is this real-time or stored?" before trusting the
    // numbers — they ARE real-time (VoIPmonitor stores them when the
    // call ends) but they are aggregates, not per-second.
    out.push_str(
        "<p class=\"muted small\">RTP stats come from VoIPmonitor's \
         RTCP reports captured during the call. They are per-call \
         aggregates, not time-series — for a per-second view, pull \
         the pcap.</p>",
    );
    out
}

fn render_branches(branches: &[cdr::CdrNextBranch]) -> String {
    if branches.is_empty() {
        return String::new();
    }
    let items: Vec<String> = branches
        .iter()
        .map(|b| {
            let ts = b
                .calldate
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "?".to_string());
            let call_id = b.call_id.as_deref().unwrap_or("");
            let fbasename = b.fbasename.as_deref().unwrap_or("");
            format!(
                "<li><span class=\"muted small\">[{ts}]</span> \
                 call_id=<code>{ci}</code> \
                 {fb}</li>",
                ts = html_escape(&ts),
                ci = html_escape(call_id),
                fb = if fbasename.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<span class=\"muted small\">В· fbasename=<code>{}</code></span>",
                        html_escape(fbasename)
                    )
                }
            )
        })
        .collect();
    format!(
        "<h2>Call legs (cdr_next_branches)</h2><ul class=\"branches\">{}</ul>",
        items.join("")
    )
}

/// Render the SIP message timeline as a collapsible list. Each row:
/// time, direction arrow, method (color-coded), response code, party
/// headers, full message body behind a `<details>` toggle.
///
/// We try to pair requests with their responses on the same row so an
/// analyst sees "INVITE → 200 OK" at a glance, with the raw request +
/// response stacked below in a `<pre>`. Unpaired responses (e.g. an
/// out-of-dialog BYE without a matching request) render as a single
/// row with no request block.
///
/// The cap is enforced server-side (500 in `fetch_sip_messages`); if
/// we hit it the heading shows "+ more not shown — check the pcap".
fn render_sip_timeline(messages: &[cdr::SipMessage]) -> String {
    if messages.is_empty() {
        return String::new();
    }
    let mut out = String::from("<h2>SIP message flow</h2>");
    out.push_str(&format!(
        "<p class=\"muted small\">{} message{} (capped at 500)</p>",
        messages.len(),
        if messages.len() == 1 { "" } else { "s" }
    ));
    out.push_str("<table class=\"cdrs sip-timeline\"><thead><tr>");
    out.push_str("<th class=\"num\">time</th>");
    out.push_str("<th class=\"num\">dir</th>");
    out.push_str("<th>method</th>");
    out.push_str("<th class=\"num\">code</th>");
    out.push_str("<th>from</th>");
    out.push_str("<th>to</th>");
    out.push_str("<th></th>");
    out.push_str("</tr></thead><tbody>");
    for m in messages {
        let ts = m.calldate.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let method_class = sip_method_class(&m.method);
        let dir_arrow = if m.direction == "out" { "→" } else { "←" };
        let dir_class = if m.direction == "out" { "dir-out" } else { "dir-in" };
        let code_class = sip_code_class(m.response_num);
        let resp_display = if m.response_num == 0 {
            String::new()
        } else {
            format!("{}", m.response_num)
        };
        let resp_text = html_escape(&m.response_text);
        let from = html_escape(&m.from_num);
        let to = html_escape(&m.to_num);
        let src = html_escape(&m.src_ip_str);
        let dst = html_escape(&m.dst_ip_str);
        let content_type = html_escape(&m.content_type);
        // Build the expandable body. Only show the toggle when there's
        // something useful to look at — bare CANCEL/ACK messages often
        // have empty content and showing them is just noise.
        let body_html = if m.content.trim().is_empty() {
            String::new()
        } else {
            let content = html_escape(&m.content);
            format!(
                "<details class=\"sip-body\">\
                   <summary>raw SIP body ({content_type}, {bytes} bytes)</summary>\
                   <pre>{content}</pre>\
                 </details>",
                bytes = m.content.len(),
            )
        };
        out.push_str(&format!(
            "<tr class=\"sip-row\">\
               <td class=\"num small\">{ts}</td>\
               <td class=\"num {dir_class}\">{dir_arrow}</td>\
               <td><span class=\"sip-method {method_class}\">{method}</span></td>\
               <td class=\"num {code_class}\" title=\"{resp_text}\">{resp_display}</td>\
               <td>{from}<br><span class=\"muted small\">{src}</span></td>\
               <td>{to}<br><span class=\"muted small\">{dst}</span></td>\
               <td>{body_html}</td>\
             </tr>",
            method = html_escape(&m.method),
        ));
    }
    out.push_str("</tbody></table>");
    out
}

/// CSS class for the response-code cell — colors 1xx / 2xx / 3xx /
/// 4xx / 5xx / 6xx distinctly so a glance at the column tells you
/// which leg failed.
fn sip_code_class(code: u16) -> &'static str {
    match code {
        100..=199 => "sip-1xx",
        200..=299 => "sip-2xx",
        300..=399 => "sip-3xx",
        400..=499 => "sip-4xx",
        500..=599 => "sip-5xx",
        600..=699 => "sip-6xx",
        _ => "sip-other",
    }
}

/// CSS class for the method cell — INVITE / BYE / CANCEL are the
/// "lifecycle" methods that matter when triaging a failed call;
/// the rest are answered with a neutral colour.
fn sip_method_class(method: &str) -> &'static str {
    match method {
        "INVITE" => "sip-method-invite",
        "BYE" => "sip-method-bye",
        "CANCEL" => "sip-method-cancel",
        "ACK" => "sip-method-ack",
        "REGISTER" => "sip-method-register",
        "OPTIONS" => "sip-method-options",
        "NOTIFY" => "sip-method-notify",
        "SUBSCRIBE" => "sip-method-subscribe",
        "REFER" => "sip-method-refer",
        "UPDATE" => "sip-method-update",
        "PRACK" => "sip-method-prack",
        "MESSAGE" => "sip-method-message",
        "PUBLISH" => "sip-method-publish",
        "INFO" => "sip-method-info",
        _ => "sip-method-other",
    }
}

/// Minimal HTML escape — good enough for v0.1 since headers come from
/// trusted admin-configured SIP traffic, but use a real sanitizer if you
/// ever start rendering attacker-controlled data.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub async fn cdr_export_csv(
    State(state): State<AppState>,
    _user: SessionUser,
    raw_query: RawQuery,
) -> AppResult<Response> {
    let params = parse_query_params(raw_query.0.as_deref().unwrap_or(""));
    let q = SingleParams {
        from: params.first("from"),
        to: params.first("to"),
        caller: params.first("caller"),
        called: params.first("called"),
        mos_min: params.first("mos_min"),
        mos_max: params.first("mos_max"),
        duration_min: params.first("duration_min"),
        duration_max: params.first("duration_max"),
        page: params.first("page"),
        page_size: params.first("page_size"),
    };
    let filters = build_filters(&q, &params);
    let tz = state.tz_default();
    let normalized = filters.normalized_for_export(tz);
    let timeout = state.config.query_timeout_secs;

    // Pull the env-configured row cap. Per-request `?csv_limit=N` can
    // override; this lets an admin temporarily allow a large export
    // without restarting the service.
    let per_request: Option<usize> = params
        .first("csv_limit")
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0);
    let cap = per_request.unwrap_or(state.config.csv_export_limit);

    // Spawn the streaming query (sync call). We can't time-bound it
    // directly — `list_stream` returns immediately and a background task
    // drives the cursor. Instead, we wait for the *first* row with the
    // configured timeout: if the server can't produce one within `timeout`
    // seconds, we 504 and drop the channel. Once rows start flowing, the
    // stream runs as long as needed (a 100k-row export shouldn't trip a
    // 30s cap).
    let mut row_stream = cdr::list_stream(&state.pool, &normalized, cap);

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

        // Wait for the first row with a timeout — bounds the initial
        // query latency. Subsequent rows stream without a per-row cap.
        let first_row = if timeout > 0 {
            tokio::time::timeout(
                std::time::Duration::from_secs(timeout),
                row_stream.next(),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("first row not produced within {timeout}s"),
                )
            })
            .and_then(|v| match v {
                Some(r) => Ok(Some(r)),
                None => Ok(None),
            })
        } else {
            Ok(row_stream.next().await)
        };

        let mut next_row: Option<Result<CdrRow, sqlx::Error>> = match first_row {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(timeout, error = %e, "CSV export: first row timed out");
                let _ = csv_tx.send(Err(e)).await;
                return;
            }
        };

        let mut sent = 0usize;
        loop {
            let row_result = match next_row.take() {
                Some(v) => Some(v),
                None => row_stream.next().await,
            };
            let Some(row_result) = row_result else { break };
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
                    sent += 1;
                }
                Err(e) => {
                    tracing::error!(error = ?e, "CSV stream error");
                    break;
                }
            }
        }
        tracing::info!(rows_sent = sent, cap = cap, "CSV export done");
    });

    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(csv_rx));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            "attachment; filename=\"cdr.csv\"",
        )
        .header("X-Export-Cap", cap.to_string())
        .body(body)
        .map_err(|e| AppError::Internal(format!("response build: {e}")))?)
}

pub(crate) fn build_filters(q: &SingleParams, params: &QueryParams) -> CdrFilters {
    CdrFilters {
        from: parse_dt(&q.from),
        to: parse_dt(&q.to),
        caller: q.caller.clone().filter(|s| !s.is_empty()),
        called: q.called.clone().filter(|s| !s.is_empty()),
        // `caller_in` / `called_in` are the multi-value exact-match fields.
        // Repeated keys (`?caller_in=A&caller_in=B`) AND a comma-joined
        // single key (`?caller_in=A,B`) both work — the SQL is a single
        // `caller IN (?, ?, ?)` rather than a chain of `LIKE OR LIKE`.
        caller_in: merge_str_list(params.all("caller_in")),
        called_in: merge_u64_list(params.all("called_in")),
        // Merge repeated-key values + comma-separated values for each
        // multi-value field into a single canonical comma-joined string.
        src_ip: merge_csv(params.all("src_ip")).filter(|s| !s.is_empty()),
        dst_ip: merge_csv(params.all("dst_ip")).filter(|s| !s.is_empty()),
        sip_code: merge_csv(params.all("sip_code")).filter(|s| !s.is_empty()),
        mos_min: parse_opt(q.mos_min.as_deref()),
        mos_max: parse_opt(q.mos_max.as_deref()),
        min_duration: parse_opt(q.duration_min.as_deref()),
        max_duration: parse_opt(q.duration_max.as_deref()),
        id_sensor: merge_csv(params.all("id_sensor")).filter(|s| !s.is_empty()),
        page: parse_opt(q.page.as_deref()),
        page_size: parse_opt(q.page_size.as_deref()),
    }
}

/// All query parameters parsed into a `name -> Vec<value>` map. We parse
/// manually because `serde_urlencoded` does not aggregate repeated keys
/// into `Vec<String>` — every `key=value` pair is delivered individually
/// as a String to deserialize, which fails for sequence types.
#[derive(Debug, Default, Clone)]
pub struct QueryParams {
    inner: HashMap<String, Vec<String>>,
}

impl QueryParams {
    fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, key: String, value: String) {
        self.inner.entry(key).or_default().push(value);
    }

    /// First value for a key, or `None`.
    pub fn first(&self, key: &str) -> Option<String> {
        self.inner.get(key).and_then(|v| v.first().cloned())
    }

    /// All values for a key (in submission order), or `None` if absent.
    pub fn all(&self, key: &str) -> Option<&[String]> {
        self.inner.get(key).map(Vec::as_slice)
    }
}

/// Parse a raw query string into a `QueryParams`. Decodes percent-encoding,
/// splits on `&` and `=`, leaves invalid pairs as empty strings (the caller
/// filters them).
pub fn parse_query_params(raw: &str) -> QueryParams {
    let mut out = QueryParams::new();
    let raw = raw.trim_start_matches('?');
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let key = percent_decode_str(k).decode_utf8_lossy().into_owned();
        let value = percent_decode_str(v).decode_utf8_lossy().into_owned();
        if !key.is_empty() {
            out.push(key, value);
        }
    }
    out
}

/// Scalar params only — multi-value fields are pulled separately from
/// `QueryParams` because of the serde_urlencoded limitation described
/// above.
#[derive(Debug, Default)]
pub(crate) struct SingleParams {
    pub from: Option<String>,
    pub to: Option<String>,
    pub caller: Option<String>,
    pub called: Option<String>,
    pub mos_min: Option<String>,
    pub mos_max: Option<String>,
    pub duration_min: Option<String>,
    pub duration_max: Option<String>,
    pub page: Option<String>,
    pub page_size: Option<String>,
}

/// Take repeated query values (from checkboxes) and split each one on
/// commas (from a text input). Return a single deduped, comma-joined string.
fn merge_csv(values: Option<&[String]>) -> Option<String> {
    let parts = merge_str_list(values);
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(","))
    }
}

/// Take repeated query values (from repeated keys like `?caller_in=A&caller_in=B`)
/// or comma-separated single keys (`?caller_in=A,B`), split, trim, dedupe.
/// Returns the cleaned list (empty when no valid values).
pub(crate) fn merge_str_list(values: Option<&[String]>) -> Vec<String> {
    let Some(vals) = values else { return Vec::new() };
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
    out
}

/// Like `merge_str_list` but parses each value as `u64`. Non-numeric
/// entries are silently dropped — the URL contract is "list of numbers",
/// so `?called_in=abc` shouldn't blow up; it just contributes nothing.
pub(crate) fn merge_u64_list(values: Option<&[String]>) -> Vec<u64> {
    merge_str_list(values)
        .into_iter()
        .filter_map(|s| s.parse::<u64>().ok())
        .collect()
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
fn label_for_window(
    from: Option<NaiveDateTime>,
    to: Option<NaiveDateTime>,
    tz: chrono::FixedOffset,
) -> String {
    use chrono::Utc;
    let now = Utc::now().with_timezone(&tz);
    let today = now.date_naive();
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

#[cfg(test)]
mod sip_render_tests {
    use super::*;

    fn mk_msg(method: &str, code: u16, seconds_offset: f64) -> cdr::SipMessage {
        let t0 = chrono::NaiveDate::from_ymd_opt(2026, 9, 25)
            .unwrap()
            .and_hms_opt(14, 30, 0)
            .unwrap();
        let delta_ms = (seconds_offset * 1000.0) as i64;
        cdr::SipMessage {
            id: 0,
            calldate: t0 + chrono::Duration::milliseconds(delta_ms),
            method: method.into(),
            response_num: code,
            response_text: format!("{code}"),
            from_num: String::new(),
            to_num: String::new(),
            src_ip_str: String::new(),
            dst_ip_str: String::new(),
            direction: String::new(),
            content_type: String::new(),
            content: String::new(),
            cseq_num: None,
            cseq_method: None,
        }
    }

    #[test]
    fn render_sip_timeline_empty_yields_empty_string() {
        // The template uses the empty string as a "section omitted"
        // signal; don't accidentally render an empty <h2> for CDRs
        // with no sip_msg rows.
        assert_eq!(render_sip_timeline(&[]), "");
    }

    #[test]
    fn render_sip_timeline_paints_class_for_failed_invite() {
        let mk = |method: &str, code: u16| cdr::SipMessage {
            id: 1,
            calldate: chrono::NaiveDate::from_ymd_opt(2026, 9, 25)
                .unwrap()
                .and_hms_opt(14, 30, 0)
                .unwrap(),
            method: method.into(),
            response_num: code,
            response_text: format!("{code}"),
            from_num: "+49123".into(),
            to_num: "49199".into(),
            src_ip_str: "10.0.0.1".into(),
            dst_ip_str: "10.0.0.2".into(),
            direction: "out".into(),
            content_type: "application/sdp".into(),
            content: String::new(),
            cseq_num: None,
            cseq_method: None,
        };
        let html = render_sip_timeline(&[mk("INVITE", 200), mk("INVITE", 503)]);
        // First row: success — green 2xx class.
        assert!(html.contains(r#"class="num sip-2xx""#));
        // Second row: failure — red 5xx class + red 5xx method class.
        assert!(html.contains(r#"class="num sip-5xx""#));
    }

    #[test]
    fn seq_diagram_omitted_for_empty_messages() {
        assert_eq!(render_sngrep_flow(&[], None, None, "", "", None, None, "", ""), "");
    }

    #[test]
    fn seq_diagram_renders_one_row_per_message() {
        // INVITE / 100 / 200 / ACK / BYE / 200 — six messages, six rows.
        // Direction must be set explicitly; empty defaults to "out"
        // (m.direction != "in"), which would lump all messages into
        // the outgoing lane.
        let mut invite = mk_msg("INVITE", 0, 0.0); invite.direction = "out".into();
        let mut r100 = mk_msg("", 100, 0.1); r100.direction = "in".into();
        let mut r200a = mk_msg("", 200, 0.2); r200a.direction = "in".into();
        let mut ack = mk_msg("ACK", 0, 0.3); ack.direction = "out".into();
        let mut bye = mk_msg("BYE", 0, 5.0); bye.direction = "out".into();
        let mut r200b = mk_msg("", 200, 5.1); r200b.direction = "in".into();
        let msgs = vec![invite, r100, r200a, ack, bye, r200b];
        let html = render_sngrep_flow(&msgs, None, None, "", "", None, None, "", "");
        // Six message rows + two RTP-flow rows (one per direction) = 8 <tr> rows.
        assert_eq!(html.matches(r#"class="seq-row seq-row-"#).count(), 8);
        // 3 outgoing SIP + 1 outgoing RTP = 4 rows carrying seq-row-out.
        assert_eq!(html.matches(r" seq-row-out").count(), 4);
        // 3 incoming SIP + 1 incoming RTP = 4 rows carrying seq-row-in.
        assert_eq!(html.matches(r" seq-row-in").count(), 4);
        // Two RTP rows total (one per direction).
        assert_eq!(html.matches(r"seq-row-rtp").count(), 2);
    }

    #[test]
    fn seq_diagram_relative_time_offsets_in_each_row() {
        // Each row shows the time offset relative to the first message.
        let msgs = vec![
            mk_msg("INVITE", 0, 0.0),
            mk_msg("BYE", 0, 5.0),
        ];
        let html = render_sngrep_flow(&msgs, None, None, "", "", None, None, "", "");
        assert!(html.contains("+0.0s"));
        assert!(html.contains("+5.0s"));
    }

    #[test]
    fn seq_diagram_rtp_row_includes_codec_and_packet_counts() {
        // When the caller passes rtp_a / rtp_b info, the RTP row
        // surfaces it inline.
        let msgs = vec![
            mk_msg("INVITE", 0, 0.0),
            mk_msg("", 200, 0.5),
            mk_msg("ACK", 0, 0.6),
            mk_msg("BYE", 0, 5.0),
            mk_msg("", 200, 5.1),
        ];
        let html = render_sngrep_flow(
            &msgs,
            Some(6739),
            Some("G.722".into()),
            "10.101.1.1",
            "10.101.1.112",
            Some(6763),
            Some("G.722".into()),
            "10.101.1.112",
            "10.101.1.1",
        );
        assert!(html.contains("G.722"), "RTP row should show the codec");
        assert!(html.contains("6739 pkts"));
        assert!(html.contains("6763 pkts"));
    }

    #[test]
    fn seq_diagram_actor_headers_show_endpoint_ips() {
        // The header row labels caller / callee by their first-observed
        // IPs from the SIP message stream.
        let t0 = chrono::NaiveDate::from_ymd_opt(2026, 9, 29)
            .unwrap()
            .and_hms_opt(2, 9, 46)
            .unwrap();
        let mut invite = mk_msg("INVITE", 0, 0.0);
        invite.src_ip_str = "10.101.1.1".into();
        invite.dst_ip_str = "10.101.1.112".into();
        let html = render_sngrep_flow(&[invite], None, None, "", "", None, None, "", "");
        assert!(html.contains("caller"));
        assert!(html.contains("callee"));
        assert!(html.contains("10.101.1.1"));
        assert!(html.contains("10.101.1.112"));
        let _ = t0;
    }

    #[test]
    fn seq_diagram_arrow_direction_matches_message_direction() {
        // Outgoing messages get the right-arrow class; incoming get
        // the left-arrow class. The CSS uses this to colour and
        // style the arrow differently.
        let mut out = mk_msg("INVITE", 0, 0.0);
        out.direction = "out".into();
        let mut inc = mk_msg("", 200, 0.5);
        inc.direction = "in".into();
        let html = render_sngrep_flow(
            &[out, inc],
            None, None, "", "",
            None, None, "", "",
        );
        assert!(html.contains("seq-arrow-out"));
        assert!(html.contains("seq-arrow-in"));
    }
}
