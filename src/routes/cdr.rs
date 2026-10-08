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
        selected_src_ips: &[String],
        selected_dst_ips: &[String],
        selected_sip_codes: &[u16],
        selected_sensor_ids: &[u16],
    ) -> Self {
        // The selected-set comparison is by textual IP representation
        // (`"1.2.3.4"` or `"2001:db8::1"`) so the same string the
        // filter form submits matches the rendered distinct chip
        // regardless of which storage shape (legacy INT UNSIGNED vs
        // post-ipv6 VARBINARY) the DB has.
        let src_ips: Vec<DistinctItem> = d
            .src_ips
            .iter()
            .map(|v| DistinctItem {
                value: v.to_dotted_decimal(),
                is_checked: selected_src_ips.contains(&v.to_dotted_decimal()),
            })
            .collect();
        let dst_ips: Vec<DistinctItem> = d
            .dst_ips
            .iter()
            .map(|v| DistinctItem {
                value: v.to_dotted_decimal(),
                is_checked: selected_dst_ips.contains(&v.to_dotted_decimal()),
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
        crate::error::with_query_timeout(
            timeout,
            cdr::list(&state.pool, &normalized, *state.ip_shape),
        ),
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
            cdr::fetch_sip_messages(&state.pool, id, sipcallerip, 500, *state.ip_shape),
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
    //
    // Both sides are `IpAddr` now; compare by their canonical textual
    // representation so the dual-shape storage (legacy INT UNSIGNED
    // vs post-ipv6 VARBINARY) doesn't matter at the comparison site.
    if let Some(marker) = sipcallerip {
        let marker_str = marker.to_dotted_decimal();
        for m in sip_messages.iter_mut() {
            if m.direction.is_empty() {
                m.direction = if m.src_ip_str == marker_str {
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
  <p><a href="/" onclick="history.back(); return false;">&larr; back to list</a></p>
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
    <tr><th>spool_index</th><td>{spool_index} <span class="muted small">(tar.zst type bucket: 0=SIP, 1=RTP, …)</span></td></tr>
  </table>
  {custom_headers_html}
  {branches_html}
  {rtp_html}
  {rtp_chart_html}
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
        rtp_chart_html = render_rtp_chart_panel(id),
    );
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response())
}

/// JSON endpoint that drives the MOS / jitter timeline chart on
/// the CDR detail page. The chart's JS fetches this once on
/// page load, then renders two datasets (A→B leg, B→A leg)
/// with jitter on the left y-axis and MOS on the right.
///
/// The pcap extraction is the same pipeline that the SIP
/// timeline fallback uses — locate the tar.zst, decompress,
/// concat the SIP and RTP inner pcaps, parse RTP packets out
/// of the merged stream, bucket per second per direction,
/// return as JSON. We deliberately keep this endpoint
/// separate from `cdr_detail` so the chart's render isn't
/// coupled to the main page load — and a parse failure here
/// degrades gracefully (returns an empty chart) rather than
/// blanking the whole detail page.
pub async fn rtp_chart_json(
    State(state): State<crate::state::AppState>,
    _user: SessionUser,
    axum::extract::Path(id): axum::extract::Path<u64>,
) -> AppResult<Response> {
    // Fetch just the two IPs we need to split A→B from B→A.
    // Avoids a full CDR deserialise for what is essentially a
    // single-column lookup.
    let row = sqlx::query_as::<_, cdr::CdrRow>(
        &format!(
            "SELECT {} FROM cdr WHERE ID = ? LIMIT 1",
            cdr::CDR_FULL_SELECT_COLUMNS
        ),
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(crate::error::AppError::from)?;
    let row = match row {
        Some(r) => r,
        None => {
            // CDR not found — return empty payload so the
            // chart JS doesn't choke. 404 would be more
            // correct but the chart treats this as "no data"
            // and degrades gracefully.
            return Ok((
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                r#"{"a_to_b":[],"b_to_a":[]}"#,
            )
                .into_response());
        }
    };

    // Pull the pcap bytes; on failure return empty chart
    // (same reasoning as above — better than blanking the
    // whole page).
    let pcap_bytes = match crate::routes::pcap::build_pcap_bytes(&state, id).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(cdr_id = id, error = ?e, "rtp chart pcap extract failed");
            return Ok((
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                r#"{"a_to_b":[],"b_to_a":[]}"#,
            )
                .into_response());
        }
    };

    // Extract RTP packets, then bucket by direction and time.
    // Direction split: a packet belongs to A→B when its
    // source IP matches the CDR's sipcallerip (the A leg in
    // VoIPmonitor's convention), otherwise B→A.
    //
    // Both sides are now `IpAddr` (handles legacy `INT UNSIGNED` and
    // post-ipv6-alter `VARBINARY(16)` from the same code). Compare
    // by canonical textual form so the dual shape doesn't matter
    // at this site.
    let packets = cdr::rtp_pcap::parse_rtp_packets_from_pcap(&pcap_bytes);
    let caller_ip_str = row
        .sipcallerip
        .as_ref()
        .filter(|ip| !ip.is_unspecified_v4() && !ip.is_unspecified_v6())
        .map(|ip| ip.to_dotted_decimal());
    let called_ip_str = row
        .sipcalledip
        .as_ref()
        .filter(|ip| !ip.is_unspecified_v4() && !ip.is_unspecified_v6())
        .map(|ip| ip.to_dotted_decimal());
    let caller_ip: Option<std::net::IpAddr> = caller_ip_str
        .as_deref()
        .and_then(|s| s.parse().ok());
    let stats = cdr::rtp_pcap::compute_rtp_stats(
        packets,
        |src| {
            if Some(src.to_string()) == caller_ip_str {
                cdr::rtp_pcap::RtpDirection::AtoB
            } else {
                cdr::rtp_pcap::RtpDirection::BtoA
            }
        },
        1, // 1-second buckets
    );

    let json = serde_json::json!({
        "a_to_b": stats.a_to_b,
        "b_to_a": stats.b_to_a,
        "a_leg_label": caller_ip_str.unwrap_or_default(),
        "b_leg_label": called_ip_str.unwrap_or_default(),
    });
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json.to_string(),
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

    // Build the actor list. Start with caller + callee from the
    // first observed outgoing message's src/dst IPs, then add any
    // SDP-discovered media IPs (c= lines) that aren't already in
    // the list. This makes proxy / RTPEngine scenarios visible as
    // additional columns — e.g. caller → proxy → callee with the
    // proxy's IP showing up in SDP.
    let first = messages.iter().find(|m| !m.src_ip_str.is_empty());
    let (caller_ip, callee_ip) = first.map_or((String::new(), String::new()), |m| {
        (m.src_ip_str.clone(), m.dst_ip_str.clone())
    });
    let mut actors: Vec<String> = Vec::new();
    for ip in [&caller_ip, &callee_ip] {
        if !ip.is_empty() && !actors.iter().any(|a| a == ip) {
            actors.push(ip.clone());
        }
    }
    // Discover additional media endpoints from SDP bodies.
    for m in messages.iter() {
        for sdp_ip in cdr::parse_sdp_c_lines(&m.content) {
            if !actors.iter().any(|a| a == &sdp_ip) {
                actors.push(sdp_ip);
            }
        }
    }
    // Cap at 6 actors — beyond that the table becomes unreadable.
    actors.truncate(6);
    let actor_idx = |ip: &str| -> Option<usize> {
        actors.iter().position(|a| a == ip)
    };

    // Time axis: relative to the first message's timestamp.
    let t_min = messages.iter().map(|m| m.calldate).min().unwrap();

    // Build the actor box HTML used at the top AND bottom of the
    // diagram. Each box shows the actor's letter label (A/B/C…)
    // plus its IP below — matches the classic UML sequence-diagram
    // idiom from sip-diagrams.netlify.app where the actor has a
    // small box at both ends of its lifeline.
    let actor_boxes: Vec<String> = actors
        .iter()
        .enumerate()
        .map(|(i, ip)| {
            let role = if i == 0 {
                "caller"
            } else if i == actors.len() - 1 {
                "callee"
            } else {
                "media"
            };
            // Letter label: A, B, C, … (skip I/O for legibility).
            let letter = ((b'A' + i as u8) as char).to_string();
            format!(
                "<div class=\"seq-actor-box\" data-role=\"{role}\">\
                   <div class=\"seq-actor-letter\">{letter}</div>\
                   <div class=\"seq-actor-ip\">{ip}</div>\
                 </div>",
                ip = html_escape(ip)
            )
        })
        .collect();

    // Build the top + bottom actor rows. The structure mirrors
    // a UML sequence diagram: time | actor_A | message lane |
    // actor_B (rather than time | actor_A | actor_B | message
    // lane). Putting the msg cell in the MIDDLE keeps the
    // leftmost / rightmost actors anchored to the table edges
    // with the signaling lane between them — matching the
    // sngrep / sip-diagrams.netlify.app layout. For N>2 actors
    // the message lane is centred between actor 0 and actor N-1
    // with the additional actors arranged symmetrically inside.
    //
    // Specifically the row order is:
    //   time | actor_0 | msg-cell | actor_1 | actor_2 | ... | actor_{N-1}
    // i.e. msg-cell goes right after the first actor, with the
    // remaining actors trailing to the right. With N=1 the
    // msg-cell goes after actor 0 and the rightmost actor
    // coincides with the lane edge — still readable.
    let n = actors.len();
    let first_actor_html = if n > 0 {
        format!(
            "<td class=\"seq-actor-cell\" data-actor-idx=\"0\">{}</td>",
            actor_boxes[0]
        )
    } else {
        String::new()
    };
    let rest_actors_html: String = (1..n)
        .map(|i| format!(
            "<td class=\"seq-actor-cell\" data-actor-idx=\"{i}\">{}</td>",
            actor_boxes[i]
        ))
        .collect();
    let actor_top_row = format!(
        "<tr class=\"seq-actor-row seq-actor-top\">\
           <td class=\"seq-time-cell\"></td>{first}\
           <td class=\"seq-msg-cell seq-msg-header\"></td>{rest}\
         </tr>",
        first = first_actor_html,
        rest = rest_actors_html,
    );
    let actor_bottom_row = format!(
        "<tr class=\"seq-actor-row seq-actor-bottom\">\
           <td class=\"seq-time-cell\"></td>{first}\
           <td class=\"seq-msg-cell seq-msg-header\"></td>{rest}\
         </tr>",
        first = first_actor_html,
        rest = rest_actors_html,
    );

    // Walk messages, emitting one <tr> per row. Each row's cells are
    //   time | actor[0] arrow | actor[1] arrow | ... | actor[N-1] arrow
    // For an outgoing message from src→dst, we put a small "──►"
    // in the cell of the actor closest to src, and the "method/code"
    // in the LAST actor's cell (the destination side). Incoming
    // messages are mirrored. The arrow's color (blue for out,
    // amber for in) matches the conventional caller/callee
    // styling.
    let mut rows: Vec<String> = Vec::with_capacity(messages.len() + 2);
    let mut media_started = false;
    let mut media_inserted = false;
    // Track the time of the last 2xx/ACK — that's when media
    // actually starts flowing. RTP rows use this as their time
    // stamp instead of the surrounding BYE's time (which is when
    // media STOPS, not when it's "active").
    let mut media_start_time: Option<String> = None;

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

        let title = format!(
            "{} {} {} → {} @ {}",
            m.method,
            m.response_text,
            html_escape(&m.src_ip_str),
            html_escape(&m.dst_ip_str),
            m.calldate.format("%H:%M:%S%.3f"),
        );

        // Build the message row in the new UML sequence-diagram
        // format: time | actor cell (lifeline only) | ... | actor
        // cell (lifeline only). The arrow + method/code label live
        // in a single cell that spans the entire message lane,
        // with the arrow drawn via CSS so it spans from the source
        // lifeline to the destination lifeline.
        let src_idx = actor_idx(&m.src_ip_str);
        let dst_idx = actor_idx(&m.dst_ip_str);
        // Self-loop (src == dst) renders as a self-pointing arrow
        // on its own lifeline — same as a normal message except
        // the arrow is shorter and doesn't cross any other
        // lifeline.
        let is_self_loop = Some(src_idx) == Some(dst_idx) && src_idx.is_some();
        let arrow_dir = if is_self_loop {
            "self"
        } else if is_out {
            "out"
        } else {
            "in"
        };
        let label = if m.method.is_empty() {
            // Response code only: "100", "200 OK", "487 Request
            // Terminated", etc.
            if m.response_num > 0 {
                format!(
                    "<span class=\"seq-code {code_class}\">{}</span> {}",
                    m.response_num,
                    html_escape(&m.response_text)
                )
            } else {
                String::new()
            }
        } else if m.response_num > 0 {
            // Method + response code: "INVITE / 200 OK".
            format!(
                "<span class=\"seq-method {method_class}\">{}</span>\
                 <span class=\"seq-method-sep\"> / </span>\
                 <span class=\"seq-code {code_class}\">{}</span> {}",
                html_escape(&m.method),
                m.response_num,
                html_escape(&m.response_text)
            )
        } else {
            // Method only (request).
            format!(
                "<span class=\"seq-method {method_class}\">{}</span>",
                html_escape(&m.method)
            )
        };
        let n = actors.len();
        let mut cells: Vec<String> = Vec::with_capacity(n + 2);
        cells.push(format!(
            "<td class=\"seq-time-cell\">{}</td>",
            rel_time
        ));
        // Push the first actor's lifeline cell (A), then the
        // spanning msg-cell, then the remaining actor cells (B,
        // C, …). This keeps actor 0 anchored to the left edge
        // and actor N-1 anchored to the right edge of the table,
        // with the signaling lane centred between them.
        if n > 0 {
            cells.push(format!(
                "<td class=\"seq-actor-cell\" data-actor-idx=\"0\"></td>"
            ));
        }
        let arrow_class = match arrow_dir {
            "out" => "seq-arrow-out",
            "in" => "seq-arrow-in",
            _ => "seq-arrow-self",
        };
        // The msg-cell sits in the middle of the table (between
        // actor 0 and the rest). The CSS-drawn arrow inside uses
        // negative horizontal margins so it visually spans from
        // the left-most lifeline to the right-most lifeline —
        // matching the sngrep / sip-diagrams idiom where the
        // arrowhead lands on the destination lifeline.
        let msg_cell = format!(
            "<td class=\"seq-msg-cell\" data-msg-dir=\"{arrow_dir}\">\
               <div class=\"seq-msg-label\">{label}</div>\
               <div class=\"seq-arrow {arrow_cls}\"></div>\
             </td>",
            arrow_cls = arrow_class,
        );
        cells.push(msg_cell);
        for i in 1..n {
            cells.push(format!(
                "<td class=\"seq-actor-cell\" data-actor-idx=\"{i}\"></td>"
            ));
        }
        let sip_row_html = format!(
            "<tr class=\"seq-row seq-row-{}\" title=\"{}\">{}</tr>",
            arrow_dir,
            title,
            cells.join(""),
        );

        // Track when media becomes active (first 2xx / ACK). The RTP
        // rows are inserted at this point — between the last 2xx/ACK
        // and the first BYE/CANCEL — to show the media stream while
        // it's actually flowing, not after the call has been torn
        // down. The time stamp for the RTP row is the last 2xx/ACK
        // message's time offset (the moment media starts flowing),
        // not the BYE's time which is when media stops.
        if !media_started {
            let ack_or_2xx =
                (!m.method.is_empty() && m.method == "ACK") ||
                (m.response_num >= 200 && m.response_num < 300);
            if ack_or_2xx {
                media_started = true;
                media_start_time = Some(rel_time.clone());
            }
        }
        // Insert RTP rows right before the first BYE/CANCEL after
        // media. Push them BEFORE the current SIP row so they
        // visually appear above the BYE in the timeline (matching
        // the sngrep / Wireshark layout where the media stream is
        // shown between setup and teardown, not after teardown).
        if media_started && !media_inserted && (m.method == "BYE" || m.method == "CANCEL") {
            let rtp_time = media_start_time.as_deref().unwrap_or(&rel_time);
            rows.push(rtp_row_html(
                rtp_time,
                rtp_a_pkts,
                rtp_a_codec.as_deref(),
                rtp_a_src,
                rtp_a_dst,
                rtp_b_pkts,
                rtp_b_codec.as_deref(),
                rtp_b_src,
                rtp_b_dst,
                actors.len(),
            ));
            media_inserted = true;
        }
        rows.push(sip_row_html);
    }
    if media_started && !media_inserted {
        // No teardown message (call was abandoned without BYE);
        // append the RTP rows after the last media-bearing message
        // and stamp them with that message's time offset.
        let last_offset_ms = messages
            .last()
            .map(|m| (m.calldate - t_min).num_milliseconds())
            .unwrap_or(0);
        let last_time = format!("+{:.1}s", last_offset_ms as f64 / 1000.0);
        rows.push(rtp_row_html(
            &last_time,
            rtp_a_pkts,
            rtp_a_codec.as_deref(),
            rtp_a_src,
            rtp_a_dst,
            rtp_b_pkts,
            rtp_b_codec.as_deref(),
            rtp_b_src,
            rtp_b_dst,
            actors.len(),
        ));
    }

    let total = messages.len();
    let n_actors = actors.len();

    format!(
        "<h2>Call flow</h2>\
         <p class=\"muted small\">\
           {total} SIP messages across {n_actors} actor{s}, time top-to-bottom. \
           Outgoing solid blue arrows, incoming dashed amber arrows. \
           Additional actors discovered from SDP c= lines (proxy / media relay).\
         </p>\
         <div class=\"seq-diagram\">\
           <table class=\"seq-table\">\
             <tbody>\
               {actor_top_row}\
               {rows}\
               {actor_bottom_row}\
             </tbody>\
           </table>\
         </div>",
        s = if n_actors == 1 { "" } else { "s" },
        rows = rows.join("\n"),
    )
}

/// Render the RTP-flow rows that live between the last 2xx/ACK and
/// the first BYE. One row per direction with the actual RTP
/// endpoints. Each row uses the same UML sequence-diagram shape as
/// a SIP message row — a single spanning cell with the codec +
/// packet-count label above a CSS-drawn arrow that spans from the
/// source lifeline to the destination lifeline. The arrow's
/// direction (left/right) and style (solid for outgoing, dashed
/// for incoming) follows the same convention as the SIP rows.
fn rtp_row_html(
    time_label: &str,
    a_pkts: Option<u32>,
    a_codec: Option<&str>,
    a_src: &str,
    a_dst: &str,
    b_pkts: Option<u32>,
    b_codec: Option<&str>,
    b_src: &str,
    b_dst: &str,
    n_actors: usize,
) -> String {
    let a_codec = a_codec.unwrap_or("").trim();
    let b_codec = b_codec.unwrap_or("").trim();
    // The codec field carries the descriptive form from
    // codec_name_from_pt() — e.g. "PCMA (G.711 A-law)". For the
    // compact flow-row display we want just the short token
    // ("PCMA") that fits on one line alongside the packet count.
    fn short_codec(s: &str) -> &str {
        // Take everything before the first " (" or "(".
        match s.find(" (") {
            Some(i) => &s[..i],
            None => s,
        }
    }
    let codec = if !a_codec.is_empty() {
        short_codec(a_codec).to_string()
    } else if !b_codec.is_empty() {
        short_codec(b_codec).to_string()
    } else {
        "RTP".to_string()
    };
    let a_count = a_pkts
        .map(|n| format!("{} pkts", n))
        .unwrap_or_else(|| "—".to_string());
    let b_count = b_pkts
        .map(|n| format!("{} pkts", n))
        .unwrap_or_else(|| "—".to_string());

    fn build_rtp_row(
        codec: &str,
        count: &str,
        src_ip: &str,
        dst_ip: &str,
        time_label: &str,
        n_actors: usize,
        is_out: bool,
        title: &str,
    ) -> String {
        let arrow_class = if is_out { "seq-arrow-out" } else { "seq-arrow-in" };
        let dir_attr = if is_out { "out" } else { "in" };
        let label = format!(
            "<span class=\"seq-rtp-codec\">{codec}</span>\
             <span class=\"seq-rtp-count\">{count}</span>\
             <div class=\"seq-rtp-endpoints muted small\">{src} → {dst}</div>",
            src = html_escape(src_ip),
            dst = html_escape(dst_ip),
        );
        let mut cells = format!(
            "<td class=\"seq-time-cell\">{time_label}</td>"
        );
        // Push actor 0's lifeline cell, then the spanning
        // msg-cell, then the remaining actor cells. Keeps the
        // leftmost actor anchored to the left edge and the
        // rightmost actor anchored to the right edge — see the
        // SIP-message loop for the matching structure.
        if n_actors > 0 {
            cells.push_str(&format!(
                "<td class=\"seq-actor-cell\" data-actor-idx=\"0\"></td>"
            ));
        }
        let msg_cell = format!(
            "<td class=\"seq-msg-cell\" data-msg-dir=\"{dir}\">\
               <div class=\"seq-msg-label\">{label}</div>\
               <div class=\"seq-arrow {arrow_cls}\"></div>\
             </td>",
            dir = dir_attr,
            arrow_cls = arrow_class,
        );
        cells.push_str(&msg_cell);
        for i in 1..n_actors {
            cells.push_str(&format!(
                "<td class=\"seq-actor-cell\" data-actor-idx=\"{i}\"></td>"
            ));
        }
        format!(
            "<tr class=\"seq-row seq-row-{dir} seq-row-rtp\" title=\"{title}\">{cells}</tr>",
            dir = dir_attr,
            title = title,
            cells = cells,
        )
    }

    let outgoing_title = format!(
        "RTP outgoing: {src} → {dst} ({codec}, {count})",
        src = a_src,
        dst = a_dst,
        codec = codec,
        count = a_count,
    );
    let incoming_title = format!(
        "RTP incoming: {src} → {dst} ({codec}, {count})",
        src = b_src,
        dst = b_dst,
        codec = codec,
        count = b_count,
    );

    let outgoing = build_rtp_row(
        &codec,
        &a_count,
        a_src,
        a_dst,
        time_label,
        n_actors,
        true,
        &outgoing_title,
    );
    let incoming = build_rtp_row(
        &codec,
        &b_count,
        b_src,
        b_dst,
        time_label,
        n_actors,
        false,
        &incoming_title,
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
/// Render the MOS / jitter timeline chart panel — a server-
/// rendered container with a `<canvas>` and a tiny inline
/// `<script>` that fetches the chart data and draws it via
/// Chart.js. Lazy-loads Chart.js itself from a CDN on first
/// use so the chart's bytes don't block the rest of the page
/// on every detail view (the call flow + RTP stats panels
/// above render server-side and don't depend on JS).
///
/// The chart has two y-axes: jitter (ms) on the left, MOS
/// (1.0..=5.0) on the right. Per-direction (A→B, B→A)
/// rendered as two datasets so the operator can compare
/// upstream vs downstream behaviour at a glance — the
/// classic "is it the network or the codec?" question.
///
/// The JS body is held as a module-level const so the
/// format!() call only has to interpolate the one CDR ID,
/// not the whole script — easier to read in the source AND
/// dodges the `{` / `}` escaping mess of inlining JS in
/// format!().
const RTP_CHART_JS: &str = r#"
(function() {
  const cdrId = __CDR_ID__;
  const canvas = document.getElementById('rtp-chart');
  const empty = document.getElementById('rtp-chart-empty');
  function loadChartJs() {
    return new Promise(function(resolve, reject) {
      if (window.Chart) return resolve();
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/chart.js@4';
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    });
  }
  function bucketSeries(buckets, key) {
    return buckets.map(function(b) {
      return { x: b.time_offset_secs, y: b[key] };
    });
  }
  loadChartJs()
    .then(function() { return fetch('/cdr/' + cdrId + '/rtp-chart.json'); })
    .then(function(r) { return r.ok ? r.json() : null; })
    .then(function(data) {
      if (!data || (!data.a_to_b.length && !data.b_to_a.length)) {
        canvas.hidden = true;
        empty.hidden = false;
        return;
      }
      new Chart(canvas, {
        type: 'line',
        data: {
          datasets: [
            {
              label: 'Jitter A->B (ms)',
              data: bucketSeries(data.a_to_b, 'jitter_ms'),
              borderColor: '#60a5fa',
              backgroundColor: 'rgba(96,165,250,0.1)',
              yAxisID: 'y',
              tension: 0.2,
              pointRadius: 0,
            },
            {
              label: 'Jitter B->A (ms)',
              data: bucketSeries(data.b_to_a, 'jitter_ms'),
              borderColor: '#fbbf24',
              backgroundColor: 'rgba(251,191,36,0.1)',
              yAxisID: 'y',
              borderDash: [4, 3],
              tension: 0.2,
              pointRadius: 0,
            },
            {
              label: 'MOS A->B',
              data: bucketSeries(data.a_to_b, 'mos'),
              borderColor: '#4ade80',
              yAxisID: 'y1',
              tension: 0.2,
              pointRadius: 0,
            },
            {
              label: 'MOS B->A',
              data: bucketSeries(data.b_to_a, 'mos'),
              borderColor: '#a3e635',
              yAxisID: 'y1',
              borderDash: [4, 3],
              tension: 0.2,
              pointRadius: 0,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          interaction: { mode: 'index', intersect: false },
          scales: {
            x: {
              type: 'linear',
              title: { display: true, text: 'time (s from call start)' },
            },
            y: {
              position: 'left',
              title: { display: true, text: 'jitter (ms)' },
              beginAtZero: true,
            },
            y1: {
              position: 'right',
              title: { display: true, text: 'MOS LQO' },
              min: 1,
              max: 5,
              grid: { drawOnChartArea: false },
            },
          },
          plugins: {
            legend: { labels: { color: '#e6e9ef' } },
            tooltip: {
              callbacks: {
                title: function(items) {
                  const t = items[0].parsed.x;
                  return '+' + t.toFixed(1) + 's';
                },
              },
            },
          },
        },
      });
    })
    .catch(function(e) {
      console.warn('rtp chart load failed', e);
      canvas.hidden = true;
      empty.hidden = false;
      empty.textContent = 'Chart load failed — see browser console.';
    });
})();
"#;

fn render_rtp_chart_panel(cdr_id: u64) -> String {
    let js = RTP_CHART_JS.replace("__CDR_ID__", &cdr_id.to_string());
    format!(
        "<h2>Media timeline</h2>\
         <p class=\"muted small\">\
           Per-second jitter (RFC 3550 smoothed) and MOS estimate\
           computed from the on-disk RTP pcap. Fetched lazily — no\
           blocking cost on initial page load.\
         </p>\
         <div class=\"rtp-chart-container\">\
           <canvas id=\"rtp-chart\" height=\"240\" aria-label=\"RTP jitter / MOS timeline\"></canvas>\
           <p id=\"rtp-chart-empty\" class=\"muted small\" hidden>\
             No RTP packets found in the on-disk pcap archive.\
           </p>\
         </div>\
         <script>{js}</script>",
        js = js,
    )
}

/// Render the SIP message timeline as a collapsible list. Each row:
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

/// Cap for the POST `/cdr/export.csv` batch path (ids or filter).
/// Matches `BATCH_MAX` in `routes::pcap` — same 100-row ceiling so the
/// operator's mental model ("zip / csv of selected / all matching") has
/// one consistent limit.
const CSV_BATCH_MAX: usize = 100;

/// Request body for `POST /cdr/export.csv`. Mirrors `BatchPcapRequest`
/// shape — the JS frontend uses the same `{ids, filter}` JSON for both
/// the bulk pcap zip and the bulk CSV download buttons.
///
/// Exactly one of two modes:
///   * `ids`    — explicit list of CDR IDs (per-row selection in the
///                UI, persisted in the session cookie).
///   * `filter` — raw URL-encoded query string mirroring the CDR list
///                page's filter form. Resolved server-side to all
///                matching CDR IDs (capped at `CSV_BATCH_MAX`).
///
/// Both fields are optional but at least one must produce a non-empty
/// result, otherwise we 400.
#[derive(serde::Deserialize)]
pub struct BatchCsvRequest {
    #[serde(default)]
    pub ids: Vec<u64>,
    #[serde(default)]
    pub filter: Option<String>,
}

/// CSV header bytes — sent once at the top of every CSV response.
const CSV_HEADER: &[u8] =
    b"id,calldate,callend,duration,caller,called,last_sip,mos,id_sensor\n";

/// Build the streaming CSV `Response` from a `Vec<CdrSummary>` (already
/// resolved + in output order). The summaries are formatted into rows
/// on a worker task and pushed into the response body via an mpsc;
/// `format_csv_line` is the shared per-row formatter.
///
/// No timeout here: the caller (POST batch or GET filter) is expected
/// to have already bounded the work. The GET filter path keeps its own
/// first-row timeout because `list_stream` can hang on a slow DB.
fn build_csv_response(summaries: Vec<CdrSummary>, cap: usize) -> AppResult<Response> {
    let (csv_tx, csv_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        if csv_tx.send(Ok(Bytes::from_static(CSV_HEADER))).await.is_err() {
            return;
        }
        let mut sent = 0usize;
        for s in summaries {
            let line = format_csv_line(&s);
            if csv_tx.send(Ok(Bytes::from(line))).await.is_err() {
                break; // client disconnected
            }
            sent += 1;
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
    let mut row_stream = cdr::list_stream(&state.pool, &normalized, cap, *state.ip_shape);

    // Channel of formatted CSV byte chunks for the HTTP response.
    let (csv_tx, csv_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);

    tokio::spawn(async move {
        // Header row first.
        if csv_tx.send(Ok(Bytes::from_static(CSV_HEADER))).await.is_err() {
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
                    let line = format_csv_line(&summary);
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

/// Bulk CSV export — `POST /cdr/export.csv`. Mirrors the
/// `/pcap/batch` shape (`{ids, filter}` JSON) so the same
/// selection-clearing / cross-page checkbox state drives both
/// downloads.
///
/// Resolves the request to a concrete list of CDR IDs (cap = 100),
/// fetches each in a single SQL roundtrip via `fetch_by_ids`, then
/// streams them out as CSV. IDs not in the DB are silently skipped
/// (a deleted CDR in the middle of a session-cookie selection isn't
/// a hard error — the operator still gets the rows that do exist).
pub async fn cdr_export_csv_batch(
    State(state): State<AppState>,
    _user: SessionUser,
    axum::Json(req): axum::Json<BatchCsvRequest>,
) -> AppResult<Response> {
    // Same ids-vs-filter precedence rule as the pcap batch: explicit
    // IDs win over a filter if both come in. Empty both → 400.
    let cdr_ids: Vec<u64> = if !req.ids.is_empty() {
        let mut seen = std::collections::HashSet::with_capacity(req.ids.len());
        let mut out = Vec::with_capacity(req.ids.len());
        for &id in &req.ids {
            if id > 0 && seen.insert(id) {
                out.push(id);
            }
        }
        out
    } else if let Some(filter) = req.filter.as_deref() {
        let tz = state.tz_default();
        cdr::ids_for_query_string(&state.pool, filter, tz, CSV_BATCH_MAX, *state.ip_shape).await?
    } else {
        return Err(AppError::BadRequest(
            "either `ids` or `filter` must be provided".into(),
        ));
    };

    if cdr_ids.is_empty() {
        return Err(AppError::BadRequest(
            "no CDRs matched the request".into(),
        ));
    }

    if cdr_ids.len() > CSV_BATCH_MAX {
        tracing::warn!(
            requested = cdr_ids.len(),
            cap = CSV_BATCH_MAX,
            "CSV batch export exceeds cap; truncating"
        );
    }
    let cdr_ids = &cdr_ids[..cdr_ids.len().min(CSV_BATCH_MAX)];

    // Single SQL roundtrip, then preserve input order — the operator
    // expects the CSV rows to follow the order they ticked.
    let by_id = cdr::fetch_by_ids(&state.pool, cdr_ids).await?;
    let mut summaries: Vec<CdrSummary> = Vec::with_capacity(cdr_ids.len());
    for &id in cdr_ids {
        if let Some(s) = by_id.get(&id) {
            summaries.push(s.clone());
        } else {
            tracing::warn!(cdr_id = id, "CSV batch: CDR not found, skipping");
        }
    }

    if summaries.is_empty() {
        return Err(AppError::BadRequest(
            "none of the requested CDRs exist in the database".into(),
        ));
    }

    build_csv_response(summaries, CSV_BATCH_MAX)
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

/// Format one CDR as a single CSV data row (without trailing CR — `\n`
/// only). Used by both the streaming GET filter export and the POST
/// batch (ids or filter) export. Pure function — easy to unit-test
/// without spinning up a DB.
fn format_csv_line(s: &CdrSummary) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{}\n",
        s.id,
        s.calldate.format("%Y-%m-%d %H:%M:%S"),
        s.callend.format("%Y-%m-%d %H:%M:%S"),
        s.duration.unwrap_or(0),
        csv_field(&s.caller),
        csv_field(&s.called),
        s.last_sip_response_num.unwrap_or(0),
        s.mos_str,
        s.id_sensor.unwrap_or(0),
    )
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
        // Set src/dst IPs so the actor list is non-empty (the new
        // sequence-diagram layout needs at least 2 actors).
        for m in [&mut invite, &mut r100, &mut r200a, &mut ack, &mut bye, &mut r200b] {
            m.src_ip_str = "10.0.0.1".into();
            m.dst_ip_str = "10.0.0.2".into();
        }
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
        // surfaces it inline. Need src/dst IPs on the messages so
        // the renderer can build the actor list — the codec + packet
        // count live inside the per-actor cells.
        let mut invite = mk_msg("INVITE", 0, 0.0);
        invite.src_ip_str = "10.101.1.1".into();
        invite.dst_ip_str = "10.101.1.112".into();
        let mut ok = mk_msg("", 200, 0.5);
        ok.src_ip_str = "10.101.1.112".into();
        ok.dst_ip_str = "10.101.1.1".into();
        let mut ack = mk_msg("ACK", 0, 0.6);
        ack.src_ip_str = "10.101.1.1".into();
        ack.dst_ip_str = "10.101.1.112".into();
        let mut bye = mk_msg("BYE", 0, 5.0);
        bye.src_ip_str = "10.101.1.1".into();
        bye.dst_ip_str = "10.101.1.112".into();
        let mut bye_ok = mk_msg("", 200, 5.1);
        bye_ok.src_ip_str = "10.101.1.112".into();
        bye_ok.dst_ip_str = "10.101.1.1".into();
        let html = render_sngrep_flow(
            &[invite, ok, ack, bye, bye_ok],
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
        // style the arrow differently. Need src/dst IPs set so the
        // renderer can place the arrow in the right actor cell.
        let mut out = mk_msg("INVITE", 0, 0.0);
        out.direction = "out".into();
        out.src_ip_str = "10.0.0.1".into();
        out.dst_ip_str = "10.0.0.2".into();
        let mut inc = mk_msg("", 200, 0.5);
        inc.direction = "in".into();
        inc.src_ip_str = "10.0.0.2".into();
        inc.dst_ip_str = "10.0.0.1".into();
        let html = render_sngrep_flow(
            &[out, inc],
            None, None, "", "",
            None, None, "", "",
        );
        assert!(html.contains("seq-arrow-out"));
        assert!(html.contains("seq-arrow-in"));
    }

    #[test]
    fn seq_diagram_method_text_appears_only_once_per_row() {
        // In the new UML sequence-diagram layout each message row
        // has a single spanning `seq-msg-cell` carrying the label
        // (method/code) plus the CSS-drawn arrow. So the test
        // asserts exactly one `seq-msg-label` per message row.
        let mut out = mk_msg("INVITE", 0, 0.0);
        out.direction = "out".into();
        out.src_ip_str = "10.0.0.1".into();
        out.dst_ip_str = "10.0.0.2".into();
        let html = render_sngrep_flow(
            &[out],
            None, None, "", "",
            None, None, "", "",
        );
        assert_eq!(
            html.matches("seq-msg-label").count(),
            1,
            "method/code label should appear in exactly one msg-cell per row"
        );
    }

    #[test]
    fn seq_diagram_rtp_rows_appear_before_bye_not_after() {
        // Regression: the media flow should be shown between
        // setup and teardown, not stacked under the BYE/200 OK to
        // BYE exchange. The renderer has to push the RTP rows
        // BEFORE the BYE row to keep the timeline ordering.
        let mut invite = mk_msg("INVITE", 0, 0.0);
        invite.src_ip_str = "10.0.0.1".into();
        invite.dst_ip_str = "10.0.0.2".into();
        let mut ok = mk_msg("", 200, 0.5);
        ok.src_ip_str = "10.0.0.2".into();
        ok.dst_ip_str = "10.0.0.1".into();
        let mut ack = mk_msg("ACK", 0, 0.6);
        ack.src_ip_str = "10.0.0.1".into();
        ack.dst_ip_str = "10.0.0.2".into();
        let mut bye = mk_msg("BYE", 0, 5.0);
        bye.src_ip_str = "10.0.0.1".into();
        bye.dst_ip_str = "10.0.0.2".into();
        let mut bye_ok = mk_msg("", 200, 5.1);
        bye_ok.src_ip_str = "10.0.0.2".into();
        bye_ok.dst_ip_str = "10.0.0.1".into();
        let html = render_sngrep_flow(
            &[invite, ok, ack, bye, bye_ok],
            Some(6739),
            Some("PCMA (G.711 A-law)".into()),
            "10.0.0.1",
            "10.0.0.2",
            Some(6763),
            Some("PCMA (G.711 A-law)".into()),
            "10.0.0.2",
            "10.0.0.1",
        );
        // The compact codec form (no parenthetical) is what lands
        // in the rendered HTML — make sure both the long form's
        // tail ("G.711 A-law)") is stripped AND the row layout
        // puts RTP before BYE. The codec and count are wrapped in
        // separate <span>s in the new layout, so check for the
        // codec token + count token near each other.
        assert!(
            html.contains("PCMA"),
            "RTP row should include the short codec token"
        );
        assert!(
            html.contains("6739 pkts"),
            "RTP row should show the A-leg packet count"
        );
        assert!(
            html.contains("6763 pkts"),
            "RTP row should show the B-leg packet count"
        );
        assert!(
            !html.contains("G.711 A-law"),
            "RTP row should NOT include the parenthetical codec description"
        );
        let rtp_pos = html.find("seq-row-rtp").expect("RTP row missing");
        let bye_pos = html
            .find(">BYE<")
            .or_else(|| html.find("&gt;BYE&lt;"))
            .expect("BYE row missing");
        assert!(
            rtp_pos < bye_pos,
            "RTP row must appear BEFORE the BYE row in the timeline"
        );
    }
}

#[cfg(test)]
mod csv_tests {
    //! Pure-function tests for the CSV exporter helpers. The
    //! streaming Response builder needs a tokio runtime + axum
    //! routing infra to exercise end-to-end, so it stays in the
    //! manual smoke-test path — these tests cover the parts that
    //! actually contain formatting logic.

    use super::*;
    use crate::cdr::{CdrSummary, RtpLeg};

    /// Build a minimal `CdrSummary` for the tests. Only the fields
    /// `format_csv_line` actually reads are populated; everything
    /// else gets `Default::default()`.
    fn mk_summary(id: u64, caller: Option<&str>, called: Option<&str>) -> CdrSummary {
        let calldate = chrono::NaiveDate::from_ymd_opt(2026, 9, 25)
            .unwrap()
            .and_hms_opt(14, 30, 0)
            .unwrap();
        CdrSummary {
            id,
            calldate,
            callend: calldate + chrono::Duration::seconds(42),
            duration: Some(42),
            connect_duration: None,
            caller: caller.map(String::from),
            callername: None,
            called: called.map(String::from),
            src_ip_str: "10.0.0.1".into(),
            dst_ip_str: "10.0.0.2".into(),
            last_sip_response_num: Some(200),
            mos_str: "4.2".into(),
            a_lost: Some(0),
            b_lost: Some(2),
            id_sensor: Some(1),
            rtp_a: RtpLeg::default(),
            rtp_b: RtpLeg::default(),
        }
    }

    #[test]
    fn csv_field_escapes_quotes_commas_and_newlines() {
        assert_eq!(csv_field(&None), "");
        assert_eq!(csv_field(&Some("plain".into())), "plain");
        // Comma must trigger quoting (otherwise the column count breaks).
        assert_eq!(csv_field(&Some("a,b".into())), "\"a,b\"");
        // Embedded double-quote → doubled-up inside the surrounding quotes.
        assert_eq!(csv_field(&Some("a\"b".into())), "\"a\"\"b\"");
        // Newline must also be quoted — Excel treats a bare \n as a
        // record terminator inside an unquoted field.
        assert_eq!(csv_field(&Some("a\nb".into())), "\"a\nb\"");
    }

    #[test]
    fn format_csv_line_emits_one_record_per_summary() {
        let s = mk_summary(123, Some("+15551234567"), Some("+15559876543"));
        let line = format_csv_line(&s);
        assert_eq!(
            line,
            "123,2026-09-25 14:30:00,2026-09-25 14:30:42,42,+15551234567,+15559876543,200,4.2,1\n"
        );
    }

    #[test]
    fn format_csv_line_handles_missing_optional_fields() {
        // CDR with no caller, no called, no MOS, no sensor. The
        // CSV row should still have the right number of columns.
        let mut s = mk_summary(7, None, None);
        s.last_sip_response_num = None;
        s.mos_str = String::new();
        s.id_sensor = None;
        let line = format_csv_line(&s);
        // 9 columns: id, calldate, callend, duration, caller, called,
        // last_sip, mos, id_sensor — even with all optionals empty.
        // Note: `mos_str` is rendered as an empty cell (None-like),
        // while numeric optionals (`last_sip_response_num`, `id_sensor`)
        // fall back to 0 via `unwrap_or(0)`. That's the contract both
        // the GET streaming path and the POST batch path share.
        assert_eq!(line.split(',').count(), 9);
        // Numeric optionals (`last_sip_response_num`, `id_sensor`) fall
        // back to 0 via `unwrap_or(0)`. That's the contract both the GET
        // streaming path and the POST batch path share.
        assert!(line.contains(",0,,"), "last_sip falls back to 0, mos is empty");
        assert!(line.ends_with(",0\n"), "sensor column falls back to 0");
    }

    #[test]
    fn format_csv_line_quotes_caller_with_comma() {
        // Real CDR data has callers like "John, Jr." — the CSV has
        // to escape them so they don't break column alignment.
        let s = mk_summary(1, Some("Doe, John"), Some("Smith, Jane"));
        let line = format_csv_line(&s);
        assert!(
            line.contains("\"Doe, John\""),
            "caller with comma must be quoted: {line}"
        );
        assert!(
            line.contains("\"Smith, Jane\""),
            "called with comma must be quoted: {line}"
        );
    }

    #[test]
    fn csv_header_is_a_single_static_line() {
        // The constant is referenced by every CSV-emitting code
        // path; if it ever drifts (e.g. someone adds a column),
        // both the GET streaming path and the POST batch path need
        // to be updated in lockstep. This test pins the shape so
        // the drift is loud.
        assert_eq!(
            std::str::from_utf8(CSV_HEADER).unwrap().trim_end(),
            "id,calldate,callend,duration,caller,called,last_sip,mos,id_sensor"
        );
        assert!(CSV_HEADER.ends_with(b"\n"));
    }

    /// Sanity: the `BatchCsvRequest` deserialises from the JS
    /// frontend's exact JSON shape. We don't construct one via axum
    /// here (that needs the full router) — just exercise serde to
    /// guard against a rename of the field name breaking the wire
    /// contract silently.
    #[test]
    fn batch_csv_request_deserialises_js_payload_shape() {
        let by_ids: BatchCsvRequest = serde_json::from_str(
            r#"{"ids":[1,2,3],"filter":null}"#,
        )
        .expect("ids payload must deserialise");
        assert_eq!(by_ids.ids, vec![1, 2, 3]);
        assert_eq!(by_ids.filter, None);

        let by_filter: BatchCsvRequest = serde_json::from_str(
            r#"{"filter":"from=2026-09-25T00:00&to=2026-09-25T23:59"}"#,
        )
        .expect("filter payload must deserialise");
        assert!(by_filter.ids.is_empty());
        assert_eq!(
            by_filter.filter.as_deref(),
            Some("from=2026-09-25T00:00&to=2026-09-25T23:59")
        );

        // Empty body — both fields default-initialised, mirrors the
        // behaviour the server checks for and 400s on.
        let empty: BatchCsvRequest = serde_json::from_str("{}")
            .expect("empty JSON must deserialise to defaults");
        assert!(empty.ids.is_empty());
        assert!(empty.filter.is_none());
    }

    /// Compile-time guard: `CdrSummary` is `Serialize`, so the
    /// `format_csv_line` shape can't drift from the underlying
    /// columns without a build break. If you remove / rename any
    /// field used in the formatter, this fails first.
    #[test]
    fn cdr_summary_is_serializable() {
        let s = mk_summary(99, Some("caller"), Some("called"));
        let json = serde_json::to_string(&s).expect("CdrSummary must serialize");
        assert!(json.contains("\"id\":99"));
        assert!(json.contains("\"mos_str\":\"4.2\""));
    }
}
