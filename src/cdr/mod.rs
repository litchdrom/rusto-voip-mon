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

use chrono::{Duration, FixedOffset, NaiveDate, NaiveDateTime, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, MySqlPool, Row};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

pub mod rtp_pcap;
pub mod sip_pcap;

/// Per-leg RTP stats from the `cdr` table. A leg = "caller side"
/// (`a_*` columns) or "callee side" (`b_*` columns).
///
/// VoIPmonitor populates these per-direction from RTCP reports it
/// sniffs off the wire — they're already computed aggregates stored
/// in cdr, not live counters. So they're a snapshot of the call's
/// call-quality, not a windowed time series (the latter would
/// require reading the pcap).
#[derive(Debug, Clone, Default, Serialize)]
pub struct RtpLeg {
    pub mos_lqo_mult10: Option<u8>,
    pub lost: Option<u32>,
    pub received: Option<u32>,
    pub avg_jitter_mult10: Option<u32>,
    pub max_jitter: Option<u16>,
    pub loss_perc_mult1000: Option<u32>,
    pub delay_avg_mult100: Option<u32>,
    pub rtcp_loss: Option<i32>,
    pub rtcp_maxjitter: Option<u16>,
    pub payload: Option<i32>,
    pub ptime: Option<u8>,
    /// Codec name derived from the RTP payload type (e.g. "G.711 µ-law"
    /// for PT=0). Empty string when PT is unknown.
    pub codec_name: String,
    /// Source IP of this leg (a_saddr / b_saddr as int) pre-formatted
    /// to dotted-quad. Empty string when VoIPmonitor didn't populate
    /// the column.
    pub src_ip_str: String,
    /// "Other" endpoint's IP — for the A leg (caller) this is the
    /// callee's address; for the B leg (callee) it's the caller's.
    /// Pre-formatted dotted-quad or empty string.
    pub dst_ip_str: String,
}

impl RtpLeg {
    /// True if any field is populated — used by the template to
    /// hide the RTP panel for calls where VoIPmonitor didn't capture
    /// any RTP stats (e.g. failed calls, early hangups).
    pub fn is_populated(&self) -> bool {
        self.mos_lqo_mult10.is_some()
            || self.lost.is_some()
            || self.received.is_some()
            || self.avg_jitter_mult10.is_some()
            || self.max_jitter.is_some()
            || self.loss_perc_mult1000.is_some()
            || self.delay_avg_mult100.is_some()
            || self.rtcp_loss.is_some()
            || self.rtcp_maxjitter.is_some()
            || self.payload.is_some()
            || self.ptime.is_some()
    }
}

/// Map a small set of well-known RTP payload types to human-readable
/// codec names. Returns empty string for unknown / dynamic PTs (the
/// 96-127 range where the codec is signaled out-of-band via SDP).
fn codec_name_from_pt(pt: i32) -> &'static str {
    match pt {
        0 => "PCMU (G.711 µ-law)",
        3 => "GSM 06.10",
        4 => "G.723.1",
        5 => "DVI4 8 kHz",
        6 => "DVI4 16 kHz",
        7 => "LPC",
        8 => "PCMA (G.711 A-law)",
        9 => "G.722",
        10 => "L16 (linear 16-bit, 2 channels)",
        11 => "L16 (linear 16-bit, 1 channel)",
        12 => "QCELP",
        13 => "CN",
        14 => "MPA",
        15 => "G.728",
        16 => "DVI4 11 kHz",
        17 => "DVI4 22 kHz",
        18 => "G.729",
        25 => "CelB",
        26 => "JPEG",
        28 => "nv",
        31 => "H.261",
        32 => "MPV",
        34 => "H.263",
        101 => "telephone-event (DTMF)",
        103 => "H.263-1998",
        104 => "H.263-2000",
        105 => "H.264",
        106 => "MP4V-ES",
        108 => "H.264-2000",
        111 => "Opus",
        116 => "red",
        117 => "telephone-event (RFC 2833)",
        // 96..=127 is the dynamic PT range; codec is signaled via SDP
        // and there's no way to map without the SDP body.
        _ => "",
    }
}

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
    // Per-leg RTP aggregates (the cdr table has every one of these in
    // a_* / b_* pairs — see VoIPmonitor schema). Pulled in CdrRow
    // because the SQL SELECT in cdr_detail wants them all in one
    // roundtrip; copied into CdrSummary as the `rtp_a` / `rtp_b`
    // bundles so the template doesn't have to know about mult-10
    // scaling or codec lookup.
    pub a_mos_lqo_mult10: Option<u8>,
    pub b_mos_lqo_mult10: Option<u8>,
    pub a_received: Option<u32>,
    pub b_received: Option<u32>,
    pub a_avgjitter_mult10: Option<u32>,
    pub b_avgjitter_mult10: Option<u32>,
    pub a_maxjitter: Option<u16>,
    pub b_maxjitter: Option<u16>,
    pub a_packet_loss_perc_mult1000: Option<u32>,
    pub b_packet_loss_perc_mult1000: Option<u32>,
    pub a_delay_avg_mult100: Option<u32>,
    pub b_delay_avg_mult100: Option<u32>,
    pub a_rtcp_loss: Option<i32>,
    pub b_rtcp_loss: Option<i32>,
    pub a_rtcp_maxjitter: Option<u16>,
    pub b_rtcp_maxjitter: Option<u16>,
    pub a_payload: Option<i32>,
    pub b_payload: Option<i32>,
    pub a_rtp_ptime: Option<u8>,
    pub b_rtp_ptime: Option<u8>,
    /// Source IP of leg A (the caller's side) as a host-order int.
    /// Stored as `a_saddr` in cdr; we render it as a dotted-quad in
    /// the RTP panel so the analyst can see at a glance which leg
    /// corresponds to which endpoint IP.
    pub a_saddr: Option<u32>,
    /// Source IP of leg B (the callee's side). Same purpose as
    /// `a_saddr` but for the B leg.
    pub b_saddr: Option<u32>,
}

/// All `cdr` columns that `CdrRow` expects via `FromRow`. Every
/// `query_as::<CdrRow>` SQL must include exactly this list (in any
/// order) — sqlx's `FromRow` derive requires the result set to
/// contain every struct field's column; missing columns surface as
/// `Error::ColumnNotFound` at execute time, not at prepare time.
///
/// Keeping the list in one place means `cdr::list`, `cdr_detail`,
/// and `fetch_by_ids` all pull the same columns — no chance of one
/// going stale when CdrRow gains a field.
pub const CDR_FULL_SELECT_COLUMNS: &str = "ID AS `id`, calldate, callend, duration, connect_duration, \
        caller, callername, called, sipcallerip, sipcalledip, \
        lastSIPresponseNum AS `last_sip_response_num`, \
        mos_min_mult10, a_lost, b_lost, id_sensor, \
        a_mos_lqo_mult10, b_mos_lqo_mult10, \
        a_received, b_received, \
        a_avgjitter_mult10, b_avgjitter_mult10, \
        a_maxjitter, b_maxjitter, \
        a_packet_loss_perc_mult1000, b_packet_loss_perc_mult1000, \
        a_delay_avg_mult100, b_delay_avg_mult100, \
        a_rtcp_loss, b_rtcp_loss, \
        a_rtcp_maxjitter, b_rtcp_maxjitter, \
        a_payload, b_payload, \
        a_rtp_ptime, b_rtp_ptime, \
        a_saddr, b_saddr";

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
    /// Per-leg RTP stats, codec names pre-resolved. The template
    /// walks these as `{{ cdr.rtp_a.mos_str }}` etc; the raw mult-10
    /// fields stay internal to the cdr module.
    pub rtp_a: RtpLeg,
    pub rtp_b: RtpLeg,
}

/// Display strings for a per-leg bundle. Built lazily in the
/// `From<CdrRow>` so the template doesn't have to know about the
/// underlying mult-10 / mult-1000 scaling.
impl RtpLeg {
    /// MOS LQO rendered as a one-decimal string ("4.2") or "" when
    /// unset. Distinct from `CdrSummary.mos_str` (which uses the
    /// call-level `mos_min_mult10`); per-leg MOS LQO is VoIPmonitor's
    /// own narrow-band listening-quality estimate per direction.
    pub fn mos_str(&self) -> String {
        self.mos_lqo_mult10
            .map(|m| format!("{:.1}", m as f32 / 10.0))
            .unwrap_or_default()
    }

    /// Loss rendered with denominator context — "N / T (P.P%)" where
    /// T = lost + received (the packets VoIPmonitor saw on this leg).
    /// "21.0%" alone is meaningless without a denominator; "5 / 23
    /// (21.0%)" reads as "5 packets lost out of 23 total". Falls back
    /// gracefully when only some fields are populated.
    pub fn loss_str(&self) -> String {
        let pct = self
            .loss_perc_mult1000
            .map(|p| format!(" ({:.1}%)", p as f32 / 10.0));
        match (self.lost, self.received) {
            // Both unset — show percent only (no count to precede it).
            (None, None) => pct
                .map(|p| p.trim_start().to_string())
                .unwrap_or_default(),
            // The interesting case — both populated.
            (Some(lost), Some(received)) => {
                let total = lost + received;
                let mut s = format!("{} / {}", lost, total);
                if let Some(p) = pct {
                    s.push_str(&p);
                }
                s
            }
            // Lost known, received missing — drop the denominator.
            (Some(n), None) => match pct {
                Some(p) => format!("{}{}", n, p),
                None => n.to_string(),
            },
            // Received known, lost missing — show received only as a
            // last-resort. We can't reconstruct the denominator, so
            // don't pretend. The "(P.P%)" is still meaningful because
            // VoIPmonitor stored it independently.
            (None, Some(r)) => match pct {
                Some(p) => format!("{}{}", r, p),
                None => r.to_string(),
            },
        }
    }

    /// Avg jitter rendered in ms (the mult-10 scaling makes the int
    /// a tenth-of-millisecond — we divide by 10 to land on real ms).
    /// Returns "" if unset.
    pub fn avg_jitter_ms(&self) -> String {
        self.avg_jitter_mult10
            .map(|j| format!("{:.1}", j as f32 / 10.0))
            .unwrap_or_default()
    }

    /// Max jitter rendered in ms (raw column is already ms).
    pub fn max_jitter_ms(&self) -> String {
        self.max_jitter
            .map(|j| j.to_string())
            .unwrap_or_default()
    }

    /// RTCP max jitter rendered in ms (with the " ms" suffix), or "" when
    /// unset / sentinel. VoIPmonitor's `*_rtcp_maxjitter` column is
    /// stored as u16 and uses 65535 (the u16 max) as a sentinel value
    /// when no RTCP report was received for that direction — short
    /// calls, mid-stream SSRC changes, and certain NAT pinholes that
    /// drop RTCP all leave the column at 65535. Showing that as
    /// "65535 ms" alongside a clean 0.4 ms on the other leg would be
    /// misleading, so we collapse the sentinel to "" and let the
    /// existing `dim_or_dash` render a muted em-dash.
    pub fn rtcp_max_jitter_ms(&self) -> String {
        match self.rtcp_maxjitter {
            None => String::new(),
            Some(65535) => String::new(),
            Some(v) => format!("{v} ms"),
        }
    }

    /// Delay rendered in ms (the mult-100 scaling makes the int a
    /// hundredth-of-millisecond — we divide by 100 to land on real ms).
    pub fn delay_ms(&self) -> String {
        self.delay_avg_mult100
            .map(|d| format!("{:.0}", d as f32 / 100.0))
            .unwrap_or_default()
    }
}

impl From<CdrRow> for CdrSummary {
    fn from(row: CdrRow) -> Self {
        let mos_str = row
            .mos_min_mult10
            .map(|m| format!("{:.1}", m as f32 / 10.0))
            .unwrap_or_default();
        // SIP-signalling endpoints (used by the SIP flow table).
        let src_ip_str = row.sipcallerip.map(int_to_ipv4).unwrap_or_default();
        let dst_ip_str = row.sipcalledip.map(int_to_ipv4).unwrap_or_default();
        // RTP-level endpoints: a_saddr is the host that sent RTP to
        // us in the caller direction; b_saddr is the host that sent
        // RTP to us in the callee direction. They can differ from the
        // SIP endpoints when the call is behind a media relay
        // (RTPEngine, SBC). Pre-format both legs so the template can
        // show "from X.X.X.X → Y.Y.Y.Y" without re-encoding.
        let a_saddr_str = row.a_saddr.map(int_to_ipv4).unwrap_or_default();
        let b_saddr_str = row.b_saddr.map(int_to_ipv4).unwrap_or_default();
        let rtp_a = RtpLeg {
            mos_lqo_mult10: row.a_mos_lqo_mult10,
            lost: row.a_lost,
            received: row.a_received,
            avg_jitter_mult10: row.a_avgjitter_mult10,
            max_jitter: row.a_maxjitter,
            loss_perc_mult1000: row.a_packet_loss_perc_mult1000,
            delay_avg_mult100: row.a_delay_avg_mult100,
            rtcp_loss: row.a_rtcp_loss,
            rtcp_maxjitter: row.a_rtcp_maxjitter,
            payload: row.a_payload,
            ptime: row.a_rtp_ptime,
            codec_name: row.a_payload.map(codec_name_from_pt).unwrap_or("").to_string(),
            src_ip_str: a_saddr_str.clone(),
            dst_ip_str: b_saddr_str.clone(),
        };
        let rtp_b = RtpLeg {
            mos_lqo_mult10: row.b_mos_lqo_mult10,
            lost: row.b_lost,
            received: row.b_received,
            avg_jitter_mult10: row.b_avgjitter_mult10,
            max_jitter: row.b_maxjitter,
            loss_perc_mult1000: row.b_packet_loss_perc_mult1000,
            delay_avg_mult100: row.b_delay_avg_mult100,
            rtcp_loss: row.b_rtcp_loss,
            rtcp_maxjitter: row.b_rtcp_maxjitter,
            payload: row.b_payload,
            ptime: row.b_rtp_ptime,
            codec_name: row.b_payload.map(codec_name_from_pt).unwrap_or("").to_string(),
            src_ip_str: b_saddr_str,
            dst_ip_str: a_saddr_str,
        };
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
            rtp_a,
            rtp_b,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CdrFilters {
    pub from: Option<NaiveDateTime>,
    pub to: Option<NaiveDateTime>,
    /// Substring match on `caller`. Kept for fuzzy "show me anything
    /// containing this digit sequence" queries; use `caller_in` for
    /// exact multi-value lookups.
    pub caller: Option<String>,
    /// Substring match on `called`. Same note as `caller`.
    pub called: Option<String>,
    /// Exact-match caller list. Use this for `OR`-over-many-values
    /// queries — the SQL is `caller IN (?, ?, ?)` rather than a
    /// chain of `LIKE`s, which is dramatically cheaper and lets the
    /// planner use indexes. Populated from repeated `caller_in=...`
    /// query keys.
    #[serde(default)]
    pub caller_in: Vec<String>,
    /// Exact-match called list. Same idea as `caller_in`. Populated
    /// from repeated `called_in=...` query keys; the values are parsed
    /// as `u64` so `?called_in=1234567` matches the digit sequence
    /// stored in `cdr.called` (VoIPmonitor stores phone numbers as
    /// digit strings, not numeric types).
    #[serde(default)]
    pub called_in: Vec<u64>,
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
    /// Resolve defaults in the supplied timezone. The default window is
    /// "today" (00:00:00 .. 23:59:59) in `tz` — so an operator whose local
    /// time differs from the server's UTC clock gets a window that lines
    /// up with their wall clock.
    pub fn normalized(&self, tz: FixedOffset) -> NormalizedFilters {
        let page = self.page.unwrap_or(1).max(1);
        let page_size = self.page_size.unwrap_or(50).clamp(1, 500);

        let (from, to) = match (self.from, self.to) {
            (None, None) => {
                let (f, t) = today_window_in_tz(&tz);
                (Some(f), Some(t))
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
            caller_in: self.caller_in.clone(),
            called_in: self.called_in.clone(),
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

    /// Same as `normalized()` but with no `page_size` cap — used by the CSV
    /// exporter which streams every matching row.
    pub fn normalized_for_export(&self, tz: FixedOffset) -> NormalizedFilters {
        let mut f = self.normalized(tz);
        f.page_size = self.page_size.unwrap_or(50).max(1);
        f
    }
}

/// Compute the `00:00:00 .. 23:59:59` window for "today" in the given
/// timezone, returned as naive datetimes suitable for binding into the
/// `calldate` SQL filter.
fn today_window_in_tz(tz: &FixedOffset) -> (NaiveDateTime, NaiveDateTime) {
    let now_local = Utc::now().with_timezone(tz);
    let day: NaiveDate = now_local.date_naive();
    (
        day.and_hms_opt(0, 0, 0).unwrap(),
        day.and_hms_opt(23, 59, 59).unwrap(),
    )
}

#[cfg(test)]
mod tz_tests {
    use super::*;

    /// The window for a given tz must always be (00:00:00 .. 23:59:59)
    /// on the *local* date — that's what makes the "Today" filter line up
    /// with the operator's wall clock regardless of server UTC offset.
    #[test]
    fn window_is_midnight_to_2359_in_local_tz() {
        use chrono::NaiveTime;
        let midnight = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
        let end_of_day = NaiveTime::from_hms_opt(23, 59, 59).unwrap();
        for offset_h in [-12, -6, -3, 0, 3, 5, 9, 12] {
            let tz = FixedOffset::east_opt(offset_h * 3600).unwrap();
            let (from, to) = today_window_in_tz(&tz);
            assert_eq!(
                (from.time(), to.time()),
                (midnight, end_of_day),
                "tz offset {offset_h}h should give a 00:00:00..23:59:59 window"
            );
            assert_eq!(from.date(), to.date(), "window must be a single day");
        }
    }

    /// Two different timezones must produce two *different* windows when
    /// the server's UTC clock puts them on opposite sides of midnight.
    #[test]
    fn windows_differ_across_timezones() {
        let utc_minus_6 = FixedOffset::east_opt(-6 * 3600).unwrap();
        let utc_plus_6 = FixedOffset::east_opt(6 * 3600).unwrap();
        let (from_west, _) = today_window_in_tz(&utc_minus_6);
        let (from_east, _) = today_window_in_tz(&utc_plus_6);
        // When the server's UTC clock is 02:00, UTC-6 is "yesterday 20:00"
        // and UTC+6 is "today 08:00" — the windows should differ by ~1 day
        // most of the time. Allow the case where they happen to coincide
        // (UTC noon / midnight) by only asserting inequality weakly.
        let diff_days = (from_east.date() - from_west.date()).num_days().abs();
        assert!(
            diff_days <= 1,
            "tz windows differ by {diff_days} days, expected <=1"
        );
    }
}

#[cfg(test)]
mod in_clause_tests {
    use super::*;

    fn f(caller_in: Vec<String>, called_in: Vec<u64>) -> NormalizedFilters {
        NormalizedFilters {
            from: None,
            to: None,
            caller: None,
            called: None,
            caller_in,
            called_in,
            src_ips: vec![],
            dst_ips: vec![],
            sip_codes: vec![],
            sensor_ids: vec![],
            mos_min_mult10: None,
            mos_max_mult10: None,
            min_duration: None,
            max_duration: None,
            page: 1,
            page_size: 50,
        }
    }

    #[test]
    fn caller_in_emits_in_clause_with_one_bind_per_value() {
        let (sql, binds) = f(
            vec!["alice".into(), "bob".into(), "carol".into()],
            vec![],
        )
        .to_where();
        assert_eq!(sql, "WHERE caller IN (?,?,?)");
        let got: Vec<String> = binds
            .into_iter()
            .map(|b| match b {
                FilterBind::Str(s) => s,
                _ => panic!("expected Str bind for caller_in"),
            })
            .collect();
        assert_eq!(got, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn called_in_emits_in_clause_with_stringified_u64s() {
        let (sql, binds) = f(
            vec![],
            vec![491234567, 491234568],
        )
        .to_where();
        assert_eq!(sql, "WHERE called IN (?,?)");
        let got: Vec<String> = binds
            .into_iter()
            .map(|b| match b {
                FilterBind::Str(s) => s,
                _ => panic!("expected Str bind (column is VARCHAR) for called_in"),
            })
            .collect();
        assert_eq!(got, vec!["491234567", "491234568"]);
    }

    #[test]
    fn empty_in_lists_add_no_clause() {
        let (sql, binds) = f(vec![], vec![]).to_where();
        assert_eq!(sql, "");
        assert!(binds.is_empty());
    }

    #[test]
    fn caller_substring_and_in_list_are_anded() {
        let mut f = f(vec!["alice".into(), "bob".into()], vec![]);
        f.caller = Some("a".into());
        let (sql, _) = f.to_where();
        // Substring LIKE first, then IN, joined with AND. Order matters
        // because callers may write tools that grep on the SQL string —
        // keep the existing LIKE clause position.
        assert_eq!(sql, "WHERE caller LIKE ? AND caller IN (?,?)");
    }
}

#[derive(Debug, Clone)]
pub struct NormalizedFilters {
    pub from: Option<NaiveDateTime>,
    pub to: Option<NaiveDateTime>,
    pub caller: Option<String>,
    pub called: Option<String>,
    /// Exact-match caller list. Emits `caller IN (?, ?, ?)` in `to_where()`.
    pub caller_in: Vec<String>,
    /// Exact-match called list. Emits `called IN (?, ?, ?)`. Values are
    /// `u64` because VoIPmonitor stores phone numbers as digit strings —
    /// parsing on the way in validates that the caller meant a number
    /// (not, say, a SIP URI) and lets us dedupe cheaply. We stringify
    /// on bind because the column type is VARCHAR.
    pub called_in: Vec<u64>,
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
        if !self.caller_in.is_empty() {
            parts.push(format!(
                "caller IN ({})",
                placeholders(self.caller_in.len())
            ));
            for v in &self.caller_in {
                binds.push(FilterBind::Str(v.clone()));
            }
        }
        if !self.called_in.is_empty() {
            parts.push(format!(
                "called IN ({})",
                placeholders(self.called_in.len())
            ));
            for v in &self.called_in {
                binds.push(FilterBind::Str(v.to_string()));
            }
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
    // Use the shared `CDR_FULL_SELECT_COLUMNS` so `query_as::<CdrRow>`
    // never trips `ColumnNotFound` when the struct gains a field.
    let sql = format!(
        "SELECT {} FROM cdr {where_sql} \
          ORDER BY calldate DESC, ID DESC \
          LIMIT ? OFFSET ?",
        CDR_FULL_SELECT_COLUMNS,
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

/// Stream all matching rows in order via a channel. The spawned task owns
/// the SQL string and binds; the returned `Receiver` is a public, easy-to-
/// consume handle. Used by the CSV exporter so memory stays flat regardless
/// of result size.
///
/// `limit` caps the number of rows returned — applied as a SQL `LIMIT` so
/// the database stops sending rows once we've hit the cap. Prevents
/// accidental multi-GB downloads from "all time" filters.
pub fn list_stream(
    pool: &MySqlPool,
    f: &NormalizedFilters,
    limit: usize,
) -> ReceiverStream<Result<CdrRow, sqlx::Error>> {
    let (where_sql, binds) = f.to_where();
    // Shared with `list` — keeps `query_as::<CdrRow>` satisfied even
    // after the struct gains columns.
    let sql = format!(
        "SELECT {} FROM cdr {where_sql} \
          ORDER BY calldate DESC, ID DESC \
          LIMIT ?",
        CDR_FULL_SELECT_COLUMNS,
    );
    let (tx, rx) = mpsc::channel(64);
    let pool = pool.clone();
    tokio::spawn(async move {
        let mut q = sqlx::query_as::<_, CdrRow>(&sql);
        for b in &binds {
            q = match b {
                FilterBind::DateTime(d) => q.bind(d),
                FilterBind::Str(s) => q.bind(s),
                FilterBind::U32(v) => q.bind(*v),
                FilterBind::U16(v) => q.bind(*v),
            };
        }
        q = q.bind(limit as i64);
        let mut stream = Box::pin(q.fetch(&pool));
        while let Some(item) = stream.next().await {
            if tx.send(item).await.is_err() {
                break; // receiver dropped (client disconnected)
            }
        }
    });
    ReceiverStream::new(rx)
}

/// Resolve a filter to just the matching CDR IDs, capped at `limit`.
/// Cheaper than `list_stream` for the batch-pcap endpoint: we only need
/// the IDs (the per-CDR work then runs in parallel from
/// `build_pcap_bytes`). Sorted newest-first to match the on-page order
/// so the resulting zip reads naturally.
pub async fn list_ids_matching(
    pool: &MySqlPool,
    f: &NormalizedFilters,
    limit: usize,
) -> Result<Vec<u64>, sqlx::Error> {
    let (where_sql, binds) = f.to_where();
    let sql = format!(
        "SELECT ID FROM cdr {where_sql} \
         ORDER BY calldate DESC, ID DESC \
         LIMIT ?"
    );
    let mut q = sqlx::query_scalar::<_, u64>(&sql);
    for b in &binds {
        q = match b {
            FilterBind::DateTime(d) => q.bind(d),
            FilterBind::Str(s) => q.bind(s),
            FilterBind::U32(v) => q.bind(*v),
            FilterBind::U16(v) => q.bind(*v),
        };
    }
    q = q.bind(limit as i64);
    q.fetch_all(pool).await
}

/// Fetch CDR summary rows by explicit ID list, returning a map keyed by
/// ID so the caller can look up each row in any order. Used by the batch
/// pcap endpoint to build the `cdrs.csv` metadata sidecar that goes into
/// the same zip as the `cdr-<id>.pcap` files.
///
/// Empty / duplicate / zero IDs in `ids` are silently dropped (matching
/// the rest of the batch pipeline). IDs that don't exist in the DB
/// simply don't appear in the returned map.
pub async fn fetch_by_ids(
    pool: &MySqlPool,
    ids: &[u64],
) -> Result<std::collections::HashMap<u64, CdrSummary>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let mut seen = std::collections::HashSet::with_capacity(ids.len());
    let mut clean: Vec<u64> = Vec::with_capacity(ids.len());
    for &id in ids {
        if id > 0 && seen.insert(id) {
            clean.push(id);
        }
    }
    if clean.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    let sql = format!(
        "SELECT {} FROM cdr WHERE ID IN ({})",
        CDR_FULL_SELECT_COLUMNS,
        placeholders(clean.len())
    );
    let mut q = sqlx::query_as::<_, CdrRow>(&sql);
    for id in &clean {
        q = q.bind(*id);
    }
    let rows = q.fetch_all(pool).await?;
    let mut out = std::collections::HashMap::with_capacity(rows.len());
    for row in rows {
        let s = CdrSummary::from(row);
        out.insert(s.id, s);
    }
    Ok(out)
}

// Re-exports the per-request helper types from `routes::cdr` so other
// modules can build a `NormalizedFilters` from a raw query string without
// reaching across the route layer. We can't move them into `cdr::mod`
// cleanly (they depend on askama view types) so we just re-export.

/// Resolve a raw URL-encoded CDR-list query string to the matching IDs.
/// Used by `/pcap/batch` when the caller sends `{"filter": "..."}` so
/// the "Download all matching pcaps" button on the list page can ship
/// the same query string the CSV button would.
pub async fn ids_for_query_string(
    pool: &MySqlPool,
    raw_query: &str,
    tz: chrono::FixedOffset,
    limit: usize,
) -> Result<Vec<u64>, crate::error::AppError> {
    let params = crate::routes::cdr::parse_query_params(raw_query);
    let q = crate::routes::cdr::SingleParams {
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
    let filters = crate::routes::cdr::build_filters(&q, &params);
    let normalized = filters.normalized(tz);
    crate::error::with_query_timeout(0, list_ids_matching(pool, &normalized, limit))
        .await
        .map_err(crate::error::AppError::from)
}

/// `cdr_next` — 1:1 extension to `cdr` that holds per-call derived state.
///
/// Static, known columns:
///   - `fbasename`        — Call-ID with special chars → underscores. Matches
///                          the PCAP inner filename; used to correlate pcaps
///                          with calls.
///   - `match_header`     — content of the configured custom header, used by
///                          VoIPmonitor to link call legs.
///   - `digest_username`  — SIP digest auth username (for INVITE challenges).
///   - `GeoPosition`      — caller geo (city, country) when GeoIP is on.
///   - `hold`             — hold/transfer history (semicolon-separated).
///   - `spool_index`      — which minute-bucket tar.zst this call was found in
///                          (matches `cdr_tar_part.type`).
///
/// Dynamic columns:
///   - `custom_header1`, `custom_header2`, ... — one per configured
///     custom-header mapping in voipmonitor.conf. Number varies per
///     install; we discover them at runtime from `INFORMATION_SCHEMA`.
#[derive(Debug, Clone, FromRow)]
pub struct CdrNext {
    pub fbasename: Option<String>,
    pub match_header: Option<String>,
    pub digest_username: Option<String>,
    pub geo_position: Option<String>,
    pub hold: Option<String>,
    pub spool_index: Option<u8>,
}

/// Discover every `custom_header%` column in the live `cdr_next` schema.
/// Called once per detail-page render (cheap — INFORMATION_SCHEMA is cached
/// by MySQL); if it gets hot we can stash the result in `AppState`.
pub async fn list_custom_header_columns(pool: &MySqlPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT COLUMN_NAME \
           FROM information_schema.COLUMNS \
          WHERE TABLE_SCHEMA = DATABASE() \
            AND TABLE_NAME   = 'cdr_next' \
            AND COLUMN_NAME LIKE 'custom_header%' \
          ORDER BY COLUMN_NAME",
    )
    .fetch_all(pool)
    .await
}

/// Fetch the static + dynamic fields for one CDR.
pub async fn fetch_cdr_next(
    pool: &MySqlPool,
    cdr_id: u64,
) -> Result<CdrNextBundle, sqlx::Error> {
    let static_row: Option<CdrNext> = sqlx::query_as(
        "SELECT fbasename, match_header, digest_username, \
                GeoPosition AS `geo_position`, hold, spool_index \
           FROM cdr_next WHERE cdr_ID = ? LIMIT 1",
    )
    .bind(cdr_id)
    .fetch_optional(pool)
    .await?;

    let custom_cols = list_custom_header_columns(pool).await?;
    let custom_values = if !custom_cols.is_empty() {
        // Quote identifiers with backticks (column names may contain digits
        // after `custom_header`).
        let select_list = custom_cols
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT {select_list} FROM cdr_next WHERE cdr_ID = ? LIMIT 1"
        );
        let row: Option<sqlx::mysql::MySqlRow> =
            sqlx::query(&sql).bind(cdr_id).fetch_optional(pool).await?;
        row.map(|r| {
            custom_cols
                .iter()
                .map(|c| {
                    let v: Option<String> = r.try_get(c.as_str()).ok().flatten();
                    (c.clone(), v.unwrap_or_default())
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(CdrNextBundle {
        static_fields: static_row,
        custom_headers: custom_values,
    })
}

/// Combined `cdr_next` payload — typed columns plus a list of
/// `(column_name, value)` for every dynamic `custom_headerN`.
#[derive(Debug, Clone)]
pub struct CdrNextBundle {
    pub static_fields: Option<CdrNext>,
    pub custom_headers: Vec<(String, String)>,
}

/// `cdr_next_branches` — one row per leg of a forked call. Primary key
/// on this table is `(cdr_ID, calldate)`, NOT `(id)` — so we sort by
/// `calldate` for a deterministic chronological order of the legs.
///
/// The table actually carries a full set of SIP fields per leg (caller,
/// called, IPs, response code, custom headers…). For v0.1 we read just
/// `calldate`, `call_id`, and `fbasename` — the minimum needed to render a
/// useful "call legs" panel. Pulling the rest is a v1.1 concern.
#[derive(Debug, Clone, FromRow)]
pub struct CdrNextBranch {
    pub calldate: Option<NaiveDateTime>,
    pub call_id: Option<String>,
    pub fbasename: Option<String>,
}

pub async fn fetch_cdr_branches(
    pool: &MySqlPool,
    cdr_id: u64,
) -> Result<Vec<CdrNextBranch>, sqlx::Error> {
    sqlx::query_as::<_, CdrNextBranch>(
        "SELECT calldate, call_id, fbasename \
           FROM cdr_next_branches \
          WHERE cdr_ID = ? \
          ORDER BY calldate",
    )
    .bind(cdr_id)
    .fetch_all(pool)
    .await
}

/// One row in the SIP message timeline.
///
/// VoIPmonitor's `sip_msg` table holds every SIP request + response
/// that traversed the sensor during a call. For a normal successful
/// INVITE you'd see ~7-10 rows: INVITE → 100 → 180 → 200 → ACK → (media
/// pass) → BYE → 200. A failed call typically adds more (487, 503,
/// re-INVITEs). We fetch the columns needed for the timeline; the
/// full SIP body lives in `content` and is rendered on demand
/// (collapsed by default — a typical call generates ~10 KB of raw SIP).
///
/// `src_ip_str` / `dst_ip_str` are the dotted-IPv4 forms of the
/// `sipcallerip` / `sipcalledip` numeric columns; pre-formatted here
/// so the template doesn't need to call into the integer-to-IP helper.
#[derive(Debug, Clone, Serialize)]
pub struct SipMessage {
    pub id: u64,
    pub calldate: NaiveDateTime,
    pub method: String,
    pub response_num: u16,
    pub response_text: String,
    pub from_num: String,
    pub to_num: String,
    pub src_ip_str: String,
    pub dst_ip_str: String,
    /// Direction: "out" if this sensor initiated the request, "in" if it
    /// received it. Computed by comparing `sipcallerip` against the CDR's
    /// own `sipcallerip` — same direction as the CDR's primary leg.
    pub direction: String,
    pub content_type: String,
    /// Raw SIP message body. Can be empty for some messages (e.g. an
    /// ACK with no body). The template decides whether to inline-show
    /// it or keep it behind a toggle.
    pub content: String,
    /// CSeq sequence number, parsed from the SIP `CSeq:` header. The
    /// `(cseq_num, cseq_method)` pair identifies a SIP transaction —
    /// every response carries the request's CSeq, so we pair each
    /// outgoing request with its incoming responses by matching this.
    /// `None` when the header couldn't be parsed (malformed pcap /
    /// schema bridge row with empty body).
    pub cseq_num: Option<u32>,
    /// CSeq method (e.g. "INVITE", "BYE"). Same `CSeq:` header as
    /// `cseq_num`. Useful as a sanity check on the pairing — a
    /// response that claims `CSeq: 1 ACK` is a bug upstream.
    pub cseq_method: Option<String>,
}

/// Parse the CSeq header from a raw SIP message body. Returns
/// `(number, method)` or `None` when the header is missing or
/// malformed. Tolerates both `\r\n` and `\n` line endings (some
/// pcap exporters strip CRs). Search is case-insensitive on the
/// header name per RFC 3261 §7.5.
pub fn parse_cseq(body: &str) -> Option<(u32, String)> {
    // Walk the headers — they end at the first blank line, which
    // separates headers from the message body. We don't care about
    // the body for CSeq.
    let headers_end = body.find("\n\n").or_else(|| body.find("\r\n\r\n"))?;
    let headers = &body[..headers_end];
    for raw_line in headers.split(|c| c == '\n' || c == '\r').filter(|l| !l.is_empty()) {
        // Header line is "Name: value"; find the first colon.
        let colon = raw_line.find(':')?;
        let name = raw_line[..colon].trim();
        if !name.eq_ignore_ascii_case("CSeq") {
            continue;
        }
        let value = raw_line[colon + 1..].trim();
        // Value is "<num> <METHOD>" — split on the first whitespace.
        let mut parts = value.splitn(2, char::is_whitespace);
        let num_str = parts.next()?.trim();
        let method = parts.next()?.trim().to_string();
        let num: u32 = num_str.parse().ok()?;
        return Some((num, method));
    }
    None
}

/// Fetch all SIP messages for one CDR, oldest first.
///
/// Schema bridge (VoIPmonitor ≥ ~8.x). We try two strategies and
/// fall back from the precise to the fuzzy one:
///
/// 1. **Precise**: `sip_msg.ID` is in `cdr_siphistory.SIPrequest_id` or
///    `.SIPresponse_id` for any row whose `cdr_ID` matches. Works when
///    the history table is populated correctly.
///
/// 2. **Fuzzy** (the one in use on real installs): filter `sip_msg`
///    by time window (`cdr.calldate - 30s … cdr.callend + 30s`) AND a
///    party-number match (the CDR's `caller` / `called` appear in
///    either the message's `number_src` or `number_dst`). Works
///    regardless of `cdr_siphistory` state, including installs where
///    every `cdr_siphistory.SIPrequest_id` is NULL or always-1.
///
/// The fuzzy match can over-match when two back-to-back calls share
/// the same number pair, but the 30s padding around the CDR window
/// keeps that rare. If it turns out to be a real problem we'd add a
/// `callid` round-trip via a `cdr.callid` lookup — the user's CDR
/// schema doesn't currently have a `callid` column.
///
/// `request_content` / `response_content` are the full SIP wire
/// bodies; we parse method + status from the first line of each
/// (no separate `method` / `sip_response` columns in this schema).
///
/// Cap at 500 rows so a SIP loop storm doesn't render a 10 MB page.
pub async fn fetch_sip_messages(
    pool: &MySqlPool,
    cdr_id: u64,
    direction_marker_ip: Option<u32>,
    limit: u32,
) -> Result<Vec<SipMessage>, sqlx::Error> {
    use sqlx::Row;
    // Load the CDR's anchor fields first — calldate/callend/caller/
    // called drive the fuzzy query. We need them as raw strings since
    // VoIPmonitor stores numbers in multiple formats (`+49...` vs
    // `49...` vs `<sip:user@host>`) and binding them as i64/u32 would
    // normalise away the variants we need to match against.
    let cdr_row = sqlx::query(
        "SELECT calldate, callend, caller, called \
           FROM cdr \
          WHERE ID = ? LIMIT 1",
    )
    .bind(cdr_id)
    .fetch_optional(pool)
    .await?;
    let Some(cdr_row) = cdr_row else {
        return Ok(Vec::new());
    };
    let calldate: NaiveDateTime = cdr_row.try_get("calldate").unwrap_or_default();
    let callend: NaiveDateTime = cdr_row.try_get("callend").unwrap_or_default();
    let caller: String = cdr_row.try_get("caller").unwrap_or_default();
    let called: String = cdr_row.try_get("called").unwrap_or_default();

    // Pad the time window slightly so we catch the very first INVITE
    // that might have been timestamped a hair before calldate and the
    // final BYE-200 that might be a hair after callend. 30s on each
    // side is wider than typical clock skew but narrow enough that
    // back-to-back calls between the same party pair don't overlap.
    let window_start = calldate - chrono::Duration::seconds(30);
    let window_end = callend + chrono::Duration::seconds(30);

    let rows = sqlx::query(
        "SELECT sip_msg.ID AS id, sip_msg.time, \
                sip_msg.ip_src, sip_msg.ip_dst, \
                sip_msg.number_src, sip_msg.number_dst, \
                sip_msg.request_content, sip_msg.response_content, \
                sip_msg.response_number \
           FROM sip_msg \
          WHERE sip_msg.time BETWEEN ? AND ? \
            AND (sip_msg.number_src IN (?, ?) \
              OR sip_msg.number_dst IN (?, ?)) \
          ORDER BY sip_msg.time ASC, sip_msg.time_us ASC, sip_msg.ID ASC \
          LIMIT ?",
    )
    .bind(window_start)
    .bind(window_end)
    .bind(&caller)
    .bind(&called)
    .bind(&caller)
    .bind(&called)
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let src_ip_int: Option<u32> = row.try_get("ip_src").ok().flatten();
        let dst_ip_int: Option<u32> = row.try_get("ip_dst").ok().flatten();
        let src_ip_str = src_ip_int
            .map(int_to_ipv4)
            .unwrap_or_default();
        let dst_ip_str = dst_ip_int
            .map(int_to_ipv4)
            .unwrap_or_default();
        // Direction heuristic: a request is "out" if the sensor's
        // known direction-marker IP (the CDR's `sipcallerip`) is the
        // source of THIS message. Falls back to "in" if we have no
        // marker — better than guessing wrong with empty data.
        let direction = match (direction_marker_ip, src_ip_int) {
            (Some(marker), Some(src)) if src == marker => "out".to_string(),
            _ => "in".to_string(),
        };
        let request_content: String =
            row.try_get("request_content").unwrap_or_default();
        let response_content: String =
            row.try_get("response_content").unwrap_or_default();
        let response_number: Option<u16> =
            row.try_get("response_number").ok().flatten();
        // Parse CSeq upfront — the header lives in either request_content
        // or response_content (one per sip_msg row), and we need to
        // parse it before the `if/else` below moves either string
        // into `content` (the compiler can't prove the branches are
        // mutually exclusive at move-time).
        let cseq = parse_cseq(&request_content)
            .or_else(|| parse_cseq(&response_content));
        let (cseq_num, cseq_method) = cseq
            .map(|(n, m)| (Some(n), Some(m)))
            .unwrap_or((None, None));
        // A row is a request if `request_content` is non-empty, a
        // response if `response_content` is non-empty. Both can be
        // populated for paired request/response rows.
        let method = parse_sip_method(&request_content);
        let (response_num, response_text) = parse_sip_response(
            &response_content,
            response_number.unwrap_or(0),
        );
        // The toggle body shows whichever side is non-empty. If both
        // are populated (paired row), show the request — analysts
        // care more about "what did we send" than "what came back".
        let content = if !request_content.is_empty() {
            request_content
        } else {
            response_content
        };
        out.push(SipMessage {
            id: row.try_get::<i64, _>("id").map(|n| n as u64).unwrap_or(0),
            calldate: row
                .try_get::<NaiveDateTime, _>("time")
                .unwrap_or_else(|_| Utc::now().naive_utc()),
            method,
            response_num,
            response_text,
            from_num: row.try_get::<String, _>("number_src").unwrap_or_default(),
            to_num: row.try_get::<String, _>("number_dst").unwrap_or_default(),
            src_ip_str,
            dst_ip_str,
            direction,
            content_type: String::new(), // schema has no per-message CT column
            content,
            cseq_num,
            cseq_method,
        });
    }
    Ok(out)
}

/// Parse the first whitespace-separated token of a SIP request line.
/// `"INVITE sip:user@example.com SIP/2.0\r\n..."` → `"INVITE"`.
/// Returns `""` for empty bodies and for response status lines
/// (`"SIP/2.0 200 OK\r\n..."`) — a response carries a status code,
/// not a method, and rendering "SIP/2.0 200" as the method column
/// is misleading.
fn parse_sip_method(request_content: &str) -> String {
    if request_content.is_empty() {
        return String::new();
    }
    let first = request_content
        .split_whitespace()
        .next()
        .unwrap_or("");
    // Response status line — no method on a response.
    if first.eq_ignore_ascii_case("SIP/2.0") {
        return String::new();
    }
    first.to_string()
}

/// Pull every `c=` connection-info address out of an SDP body.
/// Returns IPs in textual form, deduplicated in order of first
/// appearance. Both session-level `c=` and media-level `c=` lines
/// are scanned — RFC 4566 §5.7 says media-level `c=` overrides the
/// session-level one for the relevant m-section, so we keep both.
///
/// `"v=0\r\no=... c=IN IP4 10.1.2.3 ... m=audio ... c=IN IP4 10.4.5.6\r\n"`
/// → `["10.1.2.3", "10.4.5.6"]`.
///
/// IPv6 (`c=IN IP6 ::1`) and hostnames (`c=IN IP4 example.com`) are
/// also parsed — for IPv6 we keep the bracketless form, for
/// hostnames we keep the bare name. Returns `[]` on any parse
/// failure (malformed SDP, no `c=` lines, empty body).
pub fn parse_sdp_c_lines(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        // SDP lines are CRLF-terminated; `lines()` already strips
        // both \r and \n, so we're left with the raw key=value text.
        let trimmed = line.trim();
        if !trimmed.starts_with("c=") {
            continue;
        }
        // Format: c=<nettype> <addrtype> <connection-address>
        // Example: "c=IN IP4 10.1.2.3" or "c=IN IP6 2001:db8::1"
        let mut parts = trimmed[2..].split_whitespace();
        let _nettype = parts.next();
        let _addrtype = parts.next();
        let addr = match parts.next() {
            Some(a) => a,
            None => continue,
        };
        // Skip placeholder / wildcard addresses which carry no
        // operator-meaningful endpoint info.
        if addr.is_empty() || addr == "0.0.0.0" || addr == "::" || addr == "::1" {
            continue;
        }
        if !out.iter().any(|existing| existing == addr) {
            out.push(addr.to_string());
        }
    }
    out
}

/// Parse a SIP response status line into `(code, reason)`:
/// `"SIP/2.0 200 OK\r\n..."` → `(200, "OK")`.
/// Falls back to the `response_number` column (smallint in the schema)
/// when the body is missing or unparseable.
fn parse_sip_response(response_content: &str, fallback_code: u16) -> (u16, String) {
    if response_content.is_empty() {
        return (fallback_code, String::new());
    }
    let first_line = response_content.lines().next().unwrap_or("");
    let mut parts = first_line.splitn(3, char::is_whitespace);
    let _sip_version = parts.next(); // "SIP/2.0"
    let code_str = parts.next().unwrap_or("");
    let reason = parts.next().unwrap_or("").to_string();
    let code = code_str.parse::<u16>().unwrap_or(fallback_code);
    (code, reason)
}

#[cfg(test)]
mod sip_parse_tests {
    use super::*;

    #[test]
    fn parse_method_extracts_first_token() {
        assert_eq!(
            parse_sip_method("INVITE sip:user@example.com SIP/2.0\r\nVia: ..."),
            "INVITE"
        );
        assert_eq!(parse_sip_method("BYE sip:user@example.com SIP/2.0"), "BYE");
        assert_eq!(parse_sip_method("REGISTER sip:registrar SIP/2.0"), "REGISTER");
    }

    #[test]
    fn parse_method_empty_body_returns_empty_string() {
        assert_eq!(parse_sip_method(""), "");
        assert_eq!(parse_sip_method("   "), "");
    }

    #[test]
    fn parse_sdp_extracts_session_and_media_c_lines() {
        // Standard INVITE SDP: session-level c= + media-level c=.
        let sdp = "v=0\r\n\
                    o=alice 1 2 IN IP4 10.1.2.3\r\n\
                    s=-\r\n\
                    c=IN IP4 10.1.2.3\r\n\
                    t=0 0\r\n\
                    m=audio 49170 RTP/AVP 0\r\n\
                    c=IN IP4 10.4.5.6\r\n";
        assert_eq!(
            parse_sdp_c_lines(sdp),
            vec!["10.1.2.3".to_string(), "10.4.5.6".to_string()]
        );
    }

    #[test]
    fn parse_sdp_skips_placeholders_and_dedupes() {
        // 0.0.0.0 / ::1 / :: are placeholders — should NOT appear.
        let sdp = "c=IN IP4 0.0.0.0\r\nc=IN IP6 ::1\r\nc=IN IP6 ::\r\n\
                    c=IN IP4 10.0.0.1\r\nc=IN IP4 10.0.0.1\r\n";
        assert_eq!(parse_sdp_c_lines(sdp), vec!["10.0.0.1".to_string()]);
    }

    #[test]
    fn parse_sdp_supports_ipv6() {
        let sdp = "c=IN IP6 2001:db8::1\r\nm=audio 49170 RTP/AVP 0\r\n\
                    c=IN IP6 fe80::1\r\n";
        assert_eq!(
            parse_sdp_c_lines(sdp),
            vec!["2001:db8::1".to_string(), "fe80::1".to_string()]
        );
    }

    #[test]
    fn parse_sdp_returns_empty_on_no_c_lines() {
        // Pure SDP without any c= (allowed but unusual).
        let sdp = "v=0\r\no=alice 1 2 IN IP4 10.1.2.3\r\ns=-\r\nt=0 0\r\n";
        assert!(parse_sdp_c_lines(sdp).is_empty());
    }

    #[test]
    fn parse_sdp_returns_empty_on_empty_body() {
        assert!(parse_sdp_c_lines("").is_empty());
    }

    #[test]
    fn parse_response_extracts_code_and_reason() {
        assert_eq!(
            parse_sip_response("SIP/2.0 200 OK\r\n...", 0),
            (200, "OK".to_string())
        );
        assert_eq!(
            parse_sip_response("SIP/2.0 486 Busy Here\r\n...", 0),
            (486, "Busy Here".to_string())
        );
        // Multi-word reason phrase preserved verbatim.
        assert_eq!(
            parse_sip_response("SIP/2.0 503 Service Unavailable\r\n...", 0),
            (503, "Service Unavailable".to_string())
        );
    }

    #[test]
    fn parse_response_falls_back_to_column_when_body_missing() {
        // Empty body → fall back to the column-provided code, empty reason.
        assert_eq!(parse_sip_response("", 404), (404, String::new()));
        // Malformed body: parser grabs whatever's in the 2nd/3rd slots as
        // (code_str, reason) — code_str fails to parse so the column's
        // fallback wins, but the reason field captures the rest of the
        // first line. This is fine for triage: a row with garbage in
        // these slots is already a sign something's wrong upstream.
        let (code, _reason) = parse_sip_response("not a sip response", 500);
        assert_eq!(code, 500);
    }
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
/// `lookback_days` days (relative to `tz`) so the dropdown stays relevant.
pub async fn distinct_values(
    pool: &MySqlPool,
    lookback_days: i64,
    limit: u32,
    tz: FixedOffset,
) -> Result<DistinctValues, sqlx::Error> {
    let since = today_window_in_tz(&tz).0 - Duration::days(lookback_days);

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

#[cfg(test)]
mod rtp_leg_tests {
    use super::*;

    #[test]
    fn rtp_leg_default_is_unpopulated() {
        // Default constructor — every field is None / empty.
        let leg = RtpLeg::default();
        assert!(!leg.is_populated(), "default RtpLeg must report empty");
        assert_eq!(leg.mos_str(), "");
        assert_eq!(leg.loss_str(), "");
        assert_eq!(leg.avg_jitter_ms(), "");
        assert_eq!(leg.max_jitter_ms(), "");
        assert_eq!(leg.delay_ms(), "");
        assert_eq!(leg.codec_name, "");
        assert_eq!(leg.src_ip_str, "");
        assert_eq!(leg.dst_ip_str, "");
    }

    #[test]
    fn rtp_leg_mos_str_scales_mult10() {
        // 42 = 4.2 MOS (mult-10 storage in cdr).
        let leg = RtpLeg { mos_lqo_mult10: Some(42), ..Default::default() };
        assert_eq!(leg.mos_str(), "4.2");
        assert!(leg.is_populated());
    }

    #[test]
    fn rtp_leg_loss_str_shows_denominator_with_percent() {
        // The user complained "21.0% los. 21 % from what?" — the fix
        // is to put the total-packet count next to the lost count.
        // lost=5, received=18 → total=23 → "5 / 23 (21.7%)".
        let leg = RtpLeg {
            lost: Some(5),
            received: Some(18),
            loss_perc_mult1000: Some(217), // 21.7%
            ..Default::default()
        };
        assert_eq!(leg.loss_str(), "5 / 23 (21.7%)");
        // Without percent — denominator still shown.
        let leg = RtpLeg {
            lost: Some(150),
            received: Some(450),
            ..Default::default()
        };
        assert_eq!(leg.loss_str(), "150 / 600");
        // Lost only, no received — fall back to "N (P.P%)" form.
        let leg = RtpLeg {
            lost: Some(42),
            loss_perc_mult1000: Some(100), // 10.0%
            ..Default::default()
        };
        assert_eq!(leg.loss_str(), "42 (10.0%)");
        // Lost only, no percent.
        let leg = RtpLeg { lost: Some(42), ..Default::default() };
        assert_eq!(leg.loss_str(), "42");
        // Percent only — show "(P.P%)".
        let leg = RtpLeg {
            loss_perc_mult1000: Some(50),
            ..Default::default()
        };
        assert_eq!(leg.loss_str(), "(5.0%)");
        // Received only, with percent (degraded but VoIPmonitor stored it).
        let leg = RtpLeg {
            received: Some(500),
            loss_perc_mult1000: Some(35), // 3.5%
            ..Default::default()
        };
        assert_eq!(leg.loss_str(), "500 (3.5%)");
        // Neither.
        let leg = RtpLeg::default();
        assert_eq!(leg.loss_str(), "");
    }

    #[test]
    fn rtp_leg_jitter_and_delay_scale_correctly() {
        // avg jitter mult-10: 35 → 3.5 ms.
        let leg = RtpLeg {
            avg_jitter_mult10: Some(35),
            ..Default::default()
        };
        assert_eq!(leg.avg_jitter_ms(), "3.5");
        // max jitter raw ms: 80 → "80".
        let leg = RtpLeg {
            max_jitter: Some(80),
            ..Default::default()
        };
        assert_eq!(leg.max_jitter_ms(), "80");
        // delay avg mult-100: 12345 → 123 ms (12345 / 100 = 123.45, formatted as {:.0} = "123").
        let leg = RtpLeg {
            delay_avg_mult100: Some(12345),
            ..Default::default()
        };
        assert_eq!(leg.delay_ms(), "123");
    }

    #[test]
    fn codec_name_resolves_well_known_payload_types() {
        // The most common PSTN codec PTs.
        assert_eq!(codec_name_from_pt(0), "PCMU (G.711 µ-law)");
        assert_eq!(codec_name_from_pt(8), "PCMA (G.711 A-law)");
        assert_eq!(codec_name_from_pt(9), "G.722");
        assert_eq!(codec_name_from_pt(18), "G.729");
        // DTMF.
        assert_eq!(codec_name_from_pt(101), "telephone-event (DTMF)");
        assert_eq!(codec_name_from_pt(117), "telephone-event (RFC 2833)");
        // Modern.
        assert_eq!(codec_name_from_pt(111), "Opus");
    }

    #[test]
    fn codec_name_returns_empty_for_dynamic_or_unknown_pts() {
        // 96..=127 is the dynamic PT range — codec is signaled out-of-band
        // via SDP, and we have no way to map without the SDP body.
        assert_eq!(codec_name_from_pt(96), "");
        assert_eq!(codec_name_from_pt(100), "");
        assert_eq!(codec_name_from_pt(127), "");
        // Anything outside the IANA registry.
        assert_eq!(codec_name_from_pt(255), "");
        assert_eq!(codec_name_from_pt(-1), "");
        assert_eq!(codec_name_from_pt(200), "");
    }

    #[test]
    fn rtcp_max_jitter_ms_collapses_65535_sentinel() {
        // 65535 is VoIPmonitor's u16 sentinel for "no RTCP report
        // received" — it is NOT a real jitter measurement and
        // showing it as "65535 ms" misleads the operator.
        let leg = RtpLeg { rtcp_maxjitter: Some(65535), ..Default::default() };
        assert_eq!(leg.rtcp_max_jitter_ms(), "");
        // Genuinely small values pass through with the " ms" suffix.
        let leg = RtpLeg { rtcp_maxjitter: Some(12), ..Default::default() };
        assert_eq!(leg.rtcp_max_jitter_ms(), "12 ms");
        // None / unset stays empty.
        let leg = RtpLeg::default();
        assert_eq!(leg.rtcp_max_jitter_ms(), "");
    }

    /// From<CdrRow> must copy a_saddr / b_saddr into the RTP leg
    /// slots and cross-assign so each leg's `dst_ip_str` is the
    /// *other* leg's source. The SIP-level src_ip_str / dst_ip_str
    /// (from sipcallerip / sipcalledip) stays on CdrSummary itself.
    #[test]
    fn cdr_summary_populates_rtp_leg_ips_from_saddr() {
        use chrono::NaiveDate;
        let row = CdrRow {
            id: 7,
            calldate: NaiveDate::from_ymd_opt(2026, 10, 4)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            callend: NaiveDate::from_ymd_opt(2026, 10, 4)
                .unwrap()
                .and_hms_opt(0, 0, 1)
                .unwrap(),
            duration: None,
            connect_duration: None,
            caller: Some("+1".into()),
            callername: None,
            called: Some("+2".into()),
            sipcallerip: Some(0x0a00_0001), // 10.0.0.1
            sipcalledip: Some(0x0a00_0002), // 10.0.0.2
            last_sip_response_num: Some(200),
            mos_min_mult10: None,
            a_lost: None,
            b_lost: None,
            id_sensor: None,
            a_mos_lqo_mult10: None,
            b_mos_lqo_mult10: None,
            a_received: None,
            b_received: None,
            a_avgjitter_mult10: None,
            b_avgjitter_mult10: None,
            a_maxjitter: None,
            b_maxjitter: None,
            a_packet_loss_perc_mult1000: None,
            b_packet_loss_perc_mult1000: None,
            a_delay_avg_mult100: None,
            b_delay_avg_mult100: None,
            a_rtcp_loss: None,
            b_rtcp_loss: None,
            a_rtcp_maxjitter: None,
            b_rtcp_maxjitter: None,
            a_payload: None,
            b_payload: None,
            a_rtp_ptime: None,
            b_rtp_ptime: None,
            a_saddr: Some(0x0a00_0001),
            b_saddr: Some(0x0a00_0002),
        };
        let s = CdrSummary::from(row);
        // SIP-level IPs stay where they were.
        assert_eq!(s.src_ip_str, "10.0.0.1");
        assert_eq!(s.dst_ip_str, "10.0.0.2");
        // RTP-level IPs land on the per-leg structs.
        assert_eq!(s.rtp_a.src_ip_str, "10.0.0.1");
        assert_eq!(s.rtp_a.dst_ip_str, "10.0.0.2");
        assert_eq!(s.rtp_b.src_ip_str, "10.0.0.2");
        assert_eq!(s.rtp_b.dst_ip_str, "10.0.0.1");
    }

    /// When VoIPmonitor didn't populate a_saddr / b_saddr, the RTP
    /// leg IPs must be empty strings, not "0.0.0.0".
    #[test]
    fn cdr_summary_rtp_leg_ips_empty_when_saddrs_unset() {
        use chrono::NaiveDate;
        let row = CdrRow {
            id: 8,
            calldate: NaiveDate::from_ymd_opt(2026, 10, 4)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            callend: NaiveDate::from_ymd_opt(2026, 10, 4)
                .unwrap()
                .and_hms_opt(0, 0, 1)
                .unwrap(),
            duration: None,
            connect_duration: None,
            caller: None,
            callername: None,
            called: None,
            sipcallerip: None,
            sipcalledip: None,
            last_sip_response_num: None,
            mos_min_mult10: None,
            a_lost: None,
            b_lost: None,
            id_sensor: None,
            a_mos_lqo_mult10: Some(40), // populated so is_populated() is true
            b_mos_lqo_mult10: None,
            a_received: None,
            b_received: None,
            a_avgjitter_mult10: None,
            b_avgjitter_mult10: None,
            a_maxjitter: None,
            b_maxjitter: None,
            a_packet_loss_perc_mult1000: None,
            b_packet_loss_perc_mult1000: None,
            a_delay_avg_mult100: None,
            b_delay_avg_mult100: None,
            a_rtcp_loss: None,
            b_rtcp_loss: None,
            a_rtcp_maxjitter: None,
            b_rtcp_maxjitter: None,
            a_payload: None,
            b_payload: None,
            a_rtp_ptime: None,
            b_rtp_ptime: None,
            a_saddr: None,
            b_saddr: None,
        };
        let s = CdrSummary::from(row);
        assert_eq!(s.rtp_a.src_ip_str, "");
        assert_eq!(s.rtp_a.dst_ip_str, "");
        assert_eq!(s.rtp_b.src_ip_str, "");
        assert_eq!(s.rtp_b.dst_ip_str, "");
    }
}
