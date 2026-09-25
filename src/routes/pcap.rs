//! PCAP download endpoints.
//!
//! VoIPmonitor stores pcaps minute-bucketed and zstd-compressed into
//! per-type tar archives:
//!
//!     {PCAP_DIR}/YYYY-MM-DD/HH/MM/{TYPE}/{TYPE}_YYYY-MM-DD-HH-MM.tar.zst
//!
//! with `TYPE` ∈ {SIP, RTP, GRAPH, OTHER}. The `cdr_tar_part` table maps
//! each CDR to one or more byte offsets (`pos`) inside the matching
//! tar.zst file — one row per (cdr_ID, calldate, type) bucket.
//!
//! We decompress the archive once, walk it as a tar stream, and pull
//! out just the slice the caller asked for. When a CDR has multiple
//! parts (e.g. SIP+RTP), we concatenate them into a single pcap file.
//! Each pcap starts with its own 24-byte global header, so we strip
//! the header from all but the first chunk to keep Wireshark happy.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use axum::{
    body::Body,
    extract::{Path as AxPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use chrono::{Duration, NaiveDateTime, NaiveTime, Timelike};
use lzo;
use sqlx::{MySqlPool, Row};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    auth::session::SessionUser,
    error::{AppError, AppResult},
    state::AppState,
};

/// Pcap global header is exactly 24 bytes; we strip it from all but the
/// first chunk when concatenating SIP+RTP into a single pcap.
const PCAP_GLOBAL_HEADER_LEN: usize = 24;

/// What to pull from a given archive: a precise slice (used when
/// `cdr_tar_part.pos` is known) or the full pcap (used as a fallback
/// when only GRAPH parts exist for this CDR).
#[derive(Debug, Clone)]
enum SliceKind {
    /// Start at this byte offset inside the inner pcap.
    From(u64),
    /// Use the entire pcap.
    Full,
    /// Use only the inner tar entry whose name equals this string
    /// (matched with or without a `.pcap` extension).
    ByName(String),
}

/// One archive to stream, with how to slice it.
#[derive(Debug, Clone)]
struct PcapSource {
    archive: PathBuf,
    slice: SliceKind,
    /// Free-form label used in log lines and the response header.
    label: String,
}

/// `cdr_tar_part` row — the only columns we need.
#[derive(Debug, Clone)]
struct TarPartRow {
    calldate: NaiveDateTime,
    pos: u64,
    /// 0 = SIP, 1 = RTP, 2 = GRAPH, anything else = OTHER
    type_: u8,
}

impl TarPartRow {
    fn from_row(r: &sqlx::mysql::MySqlRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            calldate: r.try_get("calldate")?,
            pos: r.try_get::<u64, _>("pos")?,
            // `type` is TINYINT UNSIGNED in voipmonitor's schema.
            type_: r.try_get::<u8, _>("type")?,
        })
    }
}

/// Look up a CDR's tar parts and stream its combined pcap to the client.
pub async fn download_single(
    State(state): State<AppState>,
    user: SessionUser,
    AxPath(cdr_id): AxPath<u64>,
) -> AppResult<Response> {
    if !user.can_pcap {
        return Err(AppError::Forbidden);
    }

    let pcap_bytes = build_pcap_bytes(&state, cdr_id).await?;

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        if tx.send(Ok(Bytes::from(pcap_bytes))).await.is_err() {
            // client disconnected
        }
    });

    let body = Body::from_stream(ReceiverStream::new(rx));
    let filename = format!("cdr-{cdr_id}.pcap");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/vnd.tcpdump.pcap")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(body)
        .map_err(|e| AppError::Internal(format!("response build: {e}")))?)
}

/// Per-CDR pcap reconstruction. Used by both `download_single` and
/// `download_batch` so the byte format stays identical across endpoints.
///
/// Returns the full merged pcap bytes (header + every packet from SIP
/// and RTP sources for the call, sorted by timestamp). The caller decides
/// how to ship those bytes back to the client.
async fn build_pcap_bytes(state: &AppState, cdr_id: u64) -> AppResult<Vec<u8>> {
    let parts = crate::error::with_query_timeout(
        state.config.query_timeout_secs,
        fetch_parts(&state.pool, cdr_id),
    )
    .await?;
    let fbasename = crate::error::with_query_timeout(
        state.config.query_timeout_secs,
        fetch_fbasename(&state.pool, cdr_id),
    )
    .await
    .ok()
    .flatten();

    // Three paths, in order of precision:
    //   1. cdr_tar_part has SIP/RTP rows with byte offsets → use them
    //   2. Otherwise, look up the CDR's fbasename and search the SIP/RTP
    //      archives across the call's minute range for a matching
    //      per-call pcap file
    //   3. Last resort: download the whole minute's pcap and let the
    //      user filter in Wireshark
    let sources: Vec<PcapSource> = if parts.iter().any(|p| p.type_ != 2) {
        build_sources_from_parts(&state.config.pcap_dir, parts)
    } else if let Some(ref fb) = fbasename {
        let (from, to) = fetch_cdr_time_range(&state.pool, cdr_id).await?;
        build_sources_from_fbasename(&state.config.pcap_dir, from, to, fb)
    } else if !parts.is_empty() {
        tracing::warn!(
            cdr_id,
            "cdr_tar_part only has GRAPH entries and no cdr_next.fbasename; falling back to minute-range download"
        );
        let (from, to) = fetch_cdr_time_range(&state.pool, cdr_id).await?;
        build_sources_from_minutes(&state.config.pcap_dir, from, to)
    } else {
        match fetch_cdr_time_range(&state.pool, cdr_id).await {
            Ok((from, to)) => build_sources_from_minutes(&state.config.pcap_dir, from, to),
            Err(_) => return Err(AppError::NotFound),
        }
    };

    if sources.is_empty() {
        return Err(AppError::NotFound);
    }

    let total_sources = sources.len();

    // Resolve every source into a flat list of chunks up front so the
    // merge step has nothing to do except emit bytes. This avoids any
    // thread-local / async-state trickery for the "this source has
    // multiple chunks (RTP #N)" case.
    let resolver = state.clone();
    let resolved: Vec<Result<Vec<u8>, AppError>> = {
        let mut out = Vec::with_capacity(sources.len());
        for src in &sources {
            out.push(resolve_source_to_chunks(&resolver, cdr_id, src).await);
        }
        out
    };

    // The merge + LZO-decompress path is sync + CPU-bound, so it lives
    // on a blocking worker. The async side just feeds it pre-resolved
    // tar chunks and a return channel.
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::task::spawn_blocking(move || {
        // Collect raw pcap blobs (each with its own header if present).
        // merge_pcaps() picks the first valid header, parses every blob
        // (stripping per-blob headers when present), and emits packets
        // sorted by timestamp — same approach as `mergecap -w`.
        let blobs: Vec<Vec<u8>> = resolved.into_iter().flatten().collect();
        if blobs.is_empty() {
            tracing::warn!(cdr_id, "no pcap blobs collected");
            let _ = tx.send(Vec::new());
            return;
        }
        // Some VoIPmonitor archives store RTP chunks as LZO-compressed
        // pcaps (prefixed with a 12-byte "LZO\x9a" + metadata header).
        // Decompress those inline so merge_pcaps sees plain pcaps.
        let mut lzo_decompressed = 0usize;
        let blobs: Vec<Vec<u8>> = blobs
            .into_iter()
            .map(|mut blob| {
                if is_voipmonitor_lzo(&blob) {
                    match decompress_voipmonitor_lzo(&blob) {
                        Ok(Some(dec)) => {
                            lzo_decompressed += 1;
                            blob = dec;
                        }
                        Ok(None) => {} // shouldn't happen, is_voipmonitor_lzo was true
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "LZO decompress failed; passing blob through"
                            );
                        }
                    }
                }
                blob
            })
            .collect();
        if lzo_decompressed > 0 {
            tracing::info!(
                lzo_decompressed,
                "LZO-decompressed RTP chunks before pcap merge"
            );
        }
        // Pick the first valid pcap header. Fall back to a synthetic
        // Ethernet/Little-Endian header if none of the blobs have one.
        let mut primary_header: [u8; 24] = {
            let mut h = [0u8; 24];
            h[0..4].copy_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // LE magic
            h[4..6].copy_from_slice(&[2, 4]); // version 2.4
            h[8..12].copy_from_slice(&0xffff_u32.to_le_bytes()); // snaplen
            h[20..24].copy_from_slice(&1_u32.to_le_bytes()); // LINKTYPE_ETHERNET
            h
        };
        for blob in &blobs {
            if blob.len() >= 24 && is_pcap_magic(&blob[..4]) {
                primary_header.copy_from_slice(&blob[..24]);
                break;
            }
        }

        let blob_refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let merged = merge_pcaps(&primary_header, &blob_refs);

        tracing::info!(
            cdr_id,
            blobs = blob_refs.len(),
            sources = total_sources,
            output_bytes = merged.len(),
            "pcap build complete"
        );

        let _ = tx.send(merged);
    });

    let merged = rx.await.map_err(|_| {
        AppError::Internal("pcap builder thread dropped before sending result".into())
    })?;
    if merged.is_empty() {
        return Err(AppError::NotFound);
    }
    Ok(merged)
}

/// Resolve one `PcapSource` to one or more byte chunks ready to stream.
///
/// For `SliceKind::From`/`Full`, the result is a single chunk (or empty on
/// error). For `SliceKind::ByName`, the result may be multiple chunks
/// (RTP captures split across `<fbasename>.pcap#0`, `.pcap#1`, …) — they
/// all get returned in tar order so the streaming pipeline can concat
/// them with a single global-header strip after the first chunk.
async fn resolve_source_to_chunks(
    _state: &AppState,
    cdr_id: u64,
    src: &PcapSource,
) -> Result<Vec<u8>, AppError> {
    let archive = match read_archive(&src.archive) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(
                error = ?e,
                path = %src.archive.display(),
                label = %src.label,
                "failed to read pcap archive"
            );
            return Err(AppError::Internal(format!("read archive: {e}")));
        }
    };
    match &src.slice {
        SliceKind::ByName(name) => {
            let chunks = find_files_in_tar_by_name(&archive, name);
            if chunks.is_empty() {
                tracing::warn!(
                    path = %src.archive.display(),
                    target = %name,
                    label = %src.label,
                    "fbasename not found in this archive; skipping"
                );
                return Ok(Vec::new());
            }
            // Per-chunk header detection. Each chunk's first 4 bytes tell
            // us whether it's a self-contained pcap (needs 24-byte header
            // stripped before concat), a pcapng Section Header Block
            // (needs SHB stripped — but currently we just keep as-is and
            // warn), or raw concatenated pcap packet records (no header).
            let chunk_kinds: Vec<&'static str> = chunks
                .iter()
                .map(|c| {
                    if c.len() >= 4 && (&c[..4] == b"\xd4\xc3\xb2\xa1" || &c[..4] == b"\xa1\xb2\xc3\xd4") {
                        "pcap"
                    } else if c.len() >= 4 && &c[..4] == b"\x0a\x0d\x0d\x0a" {
                        "pcapng"
                    } else if c.len() >= 3 && &c[..3] == b"LZO" {
                        "lzo"
                    } else {
                        "raw"
                    }
                })
                .collect();
            let chunk_sizes: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
            tracing::info!(
                path = %src.archive.display(),
                target = %name,
                chunks = chunks.len(),
                kinds = ?chunk_kinds,
                sizes = ?chunk_sizes,
                "fbasename matched in archive"
            );
            // Build the concat buffer per-chunk:
            //   - "pcap" chunks: strip the 24-byte global header
            //   - "pcapng" chunks: keep as-is (pcapng SHBs must stay;
            //     reader will skip them only if the file is full pcapng,
            //     which our output isn't — so we WARN about these below)
            //   - "raw" chunks: keep as-is
            let total: usize = chunks
                .iter()
                .zip(chunk_kinds.iter())
                .map(|(c, k)| {
                    if *k == "pcap" {
                        c.len().saturating_sub(PCAP_GLOBAL_HEADER_LEN)
                    } else {
                        c.len()
                    }
                })
                .sum();
            if chunk_kinds.iter().any(|k| *k == "pcapng") {
                tracing::warn!(
                    "RTP chunks include pcapng format; concatenated output may be unreadable"
                );
            }
            let mut buf = Vec::with_capacity(total);
            for (c, k) in chunks.iter().zip(chunk_kinds.iter()) {
                if *k == "pcap" && c.len() > PCAP_GLOBAL_HEADER_LEN {
                    buf.extend_from_slice(&c[PCAP_GLOBAL_HEADER_LEN..]);
                } else {
                    buf.extend_from_slice(c);
                }
            }
            Ok(buf)
        }
        SliceKind::From(pos) => {
            let pcap = match find_pcap_in_tar(&archive) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        error = ?e,
                        path = %src.archive.display(),
                        label = %src.label,
                        "no .pcap entry in archive (GRAPH-only?)"
                    );
                    return Ok(Vec::new());
                }
            };
            let start = *pos as usize;
            if start > pcap.len() {
                tracing::error!(
                    cdr_id,
                    pos = *pos,
                    pcap_len = pcap.len(),
                    label = %src.label,
                    "pos past end of inner pcap"
                );
                return Ok(Vec::new());
            }
            Ok(pcap[start..].to_vec())
        }
        SliceKind::Full => match find_pcap_in_tar(&archive) {
            Ok(p) => Ok(p.to_vec()),
            Err(e) => {
                tracing::error!(
                    error = ?e,
                    path = %src.archive.display(),
                    label = %src.label,
                    "no .pcap entry in archive (GRAPH-only?)"
                );
                Ok(Vec::new())
            }
        },
    }
}

/// Build the source list when `cdr_tar_part` has at least one row — use
/// each row's pos to slice precisely into the matching archive.
fn build_sources_from_parts(pcap_dir: &Path, parts: Vec<TarPartRow>) -> Vec<PcapSource> {
    let mut by_file: HashMap<PathBuf, Vec<TarPartRow>> = HashMap::new();
    for p in parts {
        let path = match resolve_archive_path(pcap_dir, p.calldate, p.type_) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    calldate = %p.calldate,
                    type_ = p.type_,
                    "no tar.zst archive found for this part; skipping"
                );
                continue;
            }
        };
        by_file.entry(path).or_default().push(p);
    }
    let mut out: Vec<PcapSource> = Vec::new();
    for (archive, rows) in by_file {
        for r in rows {
            out.push(PcapSource {
                archive: archive.clone(),
                slice: SliceKind::From(r.pos),
                label: format!("type={} pos={}", r.type_, r.pos),
            });
        }
    }
    // Stable order: SIP (0) → RTP (1) → GRAPH (2) → OTHER, then by path.
    out.sort_by_key(|s| {
        let first_type = match &s.slice {
            SliceKind::Full => 0,
            SliceKind::From(_) | SliceKind::ByName(_) => {
                // Best-effort: parse the type from the label.
                s.label
                    .strip_prefix("type=")
                    .and_then(|t| t.split(' ').next())
                    .and_then(|t| t.parse::<u8>().ok())
                    .unwrap_or(255)
            }
        };
        (first_type, s.archive.clone())
    });
    out
}

/// Build a source list covering every minute from `from` to `to`
/// (inclusive) using the SIP archive (type=0) for each minute. Falls
/// back to RTP (type=1) if no SIP archive exists for a given minute.
/// This is the fallback path used when `cdr_tar_part` only has GRAPH
/// entries, so we don't have byte offsets into the SIP/RTP pcaps.
fn build_sources_from_minutes(
    pcap_dir: &Path,
    from: NaiveDateTime,
    to: NaiveDateTime,
) -> Vec<PcapSource> {
    let mut out = Vec::new();
    let mut cur = floor_to_minute(from);
    let end = floor_to_minute(to);
    while cur <= end {
        // Try SIP first, then RTP — covers most calls. Skips any minute
        // where neither archive exists.
        for type_ in [0u8, 1u8] {
            if let Some(p) = resolve_archive_path(pcap_dir, cur, type_) {
                out.push(PcapSource {
                    archive: p,
                    slice: SliceKind::Full,
                    label: format!("{} type={}", cur.format("%Y-%m-%d %H:%M"), type_),
                });
                break; // SIP found; don't also pull RTP for the same minute
            }
        }
        cur += Duration::minutes(1);
    }
    out
}

/// Truncate seconds+ns to the start of the minute.
fn floor_to_minute(dt: NaiveDateTime) -> NaiveDateTime {
    NaiveDateTime::new(dt.date(), NaiveTime::from_hms_opt(dt.hour(), dt.minute(), 0).unwrap())
}

async fn fetch_cdr_time_range(
    pool: &MySqlPool,
    cdr_id: u64,
) -> AppResult<(NaiveDateTime, NaiveDateTime)> {
    let row: Option<(NaiveDateTime, NaiveDateTime)> = sqlx::query_as(
        "SELECT calldate, callend FROM cdr WHERE ID = ? LIMIT 1",
    )
    .bind(cdr_id)
    .fetch_optional(pool)
    .await?;
    let (from, to) = row.ok_or(AppError::NotFound)?;
    Ok((from, to))
}

/// Look up `cdr_next.fbasename` — the per-call pcap filename VoIPmonitor
/// uses inside its tar archives. Used to locate the call's pcap when
/// `cdr_tar_part` doesn't have SIP/RTP byte offsets (the common case
/// where only GRAPH entries are indexed).
async fn fetch_fbasename(pool: &MySqlPool, cdr_id: u64) -> AppResult<Option<String>> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT fbasename FROM cdr_next WHERE cdr_ID = ? LIMIT 1",
    )
    .bind(cdr_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(f,)| f))
}

/// Walk every minute the call spans, look in the SIP archive (and RTP
/// as fallback) for an inner pcap whose name matches `fbasename`. Used
/// when `cdr_tar_part` is GRAPH-only on this install — the inner pcaps
/// still exist, they're just one file per call instead of one combined
/// pcap with byte offsets.
fn build_sources_from_fbasename(
    pcap_dir: &Path,
    from: NaiveDateTime,
    to: NaiveDateTime,
    fbasename: &str,
) -> Vec<PcapSource> {
    let mut out = Vec::new();
    let mut cur = floor_to_minute(from);
    let end = floor_to_minute(to);
    while cur <= end {
        // Try SIP first (most pcap data is here for most installs), then
        // RTP. Each archive may use .tar.zst or plain .tar — handled by
        // read_archive().
        for type_ in [0u8, 1u8] {
            if let Some(p) = resolve_archive_path(pcap_dir, cur, type_) {
                out.push(PcapSource {
                    archive: p,
                    slice: SliceKind::ByName(fbasename.to_string()),
                    label: format!(
                        "{} type={} name={}",
                        cur.format("%Y-%m-%d %H:%M"),
                        type_,
                        fbasename
                    ),
                });
            }
        }
        cur += Duration::minutes(1);
    }
    out
}

/// Maximum number of CDRs accepted in a single batch download. Keeps the
/// in-memory zip bounded and avoids pathological client requests that
/// would consume worker threads for minutes.
const BATCH_MAX: usize = 100;

/// Request body for `POST /pcap/batch`. A plain JSON object with one
/// field — the caller decides which IDs (filter-driven, manual paste,
/// checkbox selection, …).
#[derive(serde::Deserialize)]
pub struct BatchPcapRequest {
    pub ids: Vec<u64>,
}

/// Batch download — produce a zip of N pcaps, one entry per CDR.
///
/// The flow:
///   1. Validate `ids` (dedupe, drop zero, cap at `BATCH_MAX`).
///   2. Spawn one async task per CDR. Each calls `build_pcap_bytes` and
///      pushes `(cdr_id, Vec<u8>)` into a tokio mpsc.
///   3. A `spawn_blocking` task pulls from that mpsc and writes a zip
///      into a `Vec<u8>`. We use the sync `zip` crate inside the blocking
///      worker because its std I/O API plays well with `tokio::sync::mpsc`'s
///      `blocking_recv()`; async-zip's duplex-stream wiring is more code
///      for no real win at this batch size.
///   4. Once the zip is finalised, the buffer goes into the response body
///      via another mpsc. Failures inside one CDR are logged and the
///      entry is skipped — a single bad CDR doesn't fail the whole batch.
pub async fn download_batch(
    State(state): State<AppState>,
    user: SessionUser,
    axum::Json(req): axum::Json<BatchPcapRequest>,
) -> AppResult<Response> {
    if !user.can_pcap {
        return Err(AppError::Forbidden);
    }

    // Dedupe + drop zero + cap. Preserves the caller's order so the zip
    // entries are deterministic for a given selection.
    let mut seen = std::collections::HashSet::with_capacity(req.ids.len());
    let mut cdr_ids: Vec<u64> = Vec::with_capacity(req.ids.len());
    for id in req.ids {
        if id > 0 && seen.insert(id) {
            cdr_ids.push(id);
        }
    }
    if cdr_ids.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            "no valid CDR IDs in request",
        )
            .into_response());
    }
    if cdr_ids.len() > BATCH_MAX {
        return Ok((
            StatusCode::BAD_REQUEST,
            format!(
                "batch too large: {} IDs (max {BATCH_MAX})",
                cdr_ids.len()
            ),
        )
            .into_response());
    }

    let total = cdr_ids.len();
    tracing::info!(count = total, "batch pcap download requested");

    // Async pipeline: each CDR builds its bytes concurrently.
    let (pcap_tx, mut pcap_rx) =
        mpsc::channel::<(u64, AppResult<Vec<u8>>)>(total.max(1));
    for cdr_id in cdr_ids {
        let state = state.clone();
        let pcap_tx = pcap_tx.clone();
        tokio::spawn(async move {
            let result = build_pcap_bytes(&state, cdr_id).await;
            // Receiver is dropped below; if it's gone, the client
            // disconnected — that's fine.
            let _ = pcap_tx.send((cdr_id, result)).await;
        });
    }
    drop(pcap_tx);

    // Blocking pipeline: zip writer consumes pcaps and emits bytes.
    let (body_tx, body_rx) =
        mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut buf: Vec<u8> = Vec::new();
        let mut written = 0usize;
        let mut failed = 0usize;
        // We build the zip inside a small helper so the inner Cursor
        // (which mutably borrows `buf`) is fully dropped before we
        // move `buf` into Bytes.
        let zip_result: Result<(), zip::result::ZipError> = (|| {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            // Deflate level 1 — pcap frames compress ~40% at level 1 and
            // we don't care about zip latency since the client is already
            // paying per-CDR pcap-build time.
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .compression_level(Some(1));

            while let Some((cdr_id, result)) = pcap_rx.blocking_recv() {
                match result {
                    Ok(pcap_bytes) => {
                        let name = format!("cdr-{cdr_id}.pcap");
                        if let Err(e) = zip.start_file(&name, options) {
                            tracing::error!(
                                cdr_id, error = %e, "batch zip: start_file failed"
                            );
                            failed += 1;
                            continue;
                        }
                        if let Err(e) = zip.write_all(&pcap_bytes) {
                            tracing::error!(
                                cdr_id, error = %e, "batch zip: write_all failed"
                            );
                            failed += 1;
                            continue;
                        }
                        written += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            cdr_id, error = %e, "batch zip: skipping CDR"
                        );
                        failed += 1;
                    }
                }
            }
            zip.finish().map(|_| ())
        })();

        match zip_result {
            Ok(()) => {
                tracing::info!(
                    requested = total,
                    written,
                    failed,
                    bytes = buf.len(),
                    "batch pcap zip complete"
                );
                let _ = body_tx.blocking_send(Ok(Bytes::from(buf)));
            }
            Err(e) => {
                let msg = format!("zip finish failed: {e}");
                tracing::error!(error = %e, "batch zip finish failed");
                let _ = body_tx.blocking_send(Err(std::io::Error::other(msg)));
            }
        }
    });

    let body = Body::from_stream(ReceiverStream::new(body_rx));
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"pcaps.zip\"",
        )
        .body(body)
        .map_err(|e| AppError::Internal(format!("response build: {e}")))?)
}

async fn fetch_parts(pool: &MySqlPool, cdr_id: u64) -> AppResult<Vec<TarPartRow>> {
    let rows = sqlx::query(
        "SELECT calldate, pos, `type` \
           FROM cdr_tar_part WHERE cdr_ID = ? \
           ORDER BY calldate, `type`",
    )
    .bind(cdr_id)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(TarPartRow::from_row(r)?);
    }
    Ok(out)
}

/// Resolve `{PCAP_DIR}/YYYY-MM-DD/HH/MM/{TYPE}/{TYPE}_YYYY-MM-DD-HH-MM.tar.zst`
/// to a real path on disk. VoIPmonitor is wildly inconsistent across
/// versions — sometimes `GRAPH/graph_*.tar.zst`, sometimes
/// `graph/graph_*.tar.zst`, sometimes `GRAPH/GRAPH_*.tar.zst`. We do a
/// case-insensitive scan of the minute dir to find whatever's there.
fn resolve_archive_path(
    pcap_dir: &Path,
    calldate: NaiveDateTime,
    type_: u8,
) -> Option<PathBuf> {
    // Map numeric type to the canonical lowercase type name.
    let type_lc = match type_ {
        0 => "sip",
        1 => "rtp",
        2 => "graph",
        _ => "other",
    };

    let minute_dir = pcap_dir
        .join(calldate.format("%Y-%m-%d").to_string())
        .join(calldate.format("%H").to_string())
        .join(calldate.format("%M").to_string());

    // Scan immediate subdirs (case-insensitive) for one whose name
    // matches our type, then look for any *.tar.zst inside it.
    let entries = std::fs::read_dir(&minute_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = entry.file_name();
        let Some(dir_name) = dir_name.to_str() else { continue };
        if dir_name.to_ascii_lowercase() != type_lc {
            continue;
        }
        // Found the type dir (case-corrected). Pick any .tar.zst or .tar
        // inside it (SIP/GRAPH uses zstd, RTP uses uncompressed tar on
        // some installs — read_archive() picks the right decoder).
        let inner = std::fs::read_dir(&path).ok()?;
        for inner_entry in inner.flatten() {
            let inner_path = inner_entry.path();
            if !inner_path.is_file() {
                continue;
            }
            let Some(name) = inner_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let lname = name.to_ascii_lowercase();
            if lname.ends_with(".tar.zst") || lname.ends_with(".tar") {
                return Some(inner_path);
            }
        }
    }
    None
}

/// Build the full archive path for a given type-name casing. Test-only
/// helper — production lookups go through `resolve_archive_path` which
/// scans the disk case-insensitively.
#[cfg(test)]
fn compute_path_with(
    pcap_dir: &Path,
    calldate: NaiveDateTime,
    type_name: &str,
) -> PathBuf {
    pcap_dir
        .join(calldate.format("%Y-%m-%d").to_string())
        .join(calldate.format("%H").to_string())
        .join(calldate.format("%M").to_string())
        .join(type_name)
        .join(format!(
            "{type_name}_{}.tar.zst",
            calldate.format("%Y-%m-%d-%H-%M")
        ))
}

/// Read an entire tar archive (compressed or plain) into memory.
/// VoIPmonitor uses `.tar.zst` for SIP/GRAPH and `.tar` (uncompressed)
/// for RTP — handle both. Also tolerates a truncated trailing zstd
/// frame when capture is still in progress.
fn read_archive(path: &Path) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let is_zst = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".tar.zst"))
        .unwrap_or(false);
    let mut out = Vec::new();
    if is_zst {
        let mut dec = zstd::Decoder::new(f)?;
        match dec.read_to_end(&mut out) {
            Ok(_) => Ok(out),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::warn!(
                    path = %path.display(),
                    bytes = out.len(),
                    "zstd stream truncated (capture still in progress); returning partial archive"
                );
                Ok(out)
            }
            Err(e) => Err(e),
        }
    } else {
        // Plain tar.
        let mut r = std::io::BufReader::new(f);
        r.read_to_end(&mut out)?;
        Ok(out)
    }
}

/// Walk the (decompressed) tar and return **all** entry bodies whose
/// name matches `target_name` (the `cdr_next.fbasename`).
///
/// VoIPmonitor stores pcaps as one file per call, named
/// `<fbasename>.pcap`. Some installs add a `#<chunk>` suffix for
/// RTP captures split across multiple files, e.g.
/// `WTL_xxx.pcap#0`, `WTL_xxx.pcap#1`, …, `WTL_xxx.pcap#480`. We match:
///   - exact `<target_name>` or `<target_name>.pcap`
///   - any name starting with `<target_name>.pcap#` (chunked)
///
/// Returns bodies in tar order — caller concatenates them, stripping
/// the 24-byte pcap global header from every chunk after the first.
fn find_files_in_tar_by_name<'a>(
    archive: &'a [u8],
    target_name: &str,
) -> Vec<&'a [u8]> {
    let exact = [
        target_name.to_string(),
        format!("{}.pcap", target_name),
    ];
    let chunked_prefix = format!("{}.pcap#", target_name);
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 512 <= archive.len() {
        let header = &archive[offset..offset + 512];
        let raw_name = &header[0..100];
        let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(100);
        let entry_name = std::str::from_utf8(&raw_name[..name_end])
            .unwrap_or("")
            .trim_end();
        let size = match parse_tar_size(&header[124..136]) {
            Ok(s) => s as usize,
            Err(_) => break,
        };
        if entry_name.is_empty() && size == 0 {
            break;
        }
        let body_start = offset + 512;
        let body_end = (body_start + size).min(archive.len());

        if exact.iter().any(|c| c == entry_name) || entry_name.starts_with(&chunked_prefix) {
            out.push(&archive[body_start..body_end]);
        }

        let padded = (size + 511) & !511;
        offset = body_start + padded;
    }
    out
}

/// Walk the (decompressed) tar and return a slice that points at the
/// start of the `.pcap` entry's body. Each VoIPmonitor minute-bucket
/// tar.zst wraps a single inner pcap file that contains all the calls
/// captured during that minute.
///
/// `cdr_tar_part.pos` is the byte offset **within that inner pcap**, not
/// within the tar itself — so we ignore tar offsets and slice from `pos`
/// into the pcap body.
#[cfg(test)]
fn extract_at_pos(archive: &[u8], pos: u64) -> std::io::Result<&[u8]> {
    let pcap = find_pcap_in_tar(archive)?;
    let pos = pos as usize;
    if pos > pcap.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "pos {pos} past end of inner pcap ({} bytes)",
                pcap.len()
            ),
        ));
    }
    // If the pcap is truncated (capture still in progress), return
    // whatever bytes we have rather than failing.
    Ok(&pcap[pos..])
}

/// Iterate tar entries until we find a `.pcap` file, then return its
/// raw body slice. Tar entries are 512-byte-aligned (size rounded up).
fn find_pcap_in_tar(archive: &[u8]) -> std::io::Result<&[u8]> {
    let mut offset = 0usize;
    while offset + 512 <= archive.len() {
        let header = &archive[offset..offset + 512];
        // Name is null-terminated ASCII in the first 100 bytes.
        let raw_name = &header[0..100];
        let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(100);
        let name = std::str::from_utf8(&raw_name[..name_end])
            .unwrap_or("")
            .trim_end();
        let size = parse_tar_size(&header[124..136])? as usize;
        // Two zero blocks at the end of a tar = end of archive.
        if name.is_empty() && size == 0 {
            break;
        }
        let body_start = offset + 512;
        let body_end = (body_start + size).min(archive.len());
        if name.ends_with(".pcap") {
            return Ok(&archive[body_start..body_end]);
        }
        // Round size up to a multiple of 512 (tar block alignment).
        let padded = (size + 511) & !511;
        offset = body_start + padded;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no .pcap entry found in tar archive",
    ))
}

/// Merge multiple pcap blobs into a single pcap by sorting all packets
/// across the inputs by their timestamp. Equivalent to `mergecap -w`.
/// Returns the merged bytes (header from `primary_header` + sorted packets).
///
/// `primary_header` must be the 24-byte pcap global header from the
/// first input — we use its link type and snaplen in the output. The
/// input blobs may each be a full pcap (with header) or just the raw
/// concatenated packet records (no header); we detect per-blob.
fn merge_pcaps(primary_header: &[u8; 24], blobs: &[&[u8]]) -> Vec<u8> {
    // Walk each blob, collect (timestamp, packet_bytes) pairs. Indices
    // into `records_storage` keep the borrowed slice alive across the
    // closure so we can sort/ship them out.
    let mut records_storage: Vec<&[u8]> = Vec::new();
    let mut packets: Vec<(u64, usize)> = Vec::new();
    let mut per_blob_counts: Vec<usize> = Vec::new();
    let mut truncated_count = 0usize;
    for blob in blobs {
        let had_header = blob.len() >= 24 && is_pcap_magic(&blob[..4]);
        let body = if had_header {
            &blob[24..] // strip header
        } else {
            blob // raw packet records, no header
        };
        let mut off = 0usize;
        let mut count = 0usize;
        while off + 16 <= body.len() {
            let ts_sec = u32::from_le_bytes(body[off..off + 4].try_into().unwrap()) as u64;
            let ts_usec = u32::from_le_bytes(body[off + 4..off + 8].try_into().unwrap()) as u64;
            let incl_len =
                u32::from_le_bytes(body[off + 8..off + 12].try_into().unwrap()) as usize;
            let ts = ts_sec.saturating_mul(1_000_000).saturating_add(ts_usec);
            let record_len = 16 + incl_len;
            if body.len() < off + record_len {
                truncated_count += 1;
                break;
            }
            let idx = records_storage.len();
            records_storage.push(&body[off..off + record_len]);
            packets.push((ts, idx));
            count += 1;
            off += record_len;
        }
        per_blob_counts.push(count);
    }
    // Sort by timestamp ascending (stable so identical ts preserves order).
    packets.sort_by_key(|(ts, _)| *ts);

    tracing::info!(
        blobs = blobs.len(),
        per_blob = ?per_blob_counts,
        truncated = truncated_count,
        total_packets = packets.len(),
        "merge_pcaps parsed"
    );

    let total: usize = records_storage.iter().map(|r| r.len()).sum();
    let mut out = Vec::with_capacity(24 + total);
    out.extend_from_slice(primary_header);
    for (_, idx) in &packets {
        out.extend_from_slice(records_storage[*idx]);
    }
    out
}

fn is_pcap_magic(magic: &[u8]) -> bool {
    magic.len() >= 4 && (magic == b"\xd4\xc3\xb2\xa1" || magic == b"\xa1\xb2\xc3\xd4")
}

/// Detect VoIPmonitor's LZO-compressed pcap variant: the first 3 bytes
/// are the marker `LZO`. What follows is a sequence of chunks, each
/// prefixed by an 8-byte header (LE u32 compressed_size, LE u32
/// uncompressed size) followed by `compressed_size` bytes of LZO1X-1
/// compressed data decompressing to `uncompressed size` bytes.
///
/// The format comes from `tools_dynamic_buffer.cpp::CompressStream` in
/// voipmonitor/sniffer: when the writer constructs a `CompressStream`
/// for `lzo` and calls both `enableAutoPrefixFile()` and
/// `enableForceStream()`, it emits exactly this layout (the 3-byte
/// "LZO" prefix is written once at the very start, not per chunk).
fn is_voipmonitor_lzo(magic: &[u8]) -> bool {
    magic.len() >= 3 && &magic[..3] == b"LZO"
}

/// Decompress a VoIPmonitor LZO-compressed pcap blob. The on-disk layout
/// (see `is_voipmonitor_lzo` for the spec) is a 3-byte `LZO` magic followed
/// by zero or more chunks. Each chunk is:
///
///     [u32 LE compress_size][u32 LE size][compress_size bytes LZO1X-1]
///
/// We use the chunk's `size` field as the exact output-buffer bound for
/// `lzo::decompress`, which avoids both the "buffer too small" failure
/// (when compressed data expands) and the "back-reference before output
/// start" failure (which is what a stray leading garbage byte from a bad
/// strip produced — see commit history).
///
/// `Ok(None)` if the blob doesn't look LZO-compressed. We tolerate a
/// trailing partial chunk (capture still in progress) by stopping the
/// loop; only a chunk whose header lies past the buffer or whose LZO
/// payload is short produces an error.
fn decompress_voipmonitor_lzo(blob: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
    if !is_voipmonitor_lzo(blob) {
        return Ok(None);
    }
    const CHUNK_HEADER_LEN: usize = 8;
    let mut out = Vec::new();
    let mut pos: usize = 3; // skip "LZO" prefix
    while pos + CHUNK_HEADER_LEN <= blob.len() {
        // sChunkSizeInfo layout (from voipmonitor/sniffer
        // tools_dynamic_buffer.h): { u32 size; u32 compress_size; }.
        // So the FIRST u32 after the prefix is the uncompressed length
        // and the SECOND u32 is how many compressed bytes follow.
        let size = u32::from_le_bytes(
            blob[pos..pos + 4].try_into().unwrap(),
        ) as usize;
        let compress_size = u32::from_le_bytes(
            blob[pos + 4..pos + 8].try_into().unwrap(),
        ) as usize;
        let payload_start = pos + CHUNK_HEADER_LEN;
        let payload_end = payload_start.saturating_add(compress_size);
        if payload_end > blob.len() {
            // Chunk header says more data than we have. Either a truncated
            // last chunk (capture still in progress) or a corrupt stream.
            // Be lenient: stop here and return what we have.
            break;
        }
        let compressed = &blob[payload_start..payload_end];
        let decompressed = lzo::decompress(compressed, size).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "lzo (chunk @ {}, compress_size={}, size={}): {e}",
                    pos, compress_size, size
                ),
            )
        })?;
        if decompressed.len() != size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "lzo decompressed length {} != expected size {} (chunk @ {})",
                    decompressed.len(),
                    size,
                    pos
                ),
            ));
        }
        out.extend_from_slice(&decompressed);
        pos = payload_end;
    }
    Ok(Some(out))
}

/// Parse a 12-byte tar size field. Handles:
///  - octal ASCII (POSIX ustar, null/space padded)
///  - GNU base-256 (high bit set on first byte → binary little-endian,
///    only the next 7 bytes carry value — 56 bits max)
fn parse_tar_size(field: &[u8]) -> std::io::Result<u64> {
    if field.is_empty() {
        return Ok(0);
    }
    if (field[0] & 0x80) != 0 {
        // GNU base-256: marker byte + 7 value bytes (little-endian).
        // VoIPmonitor's writer doesn't use this, but accept it for
        // forward-compat.
        let mut val: u64 = 0;
        for (i, b) in field.iter().take(8).enumerate() {
            if i == 0 {
                continue; // marker byte
            }
            val |= (*b as u64) << (8 * (i - 1));
        }
        Ok(val)
    } else {
        let s = std::str::from_utf8(field)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let trimmed = s.trim_matches(|c: char| c == '\0' || c == ' ');
        if trimmed.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(trimmed, 8).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad tar size {:?}: {e}", trimmed),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_size_octal() {
        // "00000002000\0" → 1024 bytes (decimal) = 0o2000
        let mut field = [0u8; 12];
        field[..11].copy_from_slice(b"00000002000");
        assert_eq!(parse_tar_size(&field).unwrap(), 1024);
    }

    #[test]
    fn tar_size_space_padded() {
        // Standard tar: leading spaces, octal value, NUL terminator.
        // 1024 decimal = 0o2000. Field is exactly 12 bytes (11 chars + NUL).
        let field = *b"      02000\0";
        assert_eq!(parse_tar_size(&field).unwrap(), 1024);
    }

    #[test]
    fn tar_size_zero() {
        let field = *b"00000000000\0";
        assert_eq!(parse_tar_size(&field).unwrap(), 0);
    }

    #[test]
    fn tar_size_gnu_base256() {
        // 0x80 marker, 0x00 0x00 0x00 0x00 0x00 0x04 0x00 0x00 = 1024
        let field = [0x80, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        // 0x0400 = 1024
        assert_eq!(parse_tar_size(&field).unwrap(), 1024);
    }

    #[test]
    fn compute_path_basic() {
        let dir = PathBuf::from("/var/spool/voipmonitor");
        let ts = NaiveDateTime::parse_from_str("2026-09-21 14:35:00", "%Y-%m-%d %H:%M:%S").unwrap();
        // All four known casings build a sensible path.
        for variant in ["sip", "SIP"] {
            let p = compute_path_with(&dir, ts, variant);
            let s = p.to_string_lossy().replace('\\', "/");
            assert!(s.ends_with(&format!("{variant}/{variant}_2026-09-21-14-35.tar.zst")), "got {s}");
        }
        for variant in ["rtp", "RTP"] {
            let p = compute_path_with(&dir, ts, variant);
            let s = p.to_string_lossy().replace('\\', "/");
            assert!(s.ends_with(&format!("{variant}/{variant}_2026-09-21-14-35.tar.zst")), "got {s}");
        }
        for variant in ["graph", "GRAPH"] {
            let p = compute_path_with(&dir, ts, variant);
            let s = p.to_string_lossy().replace('\\', "/");
            assert!(s.ends_with(&format!("{variant}/{variant}_2026-09-21-14-35.tar.zst")), "got {s}");
        }
        for variant in ["other", "OTHER"] {
            let p = compute_path_with(&dir, ts, variant);
            let s = p.to_string_lossy().replace('\\', "/");
            assert!(s.ends_with(&format!("{variant}/{variant}_2026-09-21-14-35.tar.zst")), "got {s}");
        }
    }

    /// Build a synthetic tar in memory containing one .pcap entry and
    /// verify the walker finds it and respects `pos` as a byte offset
    /// inside the pcap body.
    #[test]
    fn find_pcap_in_tar_respects_pos() {
        let pcap_body: Vec<u8> = (0..200u8).collect();
        let tar = build_tar_with_one_pcap("inner.pcap", &pcap_body);
        let found = find_pcap_in_tar(&tar).unwrap();
        assert_eq!(found, &pcap_body[..]);
        // Slice from offset 50 should give the last 150 bytes.
        let sliced = extract_at_pos(&tar, 50).unwrap();
        assert_eq!(sliced.len(), 150);
        assert_eq!(sliced[0], pcap_body[50]);
    }

    /// Helper: make a minimal pcap blob with one packet record at the
    /// given timestamp (in microseconds since epoch) carrying the given
    /// payload bytes. Used to test merge_pcaps().
    fn make_pcap_with_packet(ts_us: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // pcap global header (24 bytes): magic + version 2.4 + thiszone +
        // sigfigs + snaplen + linktype. Ethernet linktype = 1.
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // magic
        out.extend_from_slice(&[2, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ver + tz + sig
        out.extend_from_slice(&0xffff_u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&1_u32.to_le_bytes()); // linktype = Ethernet
        // Packet record (16 bytes header + payload): ts_sec + ts_usec +
        // incl_len + orig_len + payload.
        out.extend_from_slice(&((ts_us / 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&((ts_us % 1_000_000) as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// merge_pcaps should sort packets from multiple blobs by timestamp
    /// even if they arrive out of order, and should strip per-blob pcap
    /// headers so a raw-record-only blob is also accepted.
    #[test]
    fn merge_pcaps_sorts_by_timestamp() {
        let pcap_a = make_pcap_with_packet(2_000_000, b"AAA");
        let pcap_b = make_pcap_with_packet(1_000_000, b"BBB");
        let pcap_c = make_pcap_with_packet(3_000_000, b"CCC");
        let header: [u8; 24] = pcap_a[..24].try_into().unwrap();
        // Pass in reverse order — merge should still sort ascending.
        let merged = merge_pcaps(&header, &[&pcap_c, &pcap_a, &pcap_b]);
        assert_eq!(merged.len(), 24 + 3 * 19);
        // After the 24-byte primary header, packets appear in ts order.
        // ts_sec=1 (BBB), ts_sec=2 (AAA), ts_sec=3 (CCC).
        assert_eq!(
            u32::from_le_bytes(merged[24..28].try_into().unwrap()),
            1
        );
        assert_eq!(&merged[24 + 16..24 + 16 + 3], b"BBB");
        assert_eq!(
            u32::from_le_bytes(merged[43..47].try_into().unwrap()),
            2
        );
        assert_eq!(&merged[43 + 16..43 + 16 + 3], b"AAA");
        assert_eq!(
            u32::from_le_bytes(merged[62..66].try_into().unwrap()),
            3
        );
        assert_eq!(&merged[62 + 16..62 + 16 + 3], b"CCC");
    }

    /// Build a minimal tar with one named file of the given size, padded
    /// to the next 512-byte boundary. Format:
    ///   [name (100 bytes)][mode (8)][uid (8)][gid (8)][size (12)][mtime (12)]
    ///   [checksum (8)][typeflag (1)][linkname (100)][magic (6)][ver (2)]
    ///   [uname (32)][gname (32)][devmajor (8)][devminor (8)][prefix (155)]
    ///   ...padding to 512...
    ///   [body, padded to 512 multiple]
    ///   [two zero blocks (end-of-archive marker)]
    fn build_tar_with_one_pcap(name: &str, body: &[u8]) -> Vec<u8> {
        let mut tar = Vec::new();
        let mut header = [b' '; 512];
        // name (100 bytes)
        let name_bytes = name.as_bytes();
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        // mode "0000644\0"
        let mode = b"0000644\0";
        header[100..108].copy_from_slice(mode);
        // uid "0000000\0"
        let uid = b"0000000\0";
        header[108..116].copy_from_slice(uid);
        // gid "0000000\0"
        let gid = b"0000000\0";
        header[116..124].copy_from_slice(gid);
        // size as 11-byte octal + NUL
        let size_str = format!("{:011o}\0", body.len());
        header[124..136].copy_from_slice(size_str.as_bytes());
        // mtime "00000000000\0"
        let mtime = b"00000000000\0";
        header[136..148].copy_from_slice(mtime);
        // checksum placeholder: 8 spaces (tar checksums use sum of bytes
        // treating the checksum field as spaces — we don't validate the
        // checksum so leaving spaces is fine for our walker).
        header[148..156].copy_from_slice(b"        ");
        // typeflag: '0' = regular file
        header[156] = b'0';
        // ustar magic + version
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        tar.extend_from_slice(&header);
        tar.extend_from_slice(body);
        let pad = (512 - body.len() % 512) % 512;
        tar.extend(std::iter::repeat(b'\0').take(pad));
        // End-of-archive: two zero blocks.
        tar.extend(std::iter::repeat(b'\0').take(1024));
        tar
    }
}
