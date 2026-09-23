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
use chrono::NaiveDateTime;
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
            type_: r.try_get::<i8, _>("type")? as u8,
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

    let parts = fetch_parts(&state.pool, cdr_id).await?;
    if parts.is_empty() {
        return Err(AppError::NotFound);
    }

    // Group parts by file path so each tar.zst is opened and decompressed
    // only once even if the same archive holds multiple slices. Move the
    // rows (not references) so the closure below can be `'static`.
    let mut by_file: HashMap<PathBuf, Vec<TarPartRow>> = HashMap::new();
    for p in parts {
        let path = compute_path(&state.config.pcap_dir, p.calldate, p.type_);
        by_file.entry(path).or_default().push(p);
    }

    // Sort files deterministically: SIP → RTP → GRAPH → OTHER, then by
    // path so tarballs from different minutes stay ordered within a type.
    let mut file_order: Vec<(PathBuf, Vec<TarPartRow>)> = by_file.into_iter().collect();
    file_order.sort_by_key(|(path, parts)| {
        (
            parts.first().map(|p| p.type_).unwrap_or(255),
            path.clone(),
        )
    });

    let total_parts: usize = file_order.iter().map(|(_, v)| v.len()).sum();
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(8);

    tokio::task::spawn_blocking(move || {
        let mut sent_header = false;
        for (path, parts) in file_order {
            let archive = match read_archive(&path) {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(error = ?e, path = %path.display(),
                        "failed to read pcap archive");
                    let _ = tx.blocking_send(Err(e));
                    return;
                }
            };

            for part in parts {
                let pos = part.pos;
                let bytes = match extract_at_pos(&archive, pos) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(error = ?e, cdr_id, pos,
                            "failed to extract pcap slice");
                        let err = std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("pos {}: {}", pos, e),
                        );
                        let _ = tx.blocking_send(Err(err));
                        return;
                    }
                };

                if sent_header {
                    if bytes.len() <= PCAP_GLOBAL_HEADER_LEN {
                        continue; // empty pcap, skip
                    }
                    let payload = Bytes::copy_from_slice(&bytes[PCAP_GLOBAL_HEADER_LEN..]);
                    if tx.blocking_send(Ok(payload)).is_err() {
                        return; // client disconnected
                    }
                } else {
                    if tx.blocking_send(Ok(Bytes::copy_from_slice(bytes))).is_err() {
                        return;
                    }
                    sent_header = true;
                }
            }
        }
        tracing::info!(cdr_id, parts = total_parts, "pcap stream complete");
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

/// Batch download — left as a 501 for v0.2.1 (requires async-zip +
/// streamed-zip-from-mpsc glue, which is fiddly in axum 0.7). The
/// single-CDR download covers the 99% case.
pub async fn download_batch(
    State(_state): State<AppState>,
    _user: SessionUser,
) -> AppResult<Response> {
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        "batch PCAP download not yet implemented (v0.2.1); use /pcap/:id per CDR",
    )
        .into_response())
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

/// Compute `{PCAP_DIR}/YYYY-MM-DD/HH/MM/{TYPE}/{TYPE}_YYYY-MM-DD-HH-MM.tar.zst`.
fn compute_path(pcap_dir: &Path, calldate: NaiveDateTime, type_: u8) -> PathBuf {
    let type_name = match type_ {
        0 => "SIP",
        1 => "RTP",
        2 => "GRAPH",
        _ => "OTHER",
    };
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

/// Read + zstd-decompress an entire tar.zst archive into memory. Tar.zst
/// archives are minute-bucketed (one type, one minute) so they stay
/// small; if that ever changes we can switch to seekable-zstd.
fn read_archive(path: &Path) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut dec = zstd::Decoder::new(f)?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

/// Find the file at the given byte offset inside a (decompressed) tar
/// archive and return its raw body bytes (header + contents excluded).
fn extract_at_pos(archive: &[u8], pos: u64) -> std::io::Result<&[u8]> {
    let pos = pos as usize;
    if pos + 512 > archive.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("pos {pos} past end of archive ({} bytes)", archive.len()),
        ));
    }

    let header = &archive[pos..pos + 512];
    let size = parse_tar_size(&header[124..136])?;

    let data_start = pos + 512;
    let data_end = data_start
        .checked_add(size as usize)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "size overflow"))?;
    if data_end > archive.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "file body ({} bytes at {}) past end of archive ({} bytes)",
                size,
                data_start,
                archive.len()
            ),
        ));
    }
    Ok(&archive[data_start..data_end])
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
        let p = compute_path(&dir, ts, 0);
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(s.ends_with("SIP/SIP_2026-09-21-14-35.tar.zst"), "got {s}");
        assert!(s.contains("2026-09-21/14/35/"), "got {s}");
        let p = compute_path(&dir, ts, 1);
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(s.ends_with("RTP/RTP_2026-09-21-14-35.tar.zst"), "got {s}");
        let p = compute_path(&dir, ts, 9);
        let s = p.to_string_lossy().replace('\\', "/");
        assert!(s.ends_with("OTHER/OTHER_2026-09-21-14-35.tar.zst"), "got {s}");
    }
}
