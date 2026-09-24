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

    let parts = crate::error::with_query_timeout(
        state.config.query_timeout_secs,
        fetch_parts(&state.pool, cdr_id),
    )
    .await?;
    if parts.is_empty() {
        return Err(AppError::NotFound);
    }

    // Group parts by file path so each tar.zst is opened and decompressed
    // only once even if the same archive holds multiple slices. Move the
    // rows (not references) so the closure below can be `'static`.
    let mut by_file: HashMap<PathBuf, Vec<TarPartRow>> = HashMap::new();
    for p in parts {
        let path = match resolve_archive_path(&state.config.pcap_dir, p.calldate, p.type_) {
            Some(p) => p,
            None => {
                tracing::error!(
                    calldate = %p.calldate,
                    type_ = p.type_,
                    "no tar.zst archive found for this part"
                );
                continue;
            }
        };
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
        // Found the type dir (case-corrected). Pick any .tar.zst inside.
        let inner = std::fs::read_dir(&path).ok()?;
        for inner_entry in inner.flatten() {
            let inner_path = inner_entry.path();
            if inner_path.is_file()
                && inner_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.to_ascii_lowercase().ends_with(".tar.zst"))
                    .unwrap_or(false)
            {
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

/// Read + zstd-decompress an entire tar.zst archive into memory. Tar.zst
/// archives are minute-bucketed (one type, one minute) so they stay
/// small; if that ever changes we can switch to seekable-zstd.
///
/// Tolerates a trailing `UnexpectedEof`: VoIPmonitor appends to the
/// `.tar.zst` continuously throughout the minute, so a download
/// triggered while capture is still active will hit an incomplete
/// trailing frame. We swallow that error and return whatever frames
/// decoded cleanly — usually enough to get the call's pcap out.
fn read_archive(path: &Path) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut dec = zstd::Decoder::new(f)?;
    let mut out = Vec::new();
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
}

/// Walk the (decompressed) tar and return a slice that points at the
/// start of the `.pcap` entry's body. Each VoIPmonitor minute-bucket
/// tar.zst wraps a single inner pcap file that contains all the calls
/// captured during that minute.
///
/// `cdr_tar_part.pos` is the byte offset **within that inner pcap**, not
/// within the tar itself — so we ignore tar offsets and slice from `pos`
/// into the pcap body.
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
