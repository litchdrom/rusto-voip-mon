//! Session cookie handling.
//!
//! We sign cookies manually with HMAC-SHA256 because axum-extra 0.9's
//! SignedCookieJar API requires pulling in the `cookie` feature (which
//! re-exports `cookie::Key`) and a state type, and we'd rather keep the
//! surface small. The format is:
//!
//!     <base64url(JSON session)>.<hex(hmac_sha256(secret, payload))>
//!
//! Tampering invalidates the HMAC, so the cookie can be trusted as long as
//! the secret is.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use axum_extra::{headers::Cookie, TypedHeader};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const COOKIE_NAME: &str = "rusto_session";
pub const TTL_SECS: i64 = 24 * 60 * 60;

/// Cap on CDR IDs persisted in the session cookie. Cookies are typically
/// bounded at ~4 KB by browsers; 100 IDs at ~7 bytes each (decimal u64)
/// stays well under that while still being a useful batch size. Mirrors
/// the server-side `BATCH_MAX` cap on `/pcap/batch`.
pub const SESSION_SELECTION_CAP: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub user_id: u32,
    pub username: String,
    pub is_admin: bool,
    pub can_cdr: bool,
    pub can_pcap: bool,
    pub expires_at: i64,
    /// Per-user timezone offset from UTC in hours. `None` means "use the
    /// server's `APP_TZ_OFFSET_HOURS` default". Stored in the session so
    /// the operator's choice survives navigation and page reloads.
    /// Defaulted on deserialize so cookies minted before this field
    /// existed keep working.
    #[serde(default)]
    pub tz_offset_hours: Option<i8>,
    /// CDR IDs the operator has ticked for the upcoming batch download.
    /// Cross-page selection state — toggling a checkbox on page 2 still
    /// sees the ones you ticked on page 1. Always deduplicated + capped
    /// at `SESSION_SELECTION_CAP`; older IDs are dropped when the cap is
    /// reached. Old cookies default to an empty list.
    #[serde(default)]
    pub selected_cdr_ids: Vec<u64>,
}

impl SessionUser {
    pub fn new(user_id: u32, username: String, is_admin: bool, can_cdr: bool, can_pcap: bool) -> Self {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 + TTL_SECS)
            .unwrap_or(0);
        Self {
            user_id,
            username,
            is_admin,
            can_cdr,
            can_pcap,
            expires_at,
            tz_offset_hours: None,
            selected_cdr_ids: Vec::new(),
        }
    }

    /// Return a copy of this session with the timezone override updated.
    /// The encoded cookie's HMAC changes too, so the browser must be
    /// re-issued the cookie.
    pub fn with_tz(mut self, tz_offset_hours: Option<i8>) -> Self {
        self.tz_offset_hours = tz_offset_hours;
        // Re-stamp the TTL so a TZ change bumps the session lifetime.
        self.expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 + TTL_SECS)
            .unwrap_or(self.expires_at);
        self
    }

    /// Replace the operator's batch-download selection with `ids`. Dedupe
    /// + cap at `SESSION_SELECTION_CAP`; the most recent N are kept if
    /// the caller sends more than the cap. Re-stamps the session TTL so
    /// an active selection list doesn't quietly expire.
    pub fn with_selection(mut self, ids: Vec<u64>) -> Self {
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        let mut deduped: Vec<u64> = Vec::with_capacity(ids.len().min(SESSION_SELECTION_CAP));
        // Preserve caller order so freshly-ticked IDs (which arrive last)
        // win when the cap kicks in — that's the principle of least
        // surprise: don't silently drop the rows the user just clicked.
        for id in ids {
            if seen.insert(id) {
                if deduped.len() >= SESSION_SELECTION_CAP {
                    deduped.remove(0);
                }
                deduped.push(id);
            }
        }
        self.selected_cdr_ids = deduped;
        self.expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64 + TTL_SECS)
            .unwrap_or(self.expires_at);
        self
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        now >= self.expires_at
    }
}

/// Encode a session as `base64url(json).hex(hmac_sha256(secret, payload))`.
pub fn encode_cookie(user: &SessionUser, secret: &[u8]) -> String {
    let json = serde_json::to_vec(user).expect("session serializes");
    let payload = base64_url_encode(&json);
    let sig = hmac_hex(secret, payload.as_bytes());
    format!("{payload}.{sig}")
}

/// Decode and verify a session cookie value. Returns None if missing,
/// malformed, tampered, or expired.
pub fn decode_cookie(value: &str, secret: &[u8]) -> Option<SessionUser> {
    let (payload, sig) = value.split_once('.')?;
    let expected = hmac_hex(secret, payload.as_bytes());
    if !constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let json = base64_url_decode(payload).ok()?;
    let user: SessionUser = serde_json::from_slice(&json).ok()?;
    if user.is_expired() {
        return None;
    }
    Some(user)
}

fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    hex::encode(bytes)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base64_url_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHA[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        let v = val(b).ok_or(())?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Extractor that pulls the session out of a `Cookie:` header.
#[axum::async_trait]
impl<S> FromRequestParts<S> for SessionUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Snapshot the secret up-front so the immutable borrow on
        // `parts.extensions` ends before we touch TypedHeader.
        let secret_bytes: Vec<u8> = {
            let secret = parts
                .extensions
                .get::<crate::auth::session::CookieSecret>()
                .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "cookie secret missing"))?;
            secret.0.as_bytes().to_vec()
        };

        let TypedHeader(cookies) = TypedHeader::<Cookie>::from_request_parts(parts, state)
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "no cookies"))?;

        let raw = cookies
            .get(COOKIE_NAME)
            .ok_or((StatusCode::UNAUTHORIZED, "no session"))?;

        decode_cookie(raw, &secret_bytes).ok_or((StatusCode::UNAUTHORIZED, "bad session"))
    }
}

/// Wrapper so we can stuff the secret into request extensions from main().
#[derive(Clone)]
pub struct CookieSecret(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let u = SessionUser::new(7, "admin".into(), true, true, true);
        let secret = b"some-secret-key";
        let encoded = encode_cookie(&u, secret);
        let decoded = decode_cookie(&encoded, secret).unwrap();
        assert_eq!(decoded.user_id, 7);
        assert_eq!(decoded.username, "admin");
    }

    #[test]
    fn tampered_rejected() {
        let u = SessionUser::new(7, "admin".into(), true, true, true);
        let encoded = encode_cookie(&u, b"secret-a");
        assert!(decode_cookie(&encoded, b"secret-b").is_none());
        // Mutate payload: change user_id 7 -> 8
        let mut bad = encoded.clone();
        let dot = bad.find('.').unwrap();
        // Replace first base64url char with something different.
        let first = bad.chars().next().unwrap();
        let replaced = if first == 'B' { 'C' } else { 'B' };
        bad.replace_range(0..1, &replaced.to_string());
        let _ = dot;
        assert!(decode_cookie(&bad, b"secret-a").is_none());
    }

    #[test]
    fn expired_rejected() {
        let mut u = SessionUser::new(7, "admin".into(), true, true, true);
        u.expires_at = 0; // epoch
        let encoded = encode_cookie(&u, b"secret");
        assert!(decode_cookie(&encoded, b"secret").is_none());
    }

    #[test]
    fn base64_url_roundtrip() {
        let original: Vec<u8> = (0..200).map(|i| (i % 251) as u8).collect();
        let enc = base64_url_encode(&original);
        let dec = base64_url_decode(&enc).unwrap();
        assert_eq!(dec, original);
    }

    #[test]
    fn selection_dedupes_and_caps() {
        let mut u = SessionUser::new(1, "u".into(), false, true, true);
        // 5 duplicates of the same ID — should collapse to one.
        u = u.with_selection(vec![10, 10, 10, 10, 10]);
        assert_eq!(u.selected_cdr_ids, vec![10]);
        // Cap: SESSION_SELECTION_CAP is 100. Send 105 unique IDs (0..105)
        // — the first 5 (0..5) are dropped from the front because the
        // cap is reached at ID 99 and pushes the oldest off. Replacement
        // semantics: the new list is exactly what we sent, capped.
        u = u.with_selection((0..105u64).collect());
        assert_eq!(u.selected_cdr_ids.len(), SESSION_SELECTION_CAP);
        assert_eq!(u.selected_cdr_ids.first(), Some(&5));
        assert_eq!(u.selected_cdr_ids.last(), Some(&104));
        // A smaller replacement just stores the new list verbatim.
        u = u.with_selection(vec![0, 1, 2, 3, 4]);
        assert_eq!(u.selected_cdr_ids, vec![0, 1, 2, 3, 4]);
    }
}
