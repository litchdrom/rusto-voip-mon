//! Verify passwords against VoIPmonitor's `users.password` column.
//!
//! VoIPmonitor stores passwords in two formats depending on version / how
//! they were set:
//!
//! - Legacy / default: plain unsalted MD5 (hex, 32 chars). E.g. `md5("admin")`
//!   = `8c6976e5b5410415bde908bd4dee15dfb167a8c`.
//! - Newer: PHP `password_hash()` output, which is bcrypt under the hood and
//!   starts with `$2y$` or `$2a$`.
//!
//! We auto-detect by prefix and verify accordingly. Plain MD5 is insecure,
//! but reusing the existing user table means inheriting whatever scheme was
//! used to create each account — we are not making it worse, and operators
//! can rotate to a stronger hash by resetting passwords through the upstream
//! VoIPmonitor GUI.

use md5::{Digest, Md5};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFormat {
    Md5,
    Bcrypt,
}

pub fn detect(hash: &str) -> Option<HashFormat> {
    let h = hash.trim();
    if h.starts_with("$2y$") || h.starts_with("$2a$") || h.starts_with("$2b$") {
        Some(HashFormat::Bcrypt)
    } else if h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(HashFormat::Md5)
    } else {
        None
    }
}

pub fn verify(hash: &str, password: &str) -> bool {
    match detect(hash) {
        Some(HashFormat::Md5) => {
            let mut hasher = Md5::new();
            hasher.update(password.as_bytes());
            let computed = hex_lowercase(&hasher.finalize());
            constant_time_eq(computed.as_bytes(), hash.trim().as_bytes())
        }
        Some(HashFormat::Bcrypt) => bcrypt::verify(password, hash.trim()).unwrap_or(false),
        None => false,
    }
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

fn hex_lowercase(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_admin_matches() {
        // md5("admin") = 21232f297a57a5a743894a0e4a801fc3
        let hash = "21232f297a57a5a743894a0e4a801fc3";
        assert_eq!(detect(hash), Some(HashFormat::Md5));
        assert!(verify(hash, "admin"));
        assert!(!verify(hash, "wrong"));
    }

    #[test]
    fn bcrypt_detect() {
        let hash = "$2y$10$abcdefghijklmnopqrstuuOYZxRXxV5Z0nQpJqA7nJYZxk8k4HUe";
        assert_eq!(detect(hash), Some(HashFormat::Bcrypt));
    }

    #[test]
    fn unknown_format_rejects() {
        assert!(!verify("not-a-hash", "x"));
        assert!(!verify("", "x"));
    }
}
