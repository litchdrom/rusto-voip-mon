//! Long-lived API bearer tokens.
//!
//! Browser flows use the signed session cookie ([`super::session`]). For
//! scripts / CI / `curl` / machine-to-machine integrations the cookie is
//! awkward: you have to log in once, scrape `Set-Cookie`, and resend it on
//! every request. Bearer tokens avoid all of that — a single
//! `Authorization: Bearer …` header on every call.
//!
//! ## Design
//!
//! - **Token format**: `<id>.<hmac_sha256(id, secret)>`. The `id` is 32
//!   random bytes hex-encoded (so 64 hex chars); the HMAC binds the id
//!   to the server's cookie secret so an attacker can't forge tokens.
//!   We never put any user data in the token payload — everything lives
//!   server-side in `TokenStore`.
//! - **Storage**: in-memory `Mutex<HashMap<TokenId, TokenEntry>>` for v1.
//!   Tokens are lost on restart, which is fine for short-lived CI tokens
//!   and matches the rest of the system's "first boot" expectations. A
//!   future migration can swap in a DB table without touching the API.
//! - **Lookup**: the `SessionUser` extractor checks
//!   `Authorization: Bearer <token>` first and resolves the token to a
//!   snapshot of the original user. We snapshot (rather than live-link)
//!   so revoking a token never accidentally affects an in-flight request,
//!   and so a deleted user doesn't break active tokens mid-stream.
//! - **Expiry**: each token has its own `expires_at`. The store lazily
//!   drops expired entries on lookup, so the in-memory footprint stays
//!   bounded without a sweeper.
//!
//! ## Routes
//!
//! - `POST /auth/token`        — exchange username + password for a token
//! - `GET  /auth/tokens`       — list your own active tokens (id + label + expiry)
//! - `DELETE /auth/tokens/:id` — revoke a token you own
//!
//! `POST /auth/token` is intentionally the only endpoint that requires a
//! password. After issuance everything is bearer-only.

use std::collections::HashMap;
use std::sync::Mutex;

use rand::RngCore;

use super::session::SessionUser;

/// Default token lifetime in seconds (90 days). Per-request overrides
/// via `ttl_seconds` in the JSON body.
pub const DEFAULT_TTL_SECS: i64 = 90 * 24 * 60 * 60;

/// Maximum token lifetime — caps operator-set `ttl_seconds` so a typo
/// can't mint a 1000-year token.
pub const MAX_TTL_SECS: i64 = 5 * 365 * 24 * 60 * 60;

/// In-memory map of active API tokens. Wrap in `Arc` and put it in
/// `AppState` so handlers can share it.
#[derive(Default)]
pub struct TokenStore {
    inner: Mutex<HashMap<String, TokenEntry>>,
}

/// One issued token's metadata. The `user` field is a snapshot at
/// issuance time — see the module docs for why.
#[derive(Clone, Debug)]
pub struct TokenEntry {
    pub id: String,
    /// Optional human-readable label (e.g. "CI for repo X").
    pub label: Option<String>,
    /// Snapshot of the user at issuance time.
    pub user: SessionUserSnapshot,
    /// Unix seconds when this token stops being accepted.
    pub expires_at: i64,
    /// Unix seconds at issuance. Useful for the listing endpoint.
    pub created_at: i64,
}

/// Minimal subset of `SessionUser` we need to materialise a `SessionUser`
/// on the fly when a token is presented. Keeps the store free of any
/// heavy fields (e.g. `selected_cdr_ids` — that's per-tab, not per-token).
#[derive(Clone, Debug)]
pub struct SessionUserSnapshot {
    pub user_id: u32,
    pub username: String,
    pub is_admin: bool,
    pub can_cdr: bool,
    pub can_pcap: bool,
}

impl From<&SessionUser> for SessionUserSnapshot {
    fn from(u: &SessionUser) -> Self {
        Self {
            user_id: u.user_id,
            username: u.username.clone(),
            is_admin: u.is_admin,
            can_cdr: u.can_cdr,
            can_pcap: u.can_pcap,
        }
    }
}

impl From<SessionUserSnapshot> for SessionUser {
    fn from(s: SessionUserSnapshot) -> Self {
        // Materialise a fresh SessionUser as if the user had just logged
        // in. `expires_at` is set so `is_expired()` returns false; the
        // *real* expiry is enforced by the TokenStore at lookup time.
        SessionUser::new(s.user_id, s.username, s.is_admin, s.can_cdr, s.can_pcap)
    }
}

impl SessionUserSnapshot {
    /// Convenience: convert a snapshot into a fresh `SessionUser`. Same
    /// as `SessionUserSnapshot::from(s).into()` but reads better at the
    /// bearer-token lookup site.
    pub fn into_session_user(self) -> SessionUser {
        self.into()
    }
}

/// Public methods of [`TokenStore`].
impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a new token bound to `user`, valid for `ttl_seconds`.
    /// Returns `(token_string, entry)` so the caller can build the
    /// HTTP response. The token string is `<id>.<hmac>`.
    pub fn create(
        &self,
        user: &SessionUser,
        label: Option<String>,
        ttl_seconds: i64,
    ) -> (String, TokenEntry) {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        let id = hex_encode(&buf);

        let now = now_unix();
        let entry = TokenEntry {
            id: id.clone(),
            label,
            user: SessionUserSnapshot::from(user),
            expires_at: now + ttl_seconds,
            created_at: now,
        };

        self.inner
            .lock()
            .expect("token store mutex poisoned")
            .insert(id.clone(), entry.clone());

        // The HMAC binds the id to the server secret so tokens can't be
        // forged even if the in-memory store is somehow read. We sign
        // with the same key as the cookie secret (loaded from
        // APP_COOKIE_SECRET) — keeping a single source of cryptographic
        // truth.
        let hmac = sign_token(&id);
        let token = format!("{id}.{hmac}");
        (token, entry)
    }

    /// Look up + verify a bearer token. Returns the entry on success.
    /// Expired entries are dropped lazily on access.
    pub fn lookup(&self, token: &str) -> Option<TokenEntry> {
        let Some((id, hmac)) = token.split_once('.') else {
            return None;
        };
        if !verify_token(id, hmac) {
            return None;
        }
        let mut guard = self.inner.lock().expect("token store mutex poisoned");
        let entry = guard.get(id)?;
        let now = now_unix();
        if entry.expires_at <= now {
            // Lazy expiry — drop and return None.
            guard.remove(id);
            return None;
        }
        Some(entry.clone())
    }

    /// Revoke a single token. Returns true if it existed.
    pub fn revoke(&self, id: &str) -> bool {
        self.inner
            .lock()
            .expect("token store mutex poisoned")
            .remove(id)
            .is_some()
    }

    /// Revoke every token belonging to `user_id`. Used by logout / user
    /// deletion. Returns the number of tokens removed.
    pub fn revoke_all_for_user(&self, user_id: u32) -> usize {
        let mut guard = self.inner.lock().expect("token store mutex poisoned");
        let before = guard.len();
        guard.retain(|_, e| e.user.user_id != user_id);
        before - guard.len()
    }

    /// All currently-valid tokens belonging to `user_id`. Used by the
    /// `GET /auth/tokens` listing endpoint. Expired entries are pruned
    /// along the way.
    pub fn list_for_user(&self, user_id: u32) -> Vec<TokenEntry> {
        let mut guard = self.inner.lock().expect("token store mutex poisoned");
        let now = now_unix();
        let mut out = Vec::new();
        let stale: Vec<String> = guard
            .iter()
            .filter_map(|(id, e)| {
                if e.expires_at <= now {
                    Some(id.clone())
                } else if e.user.user_id == user_id {
                    out.push(e.clone());
                    None
                } else {
                    None
                }
            })
            .collect();
        for id in stale {
            guard.remove(&id);
        }
        out
    }

    /// Number of currently-valid tokens across all users.
    #[allow(dead_code)] // exposed for future admin endpoints / tests
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("token store mutex poisoned")
            .len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// HMAC-SHA256 over `id`, hex-encoded. The `secret` is the same one we
/// use for the session cookie — passed in by the caller so we don't
/// depend on `AppState` here (the store is just data).
fn sign_token(id: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let secret = std::env::var("APP_COOKIE_SECRET").unwrap_or_default();
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return String::new();
    };
    mac.update(id.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn verify_token(id: &str, hmac_hex: &str) -> bool {
    let expected = sign_token(id);
    if expected.is_empty() || expected.len() != hmac_hex.len() {
        return false;
    }
    // Constant-time compare.
    let mut diff = 0u8;
    for (a, b) in expected.bytes().zip(hmac_hex.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_user() -> SessionUser {
        SessionUser::new(7, "alice".into(), true, true, true)
    }

    /// `create` then `lookup` returns the same entry.
    #[test]
    fn roundtrip() {
        // Sign with a known secret so the test is reproducible.
        std::env::set_var("APP_COOKIE_SECRET", "test-secret-for-token-module");
        let store = TokenStore::new();
        let (token, entry) = store.create(&dummy_user(), Some("ci".into()), 3600);
        let looked = store.lookup(&token).expect("lookup should hit");
        assert_eq!(looked.id, entry.id);
        assert_eq!(looked.user.user_id, 7);
        assert_eq!(looked.label.as_deref(), Some("ci"));
    }

    /// Expired tokens are pruned on access and return None.
    #[test]
    fn expired_evicted() {
        std::env::set_var("APP_COOKIE_SECRET", "test-secret-for-token-module");
        let store = TokenStore::new();
        let (token, _) = store.create(&dummy_user(), None, -1); // already expired
        assert!(store.lookup(&token).is_none());
    }

    /// Forged tokens (wrong HMAC) are rejected.
    #[test]
    fn forged_hmac_rejected() {
        std::env::set_var("APP_COOKIE_SECRET", "test-secret-for-token-module");
        let store = TokenStore::new();
        let (token, _) = store.create(&dummy_user(), None, 3600);
        let (id, _) = token.split_once('.').unwrap();
        let bad = format!("{id}.deadbeef");
        assert!(store.lookup(&bad).is_none());
    }

    /// Revocation works and is idempotent.
    #[test]
    fn revoke_removes_entry() {
        std::env::set_var("APP_COOKIE_SECRET", "test-secret-for-token-module");
        let store = TokenStore::new();
        let (token, entry) = store.create(&dummy_user(), None, 3600);
        assert!(store.revoke(&entry.id));
        assert!(!store.revoke(&entry.id));
        assert!(store.lookup(&token).is_none());
    }

    /// `revoke_all_for_user` only touches the target user.
    #[test]
    fn revoke_all_scoped() {
        std::env::set_var("APP_COOKIE_SECRET", "test-secret-for-token-module");
        let store = TokenStore::new();
        let alice = SessionUser::new(1, "alice".into(), false, true, true);
        let bob = SessionUser::new(2, "bob".into(), false, true, true);
        let (a1, _) = store.create(&alice, None, 3600);
        let (a2, _) = store.create(&alice, Some("ci-2".into()), 3600);
        let (b1, _) = store.create(&bob, None, 3600);
        let removed = store.revoke_all_for_user(1);
        assert_eq!(removed, 2);
        assert!(store.lookup(&a1).is_none());
        assert!(store.lookup(&a2).is_none());
        assert!(store.lookup(&b1).is_some(), "bob's token must survive");
    }
}
