//! User management.
//!
//! CRUD over VoIPmonitor's `users` table — the same one the existing
//! login path reads from via [`crate::auth::password::verify_login`].
//! Schema (from the existing verify_login query):
//!
//! | column             | Rust type | notes                            |
//! |--------------------|-----------|----------------------------------|
//! | id                 | i32       | signed INT AUTO_INCREMENT        |
//! | username           | String    | unique login identifier          |
//! | password           | String    | MD5 hex (legacy) or bcrypt       |
//! | is_admin           | bool      | TINYINT NOT NULL                 |
//! | can_cdr            | bool      | TINYINT NULL — null = 0          |
//! | can_pcap           | bool      | TINYINT NULL — null = 0          |
//! | blocked            | bool      | TINYINT NULL — null = 0          |
//! | password_expired   | bool      | TINYINT NULL — null = 0          |
//!
//! We never read the password hash back out of the DB for display —
//! the `list` and `get_by_id` paths omit it entirely, the `update`
//! path only writes a new hash if the operator supplied a non-empty
//! reset field (so we don't clobber an existing MD5 hash just because
//! the form rendered). Detection of the legacy MD5 format lives in
//! [`crate::auth::password::detect`] — we call that on the edit form
//! to surface a "Legacy MD5 password — rotate to bcrypt" hint.
//!
//! New passwords are always stored as bcrypt (`$2y$…`). The
//! verify_login auto-detector handles either format, so upgrading
//! is automatic on the user's next password change.

use serde::Serialize;
use sqlx::{MySqlPool, Row};

use crate::{
    auth::password::{detect, HashFormat},
    error::{AppError, AppResult},
};

/// One row of the `users` table, projected down to what the
/// operator-facing UI shows. Password hash is deliberately omitted
/// — we never display or re-emit it, and an admin editing a user
/// shouldn't have the old hash in their browser's form state.
#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub is_admin: bool,
    pub can_cdr: bool,
    pub can_pcap: bool,
    pub blocked: bool,
    pub password_expired: bool,
    /// Pre-rendered label for the stored password hash format.
    /// "bcrypt", "md5 (legacy)", or "unknown" — surfaced in the
    /// edit form so the operator knows when a legacy MD5 row is
    /// in play. Stored as `String` (not `HashFormat`) so the
    /// askama template doesn't need a serde derive on the enum.
    pub password_format_label: String,
    /// True if the stored hash starts with `$2y$/$2a$/$2b$` and
    /// isn't legacy MD5. Convenience for templates that want a
    /// "rotate this password" badge on bcrypt rows too — e.g. so
    /// the operator can rotate service passwords on a schedule.
    pub password_is_modern: bool,
}

/// Editable subset of a user. Submitted by the new/edit forms.
/// Numeric/optional fields use plain `bool`s from the form layer;
/// username + (optional) new password are the only strings.
#[derive(Debug, Clone, Default)]
pub struct UserEdit {
    pub username: String,
    pub new_password: Option<String>,
    pub is_admin: bool,
    pub can_cdr: bool,
    pub can_pcap: bool,
    pub blocked: bool,
    pub password_expired: bool,
}

/// What can go wrong when validating the edit form. Flat enum so
/// the template renders each variant with its own message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// `username` failed validation — empty, too long, or contains
    /// characters that would break the URL `/admin/users/:id/edit`.
    BadUsername(String),
    /// `new_password` (when supplied) failed length / complexity
    /// rules. We don't enforce a hard character class — VoIPmonitor
    /// doesn't — but we require 8+ characters to avoid the operator
    /// accidentally typing a one-char password.
    BadPassword(String),
}

impl EditError {
    pub fn message(&self) -> String {
        match self {
            EditError::BadUsername(s) => format!("username: {s}"),
            EditError::BadPassword(s) => format!("password: {s}"),
        }
    }
}

/// Validate + normalise a [`UserEdit`] into the typed values we
/// actually write to MySQL. Pure function — easy to unit-test.
///
/// Validation rules:
///   * `username` — trimmed; must be 1..=64 chars; alphanumeric +
///     dot / underscore / dash / at-sign (covers the typical
///     "first.last" / "service_account" / "ci-deploy" patterns);
///     no leading/trailing whitespace, no control chars.
///   * `new_password` — `None` (or empty after trim) means "don't
///     change the password"; otherwise must be ≥ 8 chars and ≤ 256
///     chars (bcrypt's own ceiling — anything longer gets
///     pre-truncated to 72 bytes by bcrypt and we don't want to
///     hide that from the operator).
pub fn parse_edit_form(form: &UserEdit) -> Result<ParsedUserEdit, EditError> {
    let username = form.username.trim();
    if username.is_empty() {
        return Err(EditError::BadUsername("must not be empty".into()));
    }
    if username.len() > 64 {
        return Err(EditError::BadUsername(
            "must be 64 characters or fewer".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return Err(EditError::BadUsername(
            "may only contain letters, digits, '.', '_', '-', '@'".into(),
        ));
    }

    let new_password: Option<String> = match form.new_password.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(s) => {
            if s.len() < 8 {
                return Err(EditError::BadPassword(
                    "must be at least 8 characters".into(),
                ));
            }
            if s.len() > 256 {
                return Err(EditError::BadPassword(
                    "must be 256 characters or fewer".into(),
                ));
            }
            Some(s.to_string())
        }
    };

    Ok(ParsedUserEdit {
        username: username.to_string(),
        new_password,
        is_admin: form.is_admin,
        can_cdr: form.can_cdr,
        can_pcap: form.can_pcap,
        blocked: form.blocked,
        password_expired: form.password_expired,
    })
}

/// Same as `UserEdit` but with `username` trimmed and `new_password`
/// normalised to a present-or-absent `Option<String>`. This is what
/// hits the DB.
#[derive(Debug, Clone)]
pub struct ParsedUserEdit {
    pub username: String,
    pub new_password: Option<String>,
    pub is_admin: bool,
    pub can_cdr: bool,
    pub can_pcap: bool,
    pub blocked: bool,
    pub password_expired: bool,
}

/// Minimum cost for bcrypt hashing. bcrypt's default is 12; we use 10
/// so a fresh `bcrypt::hash()` call takes ~60 ms on a modern x86,
/// which is acceptable for an admin form submit. Bumping this to 12
/// adds ~250 ms per write — fine for single-user CRUD but it'd be
/// hostile to any future bulk-import flow.
const BCRYPT_COST: u32 = 10;

/// Hash a plain-text password with bcrypt at [`BCRYPT_COST`]. The
/// output is a self-contained `$2y$…` string that the existing
/// [`crate::auth::password::verify_login`] auto-detector recognises.
pub fn hash_password(plain: &str) -> Result<String, String> {
    bcrypt::hash(plain, BCRYPT_COST).map_err(|e| format!("bcrypt hash: {e}"))
}

/// List every user, ordered by username (case-insensitive) so the
/// operator sees a stable alphabetical sequence. Includes blocked /
/// expired-password accounts — they're filtered at display time
/// because the operator may want to un-block them.
pub async fn list_all(pool: &MySqlPool) -> AppResult<Vec<User>> {
    let rows = sqlx::query(
        "SELECT id, username, password, is_admin, can_cdr, can_pcap, \
                blocked, password_expired \
           FROM users ORDER BY LOWER(username) ASC",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(row_to_user(&r)?);
    }
    Ok(out)
}

/// Fetch one user by their primary key. Returns `Ok(None)` if no row
/// matches. Used by the edit form.
pub async fn get_by_id(pool: &MySqlPool, id: i32) -> AppResult<Option<User>> {
    let row = sqlx::query(
        "SELECT id, username, password, is_admin, can_cdr, can_pcap, \
                blocked, password_expired \
           FROM users WHERE id = ? LIMIT 1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(row_to_user(&row)?))
}

/// Look up a user by username. Used by the create flow to reject
/// duplicates before MySQL surfaces a 23000 dup-key error.
pub async fn get_by_username(pool: &MySqlPool, username: &str) -> AppResult<Option<User>> {
    let row = sqlx::query(
        "SELECT id, username, password, is_admin, can_cdr, can_pcap, \
                blocked, password_expired \
           FROM users WHERE username = ? LIMIT 1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(row_to_user(&row)?))
}

/// Insert a new user. `edit.new_password` must be `Some` — the form
/// layer enforces this on the create path; here we panic if it's
/// `None` because that's a programmer error, not a user error.
pub async fn create(pool: &MySqlPool, edit: &ParsedUserEdit) -> AppResult<i32> {
    let new_password = edit
        .new_password
        .as_deref()
        .ok_or_else(|| crate::error::AppError::Internal(
            "users::create called without new_password — form validation bug".into(),
        ))?;
    let hash = hash_password(new_password).map_err(crate::error::AppError::Internal)?;
    let res = sqlx::query(
        "INSERT INTO users \
            (username, password, is_admin, can_cdr, can_pcap, \
             blocked, password_expired) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&edit.username)
    .bind(&hash)
    .bind(if edit.is_admin { 1_i8 } else { 0_i8 })
    .bind(if edit.can_cdr { 1_i8 } else { 0_i8 })
    .bind(if edit.can_pcap { 1_i8 } else { 0_i8 })
    .bind(if edit.blocked { 1_i8 } else { 0_i8 })
    .bind(if edit.password_expired { 1_i8 } else { 0_i8 })
    .execute(pool)
    .await?;
    Ok(res.last_insert_id() as i32)
}

/// Apply permission + username changes to an existing user. Password
/// is only updated when `edit.new_password.is_some()` — the form
/// layer uses empty-string-as-absent so the operator can leave the
/// password alone on a non-password-focused edit.
///
/// Returns the number of affected rows — caller treats 0 as 404.
pub async fn update(pool: &MySqlPool, id: i32, edit: &ParsedUserEdit) -> AppResult<u64> {
    // We build the SQL dynamically based on whether a password reset
    // is included. Two reasons:
    //   1. Don't accidentally clobber the existing hash with NULL
    //      when the form omitted the field.
    //   2. Avoid paying the bcrypt cost (~60 ms) when no reset was
    //      requested — flipping the `blocked` checkbox shouldn't
    //      require re-hashing anything.
    let affected = if let Some(new_password) = edit.new_password.as_deref() {
        let hash = hash_password(new_password).map_err(crate::error::AppError::Internal)?;
        sqlx::query(
            "UPDATE users SET \
                username = ?, password = ?, is_admin = ?, \
                can_cdr = ?, can_pcap = ?, blocked = ?, \
                password_expired = ? \
             WHERE id = ?",
        )
        .bind(&edit.username)
        .bind(&hash)
        .bind(if edit.is_admin { 1_i8 } else { 0_i8 })
        .bind(if edit.can_cdr { 1_i8 } else { 0_i8 })
        .bind(if edit.can_pcap { 1_i8 } else { 0_i8 })
        .bind(if edit.blocked { 1_i8 } else { 0_i8 })
        .bind(if edit.password_expired { 1_i8 } else { 0_i8 })
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
    } else {
        sqlx::query(
            "UPDATE users SET \
                username = ?, is_admin = ?, \
                can_cdr = ?, can_pcap = ?, blocked = ?, \
                password_expired = ? \
             WHERE id = ?",
        )
        .bind(&edit.username)
        .bind(if edit.is_admin { 1_i8 } else { 0_i8 })
        .bind(if edit.can_cdr { 1_i8 } else { 0_i8 })
        .bind(if edit.can_pcap { 1_i8 } else { 0_i8 })
        .bind(if edit.blocked { 1_i8 } else { 0_i8 })
        .bind(if edit.password_expired { 1_i8 } else { 0_i8 })
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected()
    };
    Ok(affected)
}

/// Reset just the password. Used by the per-row "Reset password"
/// button on the list view, which doesn't pull up the full edit
/// form. Caller must already have validated the new password via
/// [`parse_edit_form`].
pub async fn reset_password(pool: &MySqlPool, id: i32, new_password: &str) -> AppResult<u64> {
    let hash = hash_password(new_password).map_err(crate::error::AppError::Internal)?;
    let res = sqlx::query(
        "UPDATE users SET password = ?, password_expired = 0 \
         WHERE id = ?",
    )
    .bind(&hash)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Hard-delete a user row. The caller is responsible for any
/// "don't delete yourself" / "don't delete the last admin" checks —
/// this function just runs the DELETE.
pub async fn delete(pool: &MySqlPool, id: i32) -> AppResult<u64> {
    let res = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Count users with `is_admin = 1`. Used by the route layer to
/// refuse an attempted delete / demote that would leave the system
/// with zero admins (a soft lock-out scenario).
pub async fn count_admins(pool: &MySqlPool) -> AppResult<i64> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// Internal: turn a raw `MySqlRow` into the focused [`User`] struct.
/// Password hash is read once for format detection, then dropped —
/// we never keep it in memory past the call site.
fn row_to_user(row: &sqlx::mysql::MySqlRow) -> AppResult<User> {
    let password_hash: String = row.try_get("password").unwrap_or_default();
    let password_format = detect(&password_hash);
    let password_is_modern = matches!(password_format, Some(HashFormat::Bcrypt));
    let password_format_label = match password_format {
        Some(HashFormat::Bcrypt) => "bcrypt".into(),
        Some(HashFormat::Md5) => "md5 (legacy)".into(),
        None => "unknown".into(),
    };
    Ok(User {
        id: row.try_get("id")?,
        username: row.try_get("username")?,
        is_admin: row.try_get::<i8, _>("is_admin").map(|v| v != 0)?,
        can_cdr: row
            .try_get::<Option<i8>, _>("can_cdr")
            .map(|v| v.unwrap_or(0) != 0)
            .unwrap_or(false),
        can_pcap: row
            .try_get::<Option<i8>, _>("can_pcap")
            .map(|v| v.unwrap_or(0) != 0)
            .unwrap_or(false),
        blocked: row
            .try_get::<Option<i8>, _>("blocked")
            .map(|v| v.unwrap_or(0) != 0)
            .unwrap_or(false),
        password_expired: row
            .try_get::<Option<i8>, _>("password_expired")
            .map(|v| v.unwrap_or(0) != 0)
            .unwrap_or(false),
        password_format_label,
        password_is_modern,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(username: &str, password: Option<&str>, is_admin: bool) -> UserEdit {
        UserEdit {
            username: username.into(),
            new_password: password.map(String::from),
            is_admin,
            can_cdr: false,
            can_pcap: false,
            blocked: false,
            password_expired: false,
        }
    }

    #[test]
    fn parse_edit_form_accepts_clean_username() {
        let parsed = parse_edit_form(&edit("alice", Some("hunter2hunter"), false))
            .expect("valid");
        assert_eq!(parsed.username, "alice");
        assert_eq!(parsed.new_password.as_deref(), Some("hunter2hunter"));
        assert!(!parsed.is_admin);
    }

    #[test]
    fn parse_edit_form_trims_username_whitespace() {
        let parsed = parse_edit_form(&edit("  bob  ", Some("longenoughpw"), false))
            .expect("valid");
        assert_eq!(parsed.username, "bob");
    }

    #[test]
    fn parse_edit_form_rejects_empty_username() {
        assert!(matches!(
            parse_edit_form(&edit("", Some("longenoughpw"), false)),
            Err(EditError::BadUsername(_))
        ));
        assert!(matches!(
            parse_edit_form(&edit("   ", Some("longenoughpw"), false)),
            Err(EditError::BadUsername(_))
        ));
    }

    #[test]
    fn parse_edit_form_rejects_long_username() {
        let long = "a".repeat(65);
        assert!(matches!(
            parse_edit_form(&edit(&long, Some("longenoughpw"), false)),
            Err(EditError::BadUsername(_))
        ));
    }

    #[test]
    fn parse_edit_form_rejects_usernames_with_invalid_chars() {
        // Spaces, slashes, and quotes are not allowed.
        assert!(parse_edit_form(&edit("has space", Some("longenoughpw"), false)).is_err());
        assert!(parse_edit_form(&edit("has/slash", Some("longenoughpw"), false)).is_err());
        assert!(parse_edit_form(&edit("has\"quote", Some("longenoughpw"), false)).is_err());
        assert!(parse_edit_form(&edit("has;semicol", Some("longenoughpw"), false)).is_err());
    }

    #[test]
    fn parse_edit_form_accepts_username_with_dot_dash_at_underscore() {
        for u in ["first.last", "service-account", "ci@bot", "deploy_v2"] {
            let parsed = parse_edit_form(&edit(u, Some("longenoughpw"), false))
                .unwrap_or_else(|e| panic!("{u} should be valid: {e:?}"));
            assert_eq!(parsed.username, u);
        }
    }

    #[test]
    fn parse_edit_form_treats_empty_password_as_no_reset() {
        let parsed = parse_edit_form(&edit("alice", Some(""), false)).expect("valid");
        assert!(parsed.new_password.is_none());
        let parsed = parse_edit_form(&edit("alice", None, false)).expect("valid");
        assert!(parsed.new_password.is_none());
        // Whitespace-only is also "no reset" — operator typed and
        // then deleted the password without un-checking the field.
        let parsed = parse_edit_form(&edit("alice", Some("   "), false)).expect("valid");
        assert!(parsed.new_password.is_none());
    }

    #[test]
    fn parse_edit_form_rejects_short_passwords() {
        // 7 chars is one short of the 8-char minimum.
        assert!(matches!(
            parse_edit_form(&edit("alice", Some("1234567"), false)),
            Err(EditError::BadPassword(_))
        ));
    }

    #[test]
    fn parse_edit_form_rejects_overly_long_passwords() {
        let huge = "a".repeat(257);
        assert!(matches!(
            parse_edit_form(&edit("alice", Some(&huge), false)),
            Err(EditError::BadPassword(_))
        ));
    }

    #[test]
    fn parse_edit_form_accepts_min_and_max_length_passwords() {
        // 8 chars exactly — minimum.
        assert!(parse_edit_form(&edit("alice", Some("12345678"), false)).is_ok());
        // 256 chars exactly — bcrypt ceiling.
        let big = "a".repeat(256);
        assert!(parse_edit_form(&edit("alice", Some(&big), false)).is_ok());
    }

    #[test]
    fn parse_edit_form_round_trips_admin_flag() {
        let parsed = parse_edit_form(&edit("root", Some("longenoughpw"), true))
            .expect("valid");
        assert!(parsed.is_admin);
        let parsed = parse_edit_form(&edit("alice", Some("longenoughpw"), false))
            .expect("valid");
        assert!(!parsed.is_admin);
    }

    #[test]
    fn hash_password_produces_a_verifiable_bcrypt_string() {
        // Round-trip through bcrypt::verify so we know the produced
        // hash matches the format the existing verify_login path
        // expects. `bcrypt::verify` returns Result (it can fail on
        // hash format errors); we unwrap with a clear message —
        // an Err here would indicate our hash_password() output is
        // malformed, not that the password was wrong.
        let hash = hash_password("hunter2hunter").expect("hash should succeed");
        assert!(
            hash.starts_with("$2y$") || hash.starts_with("$2a$") || hash.starts_with("$2b$"),
            "bcrypt hash should start with $2y/$2a/$2b$, got {hash:?}"
        );
        assert!(
            bcrypt::verify("hunter2hunter", &hash).unwrap_or(false),
            "freshly-hashed password should verify"
        );
        assert!(
            !bcrypt::verify("wrong-password", &hash).unwrap_or(true),
            "wrong password should not verify"
        );
    }

    #[test]
    fn edit_error_message_names_the_offending_field() {
        // The form template renders these as inline error text —
        // the message must mention which field failed.
        assert!(EditError::BadUsername("foo".into()).message().contains("username"));
        assert!(EditError::BadPassword("bar".into()).message().contains("password"));
    }
}
