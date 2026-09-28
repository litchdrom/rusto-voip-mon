//! Build script — captures the git SHA + commit timestamp at
//! compile time and writes them as `cargo:rustc-env` values so the
//! binary knows its own build identity.
//!
//! Why this matters: deployments that pull a new commit but serve a
//! stale binary (cargo cache, partial rebuild, missed restart) are
//! the worst kind of bug — silent. With build identity baked in,
//! `rusto-voip-mon --version` and the startup banner can answer
//! "what's actually running?" without anyone having to ssh in and
//! compare build hosts. `cargo:rerun-if-changed=.git/HEAD` ensures
//! the build re-runs when HEAD moves so the SHA reflects what's
//! actually checked out.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Re-run the build script on git state changes. Pointing at
    // `.git/HEAD` (and refs/heads/) is the cargo-recommended pattern
    // — avoids cache invalidation on every git command, while still
    // picking up branch switches and commit updates.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");

    let (sha, ts) = git_metadata();
    println!("cargo:rustc-env=VERGEN_GIT_SHA={}", sha);
    println!("cargo:rustc-env=VERGEN_BUILD_TIMESTAMP={}", ts);
}

/// Run `git` to read the current HEAD's SHA + committer timestamp.
/// Falls back to "unknown" / the wall-clock time on any error — a
/// build must never fail because git wasn't reachable.
fn git_metadata() -> (String, String) {
    let sha = run("git", &["rev-parse", "--short", "HEAD"])
        .unwrap_or_else(|| "unknown".to_string());
    // ISO-8601 in UTC so the same binary gives the same string on
    // every machine regardless of timezone.
    let ts = run(
        "git",
        &[
            "log",
            "-1",
            "--format=%cd",
            "--date=format:%Y-%m-%dT%H:%M:%SZ",
        ],
    )
    .unwrap_or_else(format_now_utc);
    (sha, ts)
}

/// `2026-09-28T12:34:56Z`-style UTC timestamp built without pulling
/// in a date-time crate just for build-time formatting. We could
/// shell out to `date -u` but std + a 30-line format routine is
/// faster and avoids one more spawn.
fn format_now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d, h, mi, s) = epoch_to_utc(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, h, mi, s
    )
}

/// Civil-from-days (Howard Hinnant's `days_from_civil`) — converts
/// a Unix-epoch second count to (year, month, day, h, m, s) in UTC.
/// Equivalent to libc `gmtime_r` but doesn't need a `ctime`-linked
/// crate; ~30 lines of pure Rust.
fn epoch_to_utc(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400) as u32;
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    // Howard Hinnant's algorithm: shift epoch from 1970-01-01 to
    // 0000-03-01 so leap days fall at the end of the year.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d, h, mi, s)
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
