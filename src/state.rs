use std::sync::Arc;

use sqlx::MySqlPool;

use crate::auth::session::SessionUser;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: MySqlPool,
}

impl AppState {
    /// Server-default timezone (from `APP_TZ_OFFSET_HOURS`).
    pub fn tz_default(&self) -> chrono::FixedOffset {
        self.config.tz()
    }

    /// Resolve the effective timezone for a request.
    ///
    /// Resolution order:
    ///   1. `?tz_offset_hours=N` query parameter — but `N == 0` is treated
    ///      as "no override" (use the env default), mirroring the
    ///      behavior of `POST /tz` which uses 0 as the "reset" sentinel.
    ///   2. The user's session-stored TZ (set via the topbar dropdown)
    ///   3. The server's `APP_TZ_OFFSET_HOURS` env default
    ///
    /// Returns `(FixedOffset, Option<i8>)` — the offset and the active
    /// session-stored hours (if any), used to render the dropdown's
    /// `selected` attribute.
    pub fn resolve_tz(
        &self,
        user: &SessionUser,
        query_override: Option<i8>,
    ) -> (chrono::FixedOffset, Option<i8>) {
        // Treat query_override == 0 as "reset / use default". Otherwise an
        // accidental tz_offset_hours=0 in the URL would shadow the
        // session TZ forever (the hidden form field would keep rendering
        // 0 and clobbering the user's dropdown choice).
        let query_override = query_override.filter(|&h| h != 0);
        let hours = query_override
            .or(user.tz_offset_hours)
            .unwrap_or((self.config.tz_offset_secs / 3600) as i8);
        let secs = (hours as i32).saturating_mul(3600);
        let offset = chrono::FixedOffset::east_opt(secs)
            .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).unwrap());
        (offset, user.tz_offset_hours)
    }
}
