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
    ///   1. `?tz_offset_hours=N` query parameter (per-request override)
    ///   2. The user's session-stored TZ (set via the topbar dropdown)
    ///   3. The server's `APP_TZ_OFFSET_HOURS` env default
    ///
    /// Returns `(FixedOffset, Option<i8>)` — the offset and the value that
    /// ended up driving it (the session-stored hours, if any). Handlers
    /// use the value to render the TZ selector with the active choice.
    pub fn resolve_tz(
        &self,
        user: &SessionUser,
        query_override: Option<i8>,
    ) -> (chrono::FixedOffset, Option<i8>) {
        let hours = query_override
            .or(user.tz_offset_hours)
            .unwrap_or((self.config.tz_offset_secs / 3600) as i8);
        let secs = (hours as i32).saturating_mul(3600);
        let offset = chrono::FixedOffset::east_opt(secs)
            .unwrap_or_else(|| chrono::FixedOffset::east_opt(0).unwrap());
        (offset, user.tz_offset_hours)
    }
}
