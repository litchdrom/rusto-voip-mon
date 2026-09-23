use std::sync::Arc;

use sqlx::MySqlPool;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: MySqlPool,
}

impl AppState {
    /// Convenience: tz offset helper kept here so handlers don't need to
    /// import `Config`.
    pub fn tz(&self) -> chrono::FixedOffset {
        self.config.tz()
    }
}
