use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};

pub async fn create_pool(database_url: &str) -> Result<MySqlPool> {
    MySqlPoolOptions::new()
        .max_connections(16)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(600)))
        .connect(database_url)
        .await
        .context("failed to connect to MySQL")
}
