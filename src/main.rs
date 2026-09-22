use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::{routing::get, routing::post, Extension, Router};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod auth;
mod cdr;
mod config;
mod db;
mod error;
mod routes;
mod state;

use crate::auth::session::CookieSecret;
use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // .env is optional; ignore if missing
    let _ = dotenvy::dotenv();

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Arc::new(Config::from_env()?);
    tracing::info!(listen = %config.listen, "rusto-voip-mon starting");

    let pool = db::create_pool(&config.database_url).await?;
    tracing::info!("connected to MySQL");

    let state = AppState {
        config: config.clone(),
        pool,
    };

    let app = Router::new()
        .route("/login", get(routes::login::login_form).post(routes::login::login_submit))
        .route("/logout", post(routes::login::logout))
        .route("/", get(routes::cdr::cdr_list))
        .route("/cdr/:id", get(routes::cdr::cdr_detail))
        .route("/cdr/export.csv", get(routes::cdr::cdr_export_csv))
        .route("/pcap/:cdr_id", get(routes::pcap::download_single))
        .route("/pcap/batch", post(routes::pcap::download_batch))
        .route("/healthz", get(healthz))
        .nest_service("/static", ServeDir::new("static"))
        .layer(Extension(CookieSecret(config.cookie_secret.clone())))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from_str(&config.listen)
        .map_err(|e| anyhow::anyhow!("invalid LISTEN address {:?}: {}", config.listen, e))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}
