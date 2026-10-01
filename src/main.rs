use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    middleware as axum_middleware,
    routing::{get, post},
    Extension, Router,
};
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod auth;
mod cdr;
mod config;
mod db;
mod error;
mod middleware;
mod routes;
mod state;

use crate::auth::session::CookieSecret;
use crate::config::Config;
use crate::middleware::require_login;
use crate::state::AppState;

/// Build identity baked into the binary at compile time via vergen.
/// `VERGEN_GIT_SHA` is "true" in a dirty worktree (the cargo metadata
/// won't have a clean SHA) and "unknown" if git isn't reachable —
/// both surface in --version output so a broken build is obvious
/// at a glance.
fn build_version() -> &'static str {
    concat!(
        env!("CARGO_PKG_VERSION"),
        " (commit ",
        env!("VERGEN_GIT_SHA"),
        ", built ",
        env!("VERGEN_BUILD_TIMESTAMP"),
        ")",
    )
}

/// One-line self-identification for `--version` / `-V`. Useful when
/// debugging a deployed server: compare against `git rev-parse HEAD`
/// on the build host to confirm the running binary matches source.
fn print_version_and_exit() -> ! {
    println!("rusto-voip-mon {}", build_version());
    std::process::exit(0);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Handle `--version` / `-V` before any heavy init (DB pool, env
    // loading). Cheap operation, never touches the network.
    if let Some(arg) = std::env::args().nth(1) {
        if arg == "--version" || arg == "-V" {
            print_version_and_exit();
        }
    }

    // .env is optional; ignore if missing
    let _ = dotenvy::dotenv();

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // First log line of every process — answers "what code is
    // actually running on this server?" without needing ssh + ps.
    tracing::info!(
        version = build_version(),
        "rusto-voip-mon starting"
    );

    let config = Arc::new(Config::from_env()?);
    tracing::info!(listen = %config.listen, "config loaded");

    let pool = db::create_pool(&config.database_url).await?;
    tracing::info!("connected to MySQL");

    let state = AppState {
        config: config.clone(),
        pool,
        tokens: std::sync::Arc::new(crate::auth::token::TokenStore::new()),
    };

    // Routes that require an authenticated session.
    let protected = Router::new()
        .route("/", get(routes::cdr::cdr_list))
        .route("/cdr/:id", get(routes::cdr::cdr_detail))
        .route("/cdr/:id/rtp-chart.json", get(routes::cdr::rtp_chart_json))
        .route("/cdr/export.csv", get(routes::cdr::cdr_export_csv))
        .route("/cdr/select", post(routes::login::select_cdrs))
        .route("/pcap/:cdr_id", get(routes::pcap::download_single))
        // POST /pcap/batch  — JSON body, used by the JS frontend
        // GET  /pcap/batch  — query string, used by <noscript> links and
        //                     any no-JS client (curl, scripts, bookmarks)
        .route(
            "/pcap/batch",
            post(routes::pcap::download_batch).get(routes::pcap::download_batch_get),
        )
        .route("/auth/tokens", post(routes::auth::create_token).get(routes::auth::list_tokens))
        .route("/auth/tokens/:id", axum::routing::delete(routes::auth::revoke_token))
        .route("/tz", post(routes::login::set_tz))
        .route_layer(axum_middleware::from_fn(require_login));

    // Public routes — login, health, static assets.
    let public = Router::new()
        .route(
            "/login",
            get(routes::login::login_form).post(routes::login::login_submit),
        )
        .route("/logout", post(routes::login::logout))
        .route("/healthz", get(healthz))
        .nest_service("/static", ServeDir::new("static"));

    let app = protected
        .merge(public)
        .layer(Extension(CookieSecret(
            config.cookie_secret.clone(),
        )))
        // Expose the token store as a request extension so the
        // SessionUser extractor (used by every protected handler) can
        // resolve `Authorization: Bearer …` without needing AppState in
        // its FromRequestParts bound.
        .layer(Extension(state.tokens.clone()))
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
