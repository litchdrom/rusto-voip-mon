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
mod sensors;
mod state;
mod users;

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

    // Detect IP column shape (legacy INT UNSIGNED vs post-ipv6-alter
    // VARBINARY(16)). Cached on AppState and used by every IP-shaped
    // query in cdr / sip_msg to pick the right SQL + Rust types.
    let ip_shape = db::detect_ip_column_shape(&pool).await;
    tracing::info!(?ip_shape, "ip column shape detected");

    let state = AppState {
        config: config.clone(),
        pool,
        tokens: std::sync::Arc::new(crate::auth::token::TokenStore::new()),
        ip_shape: std::sync::Arc::new(ip_shape),
    };

    // Routes that require an authenticated session.
    let protected = Router::new()
        .route("/", get(routes::cdr::cdr_list))
        .route("/cdr/:id", get(routes::cdr::cdr_detail))
        .route("/cdr/:id/rtp-chart.json", get(routes::cdr::rtp_chart_json))
        .route("/cdr/export.csv", get(routes::cdr::cdr_export_csv).post(routes::cdr::cdr_export_csv_batch))
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
        // /admin/* — admin-only CRUD over VoIPmonitor entities. Each
        // handler enforces `is_admin` itself; the protected router
        // middleware only checks that a session exists. We keep the
        // admin gate close to the SQL so future refactors can't
        // accidentally expose a privileged path.
        .route("/admin/sensors", get(routes::sensors::list))
        .route(
            "/admin/sensors/new",
            get(routes::sensors::new_form).post(routes::sensors::create),
        )
        .route(
            "/admin/sensors/:id_sensor/edit",
            get(routes::sensors::edit_form).post(routes::sensors::update),
        )
        .route(
            "/admin/sensors/:id_sensor/delete",
            post(routes::sensors::delete),
        )
        // /admin/users — admin-only CRUD over VoIPmonitor's users
        // table. Same gating pattern as /admin/sensors: each handler
        // enforces `is_admin` itself, with self-protection rules
        // blocking accidental self-lockout at the route layer.
        .route("/admin/users", get(routes::users::list))
        .route(
            "/admin/users/new",
            get(routes::users::new_form).post(routes::users::create),
        )
        .route(
            "/admin/users/:id/edit",
            get(routes::users::edit_form).post(routes::users::update),
        )
        .route(
            "/admin/users/:id/reset-password",
            post(routes::users::reset_password),
        )
        .route(
            "/admin/users/:id/delete",
            post(routes::users::delete),
        )
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
