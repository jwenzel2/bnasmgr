use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use bnasmgr_api::{app, AppState};
use bnasmgr_helper::{MockHelper, UnixSocketHelper};
use sqlx::sqlite::SqlitePoolOptions;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bnasmgr_api=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_url = std::env::var("BNASMGR_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://bnasmgr.db?mode=rwc".into());
    let bind = std::env::var("BNASMGR_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .with_context(|| format!("connect database {db_url}"))?;

    let helper: Arc<dyn bnasmgr_helper::HelperClient> = match std::env::var("BNASMGR_HELPER_SOCKET")
    {
        Ok(path) => Arc::new(UnixSocketHelper::new(path)),
        Err(_) => Arc::new(MockHelper),
    };
    let state = AppState::new(pool, helper);
    state.migrate().await?;
    state.seed_admin().await?;

    let addr: SocketAddr = bind.parse().context("parse BNASMGR_BIND")?;
    let router = app(state);
    match (
        std::env::var("BNASMGR_TLS_CERT"),
        std::env::var("BNASMGR_TLS_KEY"),
    ) {
        (Ok(cert), Ok(key)) => {
            let config = RustlsConfig::from_pem_file(&cert, &key)
                .await
                .with_context(|| format!("load TLS certificate {cert} and key {key}"))?;
            tracing::info!(%addr, %cert, "bnasmgr api listening with https");
            axum_server::bind_rustls(addr, config)
                .serve(router.into_make_service())
                .await?;
        }
        _ => {
            let listener = TcpListener::bind(addr).await?;
            tracing::info!(%addr, "bnasmgr api listening without tls");
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}
