use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use bnasmgr_api::{app_with_static_dir, AppState};
use bnasmgr_helper::{MockHelper, UnixSocketHelper};
use sqlx::sqlite::SqlitePoolOptions;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
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
    if std::env::var("BNASMGR_SNAPSHOT_SCHEDULER").as_deref() != Ok("off") {
        let scheduler_state = state.clone();
        let interval_seconds = std::env::var("BNASMGR_SNAPSHOT_SCHEDULER_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value >= 10)
            .unwrap_or(60);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
            loop {
                interval.tick().await;
                match scheduler_state.run_due_snapshot_tasks().await {
                    Ok(ran) if ran > 0 => tracing::info!(ran, "scheduled snapshot tasks ran"),
                    Ok(_) => {}
                    Err(err) => tracing::warn!(?err, "scheduled snapshot task scan failed"),
                }
            }
        });
    }
    if std::env::var("BNASMGR_REPLICATION_SCHEDULER").as_deref() != Ok("off") {
        let scheduler_state = state.clone();
        let interval_seconds = std::env::var("BNASMGR_REPLICATION_SCHEDULER_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value >= 10)
            .unwrap_or(60);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
            loop {
                interval.tick().await;
                match scheduler_state.run_due_replication_tasks().await {
                    Ok(ran) if ran > 0 => tracing::info!(ran, "scheduled replication tasks ran"),
                    Ok(_) => {}
                    Err(err) => tracing::warn!(?err, "scheduled replication task scan failed"),
                }
            }
        });
    }
    if std::env::var("BNASMGR_ALERT_NOTIFIER").as_deref() != Ok("off") {
        let notifier_state = state.clone();
        let interval_seconds = std::env::var("BNASMGR_ALERT_NOTIFIER_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value >= 30)
            .unwrap_or(300);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
            loop {
                interval.tick().await;
                match notifier_state.run_alert_notifications().await {
                    Ok(sent) if sent > 0 => {
                        tracing::info!(sent, "alert notification delivery attempts queued")
                    }
                    Ok(_) => {}
                    Err(err) => tracing::warn!(?err, "alert notification scan failed"),
                }
            }
        });
    }

    let addr: SocketAddr = bind.parse().context("parse BNASMGR_BIND")?;
    let static_dir = std::env::var("BNASMGR_STATIC_DIR").ok().map(PathBuf::from);
    if let Some(static_dir) = &static_dir {
        tracing::info!(path = %static_dir.display(), "serving built frontend assets");
    }
    let router = app_with_static_dir(state, static_dir);
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
