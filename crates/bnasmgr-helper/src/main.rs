use bnasmgr_helper::{FreeBsdHelper, HelperClient, HelperRequest, MockHelper};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = std::env::var("BNASMGR_HELPER_SOCKET")
        .unwrap_or_else(|_| "/var/run/bnasmgr/helper.sock".into());
    let backend = std::env::var("BNASMGR_HELPER_BACKEND").unwrap_or_else(|_| "mock".into());
    let path = PathBuf::from(socket);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if tokio::fs::try_exists(&path).await? {
        tokio::fs::remove_file(&path).await?;
    }
    let listener = UnixListener::bind(&path)?;
    let helper: Arc<dyn HelperClient> = match backend.as_str() {
        "freebsd" => Arc::new(FreeBsdHelper),
        _ => Arc::new(MockHelper),
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let helper = helper.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(stream, helper).await {
                eprintln!("helper request failed: {err}");
            }
        });
    }
}

async fn handle(stream: UnixStream, helper: Arc<dyn HelperClient>) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let request: HelperRequest = serde_json::from_str(&line)?;
        let response = helper.execute(request).await;
        let payload = match response {
            Ok(value) => serde_json::to_string(&value)?,
            Err(err) => serde_json::to_string(&serde_json::json!({
                "ok": false,
                "category": "helper",
                "target": "request",
                "message": err.to_string(),
                "data": {}
            }))?,
        };
        writer.write_all(payload.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    Ok(())
}
