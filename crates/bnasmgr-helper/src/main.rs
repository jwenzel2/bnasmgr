use bnasmgr_helper::{FreeBsdHelper, HelperClient, HelperRequest, MockHelper};
use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
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
    let listener = bind_helper_socket(&path).await?;
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

async fn bind_helper_socket(path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if tokio::fs::try_exists(path).await? {
        let metadata = tokio::fs::symlink_metadata(path).await?;
        if !metadata.file_type().is_socket() {
            anyhow::bail!(
                "refusing to remove non-socket helper path {}",
                path.display()
            );
        }
        tokio::fs::remove_file(path).await?;
    }
    let listener = UnixListener::bind(path)?;
    set_helper_socket_permissions(path).await?;
    Ok(listener)
}

async fn set_helper_socket_permissions(path: &Path) -> anyhow::Result<()> {
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn helper_socket_permissions_are_group_writable_without_world_access() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bnasmgr-helper-{}-{suffix}.tmp",
            std::process::id()
        ));
        tokio::fs::write(&path, b"").await.unwrap();
        set_helper_socket_permissions(&path).await.unwrap();
        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        tokio::fs::remove_file(&path).await.unwrap();

        assert_eq!(mode, 0o660);
    }

    #[tokio::test]
    async fn helper_socket_bind_refuses_to_remove_non_socket_path() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "bnasmgr-helper-{}-{suffix}.txt",
            std::process::id()
        ));
        tokio::fs::write(&path, b"do not remove").await.unwrap();

        let err = bind_helper_socket(&path).await.unwrap_err();
        let contents = tokio::fs::read(&path).await.unwrap();
        tokio::fs::remove_file(&path).await.unwrap();

        assert!(err.to_string().contains("refusing to remove non-socket"));
        assert_eq!(contents, b"do not remove");
    }
}
