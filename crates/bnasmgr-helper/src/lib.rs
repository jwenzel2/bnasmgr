use async_trait::async_trait;
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HelperOperation {
    ListStorage,
    ListSnapshots {
        dataset: Option<String>,
    },
    CreateSnapshot {
        dataset: String,
        name: String,
    },
    DeleteSnapshot {
        snapshot: String,
    },
    RollbackSnapshot {
        snapshot: String,
    },
    SetQuota {
        dataset: String,
        quota: String,
    },
    ApplySambaShare {
        name: String,
        path: String,
        allowed_users: Vec<String>,
        readonly: bool,
    },
    DeleteSambaShare {
        name: String,
    },
    UpsertSambaUser {
        username: String,
        password: String,
        enabled: bool,
    },
    DeleteSambaUser {
        username: String,
    },
    ApplyNfsExport {
        path: String,
        clients: String,
        options: String,
    },
    DeleteNfsExport {
        path: String,
    },
    ServiceStatus {
        service: String,
    },
    ServiceAction {
        service: String,
        action: ServiceAction,
    },
    ReadLogs {
        service: Option<String>,
        severity: Option<String>,
        search: Option<String>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelperRequest {
    pub actor: String,
    pub operation: HelperOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelperResponse {
    pub ok: bool,
    pub category: String,
    pub target: String,
    pub message: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageDataset {
    pub name: String,
    pub used: String,
    pub available: String,
    pub quota: Option<String>,
    pub mountpoint: String,
    pub health: String,
    pub snapshots: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    pub dataset: String,
    pub created_at: DateTime<Utc>,
    pub used: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub label: String,
    pub status: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub service: String,
    pub severity: String,
    pub message: String,
}

#[derive(thiserror::Error, Debug)]
pub enum HelperError {
    #[error("operation rejected: {0}")]
    Rejected(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[async_trait]
pub trait HelperClient: Send + Sync {
    async fn execute(&self, request: HelperRequest) -> Result<HelperResponse, HelperError>;
}

#[derive(Debug, Default)]
pub struct MockHelper;

#[async_trait]
impl HelperClient for MockHelper {
    async fn execute(&self, request: HelperRequest) -> Result<HelperResponse, HelperError> {
        let now = Utc::now();
        let response = match request.operation {
            HelperOperation::ListStorage => HelperResponse {
                ok: true,
                category: "storage".into(),
                target: "overview".into(),
                message: "mock storage loaded".into(),
                data: serde_json::json!({
                    "pools": [{"name": "tank", "health": "online", "used": "1.2T", "available": "6.8T"}],
                    "datasets": [
                        {"name":"tank/media","used":"820G","available":"5.4T","quota":"6T","mountpoint":"/mnt/tank/media","health":"online","snapshots":12},
                        {"name":"tank/backups","used":"410G","available":"1.4T","quota":"2T","mountpoint":"/mnt/tank/backups","health":"online","snapshots":31}
                    ]
                }),
            },
            HelperOperation::ListSnapshots { dataset } => {
                let ds = dataset.unwrap_or_else(|| "tank/media".into());
                HelperResponse {
                    ok: true,
                    category: "snapshot".into(),
                    target: ds.clone(),
                    message: "mock snapshots loaded".into(),
                    data: serde_json::json!([
                        {"name": format!("{ds}@daily-2026-05-18"), "dataset": ds, "created_at": now, "used": "42M"}
                    ]),
                }
            }
            HelperOperation::CreateSnapshot { dataset, name } => HelperResponse {
                ok: true,
                category: "snapshot".into(),
                target: format!("{dataset}@{name}"),
                message: "snapshot created".into(),
                data: serde_json::json!({ "name": format!("{dataset}@{name}") }),
            },
            HelperOperation::DeleteSnapshot { snapshot } => HelperResponse {
                ok: true,
                category: "snapshot".into(),
                target: snapshot,
                message: "snapshot deleted".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::RollbackSnapshot { snapshot } => HelperResponse {
                ok: true,
                category: "snapshot".into(),
                target: snapshot,
                message: "snapshot rolled back".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::SetQuota { dataset, quota } => HelperResponse {
                ok: true,
                category: "quota".into(),
                target: dataset,
                message: format!("quota set to {quota}"),
                data: serde_json::json!({}),
            },
            HelperOperation::ApplySambaShare { name, .. } => HelperResponse {
                ok: true,
                category: "samba".into(),
                target: name,
                message: "samba share applied".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::DeleteSambaShare { name } => HelperResponse {
                ok: true,
                category: "samba".into(),
                target: name,
                message: "samba share removed".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::UpsertSambaUser {
                username, enabled, ..
            } => HelperResponse {
                ok: true,
                category: "samba_user".into(),
                target: username,
                message: if enabled {
                    "samba user password set".into()
                } else {
                    "samba user password set and disabled".into()
                },
                data: serde_json::json!({}),
            },
            HelperOperation::DeleteSambaUser { username } => HelperResponse {
                ok: true,
                category: "samba_user".into(),
                target: username,
                message: "samba user deleted".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::ApplyNfsExport { path, .. } => HelperResponse {
                ok: true,
                category: "nfs".into(),
                target: path,
                message: "nfs export applied".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::DeleteNfsExport { path } => HelperResponse {
                ok: true,
                category: "nfs".into(),
                target: path,
                message: "nfs export removed".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::ServiceStatus { service } => {
                let mut status = BTreeMap::new();
                status.insert("zfs".to_string(), "running".to_string());
                status.insert("samba_server".to_string(), "running".to_string());
                status.insert("nfsd".to_string(), "stopped".to_string());
                status.insert("ctld".to_string(), "unknown".to_string());
                let value = status
                    .get(&service)
                    .cloned()
                    .unwrap_or_else(|| "unknown".into());
                HelperResponse {
                    ok: true,
                    category: "service".into(),
                    target: service,
                    message: value.clone(),
                    data: serde_json::json!({ "status": value, "color": service_color(&value) }),
                }
            }
            HelperOperation::ServiceAction { service, action } => HelperResponse {
                ok: true,
                category: "service".into(),
                target: service,
                message: format!("{action:?} requested"),
                data: serde_json::json!({ "status": "running", "color": "green" }),
            },
            HelperOperation::ReadLogs {
                service,
                severity,
                search,
                from,
                to,
            } => HelperResponse {
                ok: true,
                category: "logs".into(),
                target: service.clone().unwrap_or_else(|| "all".into()),
                message: "mock logs loaded".into(),
                data: serde_json::to_value(filter_log_entries(
                    vec![LogEntry {
                        timestamp: now,
                        service: service.unwrap_or_else(|| "samba".into()),
                        severity: severity.unwrap_or_else(|| "info".into()),
                        message: search.unwrap_or_else(|| "Mock log entry".into()),
                    }],
                    None,
                    None,
                    None,
                    from,
                    to,
                ))
                .unwrap_or_else(|_| serde_json::json!([])),
            },
        };
        Ok(response)
    }
}

#[derive(Debug, Clone)]
pub struct UnixSocketHelper {
    socket_path: String,
}

impl UnixSocketHelper {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }
}

#[async_trait]
impl HelperClient for UnixSocketHelper {
    async fn execute(&self, request: HelperRequest) -> Result<HelperResponse, HelperError> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|err| HelperError::Other(err.into()))?;
        let (reader, mut writer) = stream.into_split();
        let payload =
            serde_json::to_string(&request).map_err(|err| HelperError::Other(err.into()))?;
        writer
            .write_all(payload.as_bytes())
            .await
            .map_err(|err| HelperError::Other(err.into()))?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|err| HelperError::Other(err.into()))?;
        let mut lines = BufReader::new(reader).lines();
        let line = lines
            .next_line()
            .await
            .map_err(|err| HelperError::Other(err.into()))?
            .ok_or_else(|| HelperError::Rejected("helper socket closed without response".into()))?;
        serde_json::from_str(&line).map_err(|err| HelperError::Other(err.into()))
    }
}

pub fn service_color(status: &str) -> &'static str {
    match status {
        "running" | "online" | "ok" => "green",
        "degraded" | "starting" | "stopping" | "unknown" => "yellow",
        _ => "red",
    }
}

pub fn allowed_service(service: &str) -> bool {
    matches!(
        service,
        "zfs" | "samba_server" | "nfsd" | "mountd" | "rpcbind" | "ctld" | "syslogd"
    )
}

#[derive(Debug, Default)]
pub struct FreeBsdCommandBuilder;

impl FreeBsdCommandBuilder {
    pub fn build(operation: &HelperOperation) -> Result<Vec<String>, HelperError> {
        fn safe_arg(value: &str) -> Result<(), HelperError> {
            if value.is_empty()
                || value.contains('\0')
                || value.contains('\n')
                || value.contains(';')
                || value.contains('&')
                || value.contains('|')
                || value.contains('`')
            {
                return Err(HelperError::Rejected("unsafe command argument".into()));
            }
            Ok(())
        }

        let cmd = match operation {
            HelperOperation::ListStorage => vec![
                "zfs".into(),
                "list".into(),
                "-Hp".into(),
                "-o".into(),
                "name,used,avail,quota,mountpoint".into(),
            ],
            HelperOperation::ListSnapshots { dataset } => {
                if let Some(dataset) = dataset {
                    safe_arg(dataset)?;
                    vec![
                        "zfs".into(),
                        "list".into(),
                        "-Hp".into(),
                        "-t".into(),
                        "snapshot".into(),
                        "-o".into(),
                        "name,used,creation".into(),
                        "-r".into(),
                        dataset.clone(),
                    ]
                } else {
                    vec![
                        "zfs".into(),
                        "list".into(),
                        "-Hp".into(),
                        "-t".into(),
                        "snapshot".into(),
                        "-o".into(),
                        "name,used,creation".into(),
                    ]
                }
            }
            HelperOperation::CreateSnapshot { dataset, name } => {
                safe_arg(dataset)?;
                safe_arg(name)?;
                vec!["zfs".into(), "snapshot".into(), format!("{dataset}@{name}")]
            }
            HelperOperation::DeleteSnapshot { snapshot } => {
                safe_arg(snapshot)?;
                vec!["zfs".into(), "destroy".into(), snapshot.clone()]
            }
            HelperOperation::RollbackSnapshot { snapshot } => {
                safe_arg(snapshot)?;
                vec!["zfs".into(), "rollback".into(), snapshot.clone()]
            }
            HelperOperation::SetQuota { dataset, quota } => {
                safe_arg(dataset)?;
                safe_arg(quota)?;
                if !valid_quota(quota) {
                    return Err(HelperError::Rejected("invalid quota value".into()));
                }
                vec![
                    "zfs".into(),
                    "set".into(),
                    format!("quota={quota}"),
                    dataset.clone(),
                ]
            }
            HelperOperation::ApplySambaShare {
                name,
                path,
                allowed_users,
                ..
            } => {
                safe_arg(name)?;
                safe_arg(path)?;
                for user in allowed_users {
                    safe_arg(user)?;
                }
                vec!["service".into(), "samba_server".into(), "reload".into()]
            }
            HelperOperation::DeleteSambaShare { name } => {
                safe_arg(name)?;
                vec!["service".into(), "samba_server".into(), "reload".into()]
            }
            HelperOperation::UpsertSambaUser { username, .. } => {
                safe_arg(username)?;
                vec![
                    "smbpasswd".into(),
                    "-a".into(),
                    "-s".into(),
                    username.clone(),
                ]
            }
            HelperOperation::DeleteSambaUser { username } => {
                safe_arg(username)?;
                vec!["pdbedit".into(), "-x".into(), "-u".into(), username.clone()]
            }
            HelperOperation::ApplyNfsExport {
                path,
                clients,
                options,
            } => {
                safe_arg(path)?;
                safe_arg(clients)?;
                safe_arg(options)?;
                vec!["service".into(), "mountd".into(), "reload".into()]
            }
            HelperOperation::DeleteNfsExport { path } => {
                safe_arg(path)?;
                vec!["service".into(), "mountd".into(), "reload".into()]
            }
            HelperOperation::ServiceStatus { service } => {
                safe_arg(service)?;
                if !allowed_service(service) {
                    return Err(HelperError::Rejected("service is not allowlisted".into()));
                }
                vec!["service".into(), service.clone(), "status".into()]
            }
            HelperOperation::ServiceAction { service, action } => {
                safe_arg(service)?;
                if !allowed_service(service) {
                    return Err(HelperError::Rejected("service is not allowlisted".into()));
                }
                let verb = match action {
                    ServiceAction::Start => "start",
                    ServiceAction::Stop => "stop",
                    ServiceAction::Restart => "restart",
                };
                vec!["service".into(), service.clone(), verb.into()]
            }
            HelperOperation::ReadLogs { service, .. } => {
                if let Some(service) = service {
                    safe_arg(service)?;
                    vec![
                        "tail".into(),
                        "-n".into(),
                        "500".into(),
                        format!("/var/log/{service}.log"),
                    ]
                } else {
                    vec![
                        "tail".into(),
                        "-n".into(),
                        "500".into(),
                        "/var/log/messages".into(),
                    ]
                }
            }
        };
        Ok(cmd)
    }
}

pub fn valid_quota(quota: &str) -> bool {
    let trimmed = quota.trim();
    if matches!(trimmed, "none" | "off") {
        return true;
    }
    let Some(unit) = trimmed.chars().last() else {
        return false;
    };
    let number = if unit.is_ascii_alphabetic() {
        &trimmed[..trimmed.len().saturating_sub(unit.len_utf8())]
    } else {
        trimmed
    };
    !number.is_empty()
        && number.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
        && number.chars().filter(|ch| *ch == '.').count() <= 1
        && unit
            .to_ascii_uppercase()
            .to_string()
            .chars()
            .all(|ch| matches!(ch, '0'..='9' | 'K' | 'M' | 'G' | 'T' | 'P' | 'E'))
}

#[derive(Debug, Default)]
pub struct FreeBsdHelper;

#[async_trait]
impl HelperClient for FreeBsdHelper {
    async fn execute(&self, request: HelperRequest) -> Result<HelperResponse, HelperError> {
        let operation = request.operation;
        match &operation {
            HelperOperation::ListStorage => return freebsd_storage_overview().await,
            HelperOperation::ListSnapshots { .. } => return freebsd_snapshots(&operation).await,
            HelperOperation::ServiceStatus { .. } => {
                return freebsd_service_status(&operation).await
            }
            HelperOperation::ReadLogs { .. } => return freebsd_logs(&operation).await,
            HelperOperation::ApplySambaShare { .. }
            | HelperOperation::DeleteSambaShare { .. }
            | HelperOperation::ApplyNfsExport { .. }
            | HelperOperation::DeleteNfsExport { .. } => {
                return freebsd_apply_share_fragment(&operation).await
            }
            HelperOperation::UpsertSambaUser { .. } => {
                return freebsd_upsert_samba_user(&operation).await
            }
            _ => {}
        }
        let cmd = FreeBsdCommandBuilder::build(&operation)?;
        let output = run_command(cmd).await?;
        let (category, target) = operation_category_target(&operation);
        Ok(HelperResponse {
            ok: output.ok,
            category,
            target,
            message: if output.ok {
                output.stdout.clone()
            } else {
                output.stderr.clone()
            },
            data: serde_json::json!({
                "stdout": output.stdout,
                "stderr": output.stderr,
                "status": output.status
            }),
        })
    }
}

#[derive(Debug)]
struct CommandResult {
    ok: bool,
    stdout: String,
    stderr: String,
    status: Option<i32>,
}

async fn run_command(cmd: Vec<String>) -> Result<CommandResult, HelperError> {
    let (program, args) = cmd
        .split_first()
        .ok_or_else(|| HelperError::Rejected("empty command".into()))?;
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    Ok(CommandResult {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        status: output.status.code(),
    })
}

async fn run_command_with_stdin(
    cmd: Vec<String>,
    stdin: &[u8],
) -> Result<CommandResult, HelperError> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let (program, args) = cmd
        .split_first()
        .ok_or_else(|| HelperError::Rejected("empty command".into()))?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HelperError::Other(err.into()))?;
    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin
            .write_all(stdin)
            .await
            .map_err(|err| HelperError::Other(err.into()))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    Ok(CommandResult {
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        status: output.status.code(),
    })
}

async fn freebsd_storage_overview() -> Result<HelperResponse, HelperError> {
    let pools = run_command(vec![
        "zpool".into(),
        "list".into(),
        "-Hp".into(),
        "-o".into(),
        "name,health,allocated,free".into(),
    ])
    .await?;
    let datasets =
        run_command(FreeBsdCommandBuilder::build(&HelperOperation::ListStorage)?).await?;
    let snapshots = run_command(vec![
        "zfs".into(),
        "list".into(),
        "-Hp".into(),
        "-t".into(),
        "snapshot".into(),
        "-o".into(),
        "name".into(),
    ])
    .await;

    if !pools.ok || !datasets.ok {
        return Ok(HelperResponse {
            ok: false,
            category: "storage".into(),
            target: "overview".into(),
            message: if !pools.ok {
                pools.stderr
            } else {
                datasets.stderr
            },
            data: serde_json::json!({}),
        });
    }

    let pool_rows = parse_zpool_list(&pools.stdout);
    let snapshot_counts = snapshots
        .ok()
        .filter(|result| result.ok)
        .map(|result| parse_snapshot_counts(&result.stdout))
        .unwrap_or_default();
    let dataset_rows = parse_zfs_datasets(&datasets.stdout, &pool_rows, &snapshot_counts);
    Ok(HelperResponse {
        ok: true,
        category: "storage".into(),
        target: "overview".into(),
        message: "storage loaded".into(),
        data: serde_json::json!({
            "pools": pool_rows,
            "datasets": dataset_rows,
        }),
    })
}

async fn freebsd_snapshots(operation: &HelperOperation) -> Result<HelperResponse, HelperError> {
    let cmd = FreeBsdCommandBuilder::build(operation)?;
    let output = run_command(cmd).await?;
    let (category, target) = operation_category_target(operation);
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "snapshots loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            serde_json::to_value(parse_zfs_snapshots(&output.stdout))
                .unwrap_or_else(|_| serde_json::json!([]))
        } else {
            serde_json::json!({})
        },
    })
}

async fn freebsd_service_status(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let cmd = FreeBsdCommandBuilder::build(operation)?;
    let output = run_command(cmd).await?;
    let (category, target) = operation_category_target(operation);
    let status = parse_service_status(&output.stdout, &output.stderr, output.ok);
    Ok(HelperResponse {
        ok: true,
        category,
        target,
        message: status.clone(),
        data: serde_json::json!({
            "status": status,
            "color": service_color(&status),
            "stdout": output.stdout,
            "stderr": output.stderr,
        }),
    })
}

async fn freebsd_logs(operation: &HelperOperation) -> Result<HelperResponse, HelperError> {
    let HelperOperation::ReadLogs {
        service,
        severity,
        search,
        from,
        to,
    } = operation
    else {
        return Err(HelperError::Rejected("expected log operation".into()));
    };
    let output = run_command(FreeBsdCommandBuilder::build(operation)?).await?;
    let (category, target) = operation_category_target(operation);
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "logs loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            serde_json::to_value(parse_log_lines(
                &output.stdout,
                service.as_deref(),
                severity.as_deref(),
                search.as_deref(),
                *from,
                *to,
            ))
            .unwrap_or_else(|_| serde_json::json!([]))
        } else {
            serde_json::json!({})
        },
    })
}

async fn freebsd_apply_share_fragment(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let (category, target) = operation_category_target(operation);
    match operation {
        HelperOperation::ApplySambaShare {
            name,
            path,
            allowed_users,
            readonly,
        } => {
            let dir = config_dir(
                "BNASMGR_SAMBA_INCLUDE_DIR",
                "/usr/local/etc/bnasmgr/smb4.includes",
            );
            let file = dir.join(format!("{}.conf", safe_file_stem(name)?));
            atomic_write(
                &file,
                &render_samba_share(name, path, allowed_users, *readonly),
            )
            .await?;
        }
        HelperOperation::DeleteSambaShare { name } => {
            let dir = config_dir(
                "BNASMGR_SAMBA_INCLUDE_DIR",
                "/usr/local/etc/bnasmgr/smb4.includes",
            );
            remove_if_exists(dir.join(format!("{}.conf", safe_file_stem(name)?))).await?;
        }
        HelperOperation::ApplyNfsExport {
            path,
            clients,
            options,
        } => {
            let dir = config_dir(
                "BNASMGR_NFS_EXPORTS_DIR",
                "/usr/local/etc/bnasmgr/exports.d",
            );
            let file = dir.join(format!("{}.exports", safe_file_stem(path)?));
            atomic_write(&file, &render_nfs_export(path, clients, options)).await?;
        }
        HelperOperation::DeleteNfsExport { path } => {
            let dir = config_dir(
                "BNASMGR_NFS_EXPORTS_DIR",
                "/usr/local/etc/bnasmgr/exports.d",
            );
            remove_if_exists(dir.join(format!("{}.exports", safe_file_stem(path)?))).await?;
        }
        _ => return Err(HelperError::Rejected("expected share operation".into())),
    }

    let output = run_command(FreeBsdCommandBuilder::build(operation)?).await?;
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "share configuration applied".into()
        } else {
            output.stderr
        },
        data: serde_json::json!({ "status": output.status }),
    })
}

fn config_dir(env_key: &str, default: &str) -> PathBuf {
    std::env::var(env_key)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

async fn atomic_write(path: &PathBuf, contents: &str) -> Result<(), HelperError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|err| HelperError::Other(err.into()))?;
    }
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, contents)
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    Ok(())
}

async fn remove_if_exists(path: PathBuf) -> Result<(), HelperError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(HelperError::Other(err.into())),
    }
}

fn safe_file_stem(value: &str) -> Result<String, HelperError> {
    let stem: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let stem = stem.trim_matches('_').to_string();
    if stem.is_empty() {
        return Err(HelperError::Rejected(
            "unable to derive config file name".into(),
        ));
    }
    Ok(stem)
}

fn render_samba_share(name: &str, path: &str, allowed_users: &[String], readonly: bool) -> String {
    let mut lines = vec![
        format!("[{name}]"),
        format!("    path = {path}"),
        "    browseable = yes".into(),
        format!("    read only = {}", if readonly { "yes" } else { "no" }),
    ];
    if !allowed_users.is_empty() {
        lines.push(format!("    valid users = {}", allowed_users.join(" ")));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn render_nfs_export(path: &str, clients: &str, options: &str) -> String {
    format!("{path} {options} {clients}\n")
}

async fn freebsd_upsert_samba_user(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::UpsertSambaUser {
        username,
        password,
        enabled,
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected samba user operation".into(),
        ));
    };
    let output = run_command_with_stdin(
        FreeBsdCommandBuilder::build(operation)?,
        format!("{password}\n{password}\n").as_bytes(),
    )
    .await?;
    if !output.ok {
        return Ok(HelperResponse {
            ok: false,
            category: "samba_user".into(),
            target: username.clone(),
            message: output.stderr,
            data: serde_json::json!({ "status": output.status }),
        });
    }
    if !enabled {
        let disabled = run_command(vec!["smbpasswd".into(), "-d".into(), username.clone()]).await?;
        if !disabled.ok {
            return Ok(HelperResponse {
                ok: false,
                category: "samba_user".into(),
                target: username.clone(),
                message: disabled.stderr,
                data: serde_json::json!({ "status": disabled.status }),
            });
        }
    }
    Ok(HelperResponse {
        ok: true,
        category: "samba_user".into(),
        target: username.clone(),
        message: if *enabled {
            "samba user password set".into()
        } else {
            "samba user password set and disabled".into()
        },
        data: serde_json::json!({}),
    })
}

fn parse_zpool_list(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next()?.to_string();
            let health = fields.next().unwrap_or("unknown").to_ascii_lowercase();
            let used = fields.next().unwrap_or("0").to_string();
            let available = fields.next().unwrap_or("0").to_string();
            Some(serde_json::json!({
                "name": name,
                "health": health,
                "used": used,
                "available": available,
            }))
        })
        .collect()
}

fn parse_snapshot_counts(stdout: &str) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();
    for line in stdout.lines() {
        if let Some((dataset, _)) = line.split_once('@') {
            *counts.entry(dataset.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

fn parse_zfs_datasets(
    stdout: &str,
    pools: &[serde_json::Value],
    snapshot_counts: &BTreeMap<String, u32>,
) -> Vec<serde_json::Value> {
    let pool_health: BTreeMap<String, String> = pools
        .iter()
        .filter_map(|pool| {
            Some((
                pool.get("name")?.as_str()?.to_string(),
                pool.get("health")?.as_str()?.to_string(),
            ))
        })
        .collect();
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next()?.to_string();
            let used = fields.next().unwrap_or("0").to_string();
            let available = fields.next().unwrap_or("0").to_string();
            let quota = match fields.next().unwrap_or("none") {
                "none" | "-" => None,
                value => Some(value.to_string()),
            };
            let mountpoint = fields.next().unwrap_or("-").to_string();
            let pool = name.split('/').next().unwrap_or(&name);
            let health = pool_health
                .get(pool)
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            Some(serde_json::json!({
                "name": name,
                "used": used,
                "available": available,
                "quota": quota,
                "mountpoint": mountpoint,
                "health": health,
                "snapshots": snapshot_counts.get(line.split('\t').next().unwrap_or_default()).copied().unwrap_or(0),
            }))
        })
        .collect()
}

fn parse_zfs_snapshots(stdout: &str) -> Vec<SnapshotInfo> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next()?.to_string();
            let used = fields.next().unwrap_or("0").to_string();
            let created_at = fields
                .next()
                .and_then(|value| value.parse::<i64>().ok())
                .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
                .unwrap_or_else(Utc::now);
            let dataset = name.split_once('@')?.0.to_string();
            Some(SnapshotInfo {
                name,
                dataset,
                created_at,
                used,
            })
        })
        .collect()
}

fn parse_service_status(stdout: &str, stderr: &str, success: bool) -> String {
    let text = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    if text.contains("not running") || text.contains("stopped") {
        "stopped".into()
    } else if text.contains("degraded") {
        "degraded".into()
    } else if success || text.contains("is running") || text.contains("running as pid") {
        "running".into()
    } else {
        "unknown".into()
    }
}

fn parse_log_lines(
    stdout: &str,
    service: Option<&str>,
    severity: Option<&str>,
    search: Option<&str>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Vec<LogEntry> {
    let entries = stdout
        .lines()
        .map(|line| LogEntry {
            timestamp: parse_log_timestamp(line).unwrap_or_else(Utc::now),
            service: service.unwrap_or("system").to_string(),
            severity: detect_log_severity(line),
            message: line.to_string(),
        })
        .collect();
    filter_log_entries(entries, service, severity, search, from, to)
}

fn filter_log_entries(
    entries: Vec<LogEntry>,
    service: Option<&str>,
    severity: Option<&str>,
    search: Option<&str>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Vec<LogEntry> {
    let severity_filter = severity.map(str::to_ascii_lowercase);
    let search_filter = search.map(str::to_ascii_lowercase);
    let service_filter = service.map(str::to_ascii_lowercase);
    entries
        .into_iter()
        .filter(|entry| {
            if let Some(filter) = &service_filter {
                if !entry.service.to_ascii_lowercase().contains(filter)
                    && !entry.message.to_ascii_lowercase().contains(filter)
                {
                    return false;
                }
            }
            if let Some(filter) = &severity_filter {
                if entry.severity.to_ascii_lowercase() != *filter {
                    return false;
                }
            }
            if let Some(filter) = &search_filter {
                if !entry.message.to_ascii_lowercase().contains(filter) {
                    return false;
                }
            }
            if let Some(from) = from {
                if entry.timestamp < from {
                    return false;
                }
            }
            if let Some(to) = to {
                if entry.timestamp > to {
                    return false;
                }
            }
            true
        })
        .collect()
}

fn detect_log_severity(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let detected = ["error", "warn", "warning", "notice", "info", "debug"]
        .iter()
        .find(|level| lower.contains(**level))
        .copied()
        .unwrap_or("info");
    if detected == "warning" {
        "warn".into()
    } else {
        detected.into()
    }
}

fn parse_log_timestamp(line: &str) -> Option<DateTime<Utc>> {
    if let Some(prefix) = line.get(..20) {
        if let Ok(value) = DateTime::parse_from_rfc3339(prefix.trim()) {
            return Some(value.with_timezone(&Utc));
        }
    }
    let mut parts = line.split_whitespace();
    let month = parts.next()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    let time = NaiveTime::parse_from_str(parts.next()?, "%H:%M:%S").ok()?;
    let month = match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let date = NaiveDate::from_ymd_opt(Utc::now().year(), month, day)?;
    Some(DateTime::from_naive_utc_and_offset(
        NaiveDateTime::new(date, time),
        Utc,
    ))
}

pub fn operation_category_target(operation: &HelperOperation) -> (String, String) {
    match operation {
        HelperOperation::ListStorage => ("storage".into(), "overview".into()),
        HelperOperation::ListSnapshots { dataset } => (
            "snapshot".into(),
            dataset.clone().unwrap_or_else(|| "all".into()),
        ),
        HelperOperation::CreateSnapshot { dataset, name } => {
            ("snapshot".into(), format!("{dataset}@{name}"))
        }
        HelperOperation::DeleteSnapshot { snapshot }
        | HelperOperation::RollbackSnapshot { snapshot } => ("snapshot".into(), snapshot.clone()),
        HelperOperation::SetQuota { dataset, .. } => ("quota".into(), dataset.clone()),
        HelperOperation::ApplySambaShare { name, .. }
        | HelperOperation::DeleteSambaShare { name } => ("samba".into(), name.clone()),
        HelperOperation::UpsertSambaUser { username, .. }
        | HelperOperation::DeleteSambaUser { username } => ("samba_user".into(), username.clone()),
        HelperOperation::ApplyNfsExport { path, .. }
        | HelperOperation::DeleteNfsExport { path } => ("nfs".into(), path.clone()),
        HelperOperation::ServiceStatus { service }
        | HelperOperation::ServiceAction { service, .. } => ("service".into(), service.clone()),
        HelperOperation::ReadLogs { service, .. } => (
            "logs".into(),
            service.clone().unwrap_or_else(|| "all".into()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_service_status_to_colors() {
        assert_eq!(service_color("running"), "green");
        assert_eq!(service_color("unknown"), "yellow");
        assert_eq!(service_color("stopped"), "red");
    }

    #[test]
    fn service_allowlist_rejects_unplanned_services() {
        let err = FreeBsdCommandBuilder::build(&HelperOperation::ServiceAction {
            service: "sshd".into(),
            action: ServiceAction::Restart,
        })
        .unwrap_err();
        assert!(err.to_string().contains("allowlisted"));
    }

    #[test]
    fn quota_values_are_validated_before_command_building() {
        assert!(valid_quota("2T"));
        assert!(valid_quota("none"));
        let err = FreeBsdCommandBuilder::build(&HelperOperation::SetQuota {
            dataset: "tank/media".into(),
            quota: "../../bad".into(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid quota") || err.to_string().contains("unsafe"));
    }

    #[test]
    fn builds_snapshot_command_without_shell() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::CreateSnapshot {
            dataset: "tank/media".into(),
            name: "daily".into(),
        })
        .unwrap();
        assert_eq!(cmd, vec!["zfs", "snapshot", "tank/media@daily"]);
    }

    #[test]
    fn rejects_unsafe_arguments() {
        let err = FreeBsdCommandBuilder::build(&HelperOperation::DeleteSnapshot {
            snapshot: "tank/a@snap;rm -rf /".into(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("rejected"));
    }

    #[test]
    fn share_operations_build_only_allowlisted_reload_commands() {
        let samba = FreeBsdCommandBuilder::build(&HelperOperation::ApplySambaShare {
            name: "media".into(),
            path: "/mnt/tank/media".into(),
            allowed_users: vec!["alice".into(), "bob".into()],
            readonly: false,
        })
        .unwrap();
        assert_eq!(samba, vec!["service", "samba_server", "reload"]);

        let nfs = FreeBsdCommandBuilder::build(&HelperOperation::ApplyNfsExport {
            path: "/mnt/tank/media".into(),
            clients: "192.168.1.0/24".into(),
            options: "-maproot=root".into(),
        })
        .unwrap();
        assert_eq!(nfs, vec!["service", "mountd", "reload"]);
    }

    #[test]
    fn samba_user_commands_do_not_include_passwords() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::UpsertSambaUser {
            username: "alice".into(),
            password: "not-in-argv".into(),
            enabled: true,
        })
        .unwrap();
        assert_eq!(cmd, vec!["smbpasswd", "-a", "-s", "alice"]);
        assert!(!cmd.iter().any(|arg| arg.contains("not-in-argv")));
    }

    #[test]
    fn renders_samba_and_nfs_fragments() {
        let samba = render_samba_share(
            "media",
            "/mnt/tank/media",
            &["alice".into(), "bob".into()],
            false,
        );
        assert!(samba.contains("[media]"));
        assert!(samba.contains("path = /mnt/tank/media"));
        assert!(samba.contains("read only = no"));
        assert!(samba.contains("valid users = alice bob"));

        let nfs = render_nfs_export("/mnt/tank/media", "192.168.1.0/24", "-maproot=root");
        assert_eq!(nfs, "/mnt/tank/media -maproot=root 192.168.1.0/24\n");
    }

    #[test]
    fn derives_safe_fragment_file_names() {
        assert_eq!(safe_file_stem("media").unwrap(), "media");
        assert_eq!(safe_file_stem("/mnt/tank/media").unwrap(), "mnt_tank_media");
    }

    #[test]
    fn rejects_unsafe_share_arguments() {
        let err = FreeBsdCommandBuilder::build(&HelperOperation::ApplySambaShare {
            name: "media".into(),
            path: "/mnt/tank/media;reboot".into(),
            allowed_users: vec!["alice".into()],
            readonly: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("rejected"));
    }

    #[test]
    fn parses_freebsd_storage_output() {
        let pools = parse_zpool_list("tank\tONLINE\t1099511627776\t2199023255552\n");
        let counts =
            parse_snapshot_counts("tank/media@daily\ntank/media@weekly\ntank/backups@daily\n");
        let datasets = parse_zfs_datasets(
            "tank/media\t879609302220\t5937362789990\t6597069766656\t/mnt/tank/media\n",
            &pools,
            &counts,
        );
        assert_eq!(pools[0]["name"], "tank");
        assert_eq!(pools[0]["health"], "online");
        assert_eq!(datasets[0]["name"], "tank/media");
        assert_eq!(datasets[0]["health"], "online");
        assert_eq!(datasets[0]["snapshots"], 2);
    }

    #[test]
    fn parses_freebsd_snapshot_output() {
        let snapshots = parse_zfs_snapshots("tank/media@daily\t41943040\t1779120000\n");
        assert_eq!(snapshots[0].name, "tank/media@daily");
        assert_eq!(snapshots[0].dataset, "tank/media");
        assert_eq!(snapshots[0].used, "41943040");
    }

    #[test]
    fn parses_service_status_without_treating_stopped_as_helper_failure() {
        assert_eq!(
            parse_service_status("samba_server is running as pid 42", "", true),
            "running"
        );
        assert_eq!(
            parse_service_status("", "nfsd is not running", false),
            "stopped"
        );
        assert_eq!(
            service_color(&parse_service_status("", "nfsd is not running", false)),
            "red"
        );
    }

    #[test]
    fn parses_and_filters_log_date_ranges() {
        let current_year = Utc::now().year();
        let from = DateTime::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(current_year, 5, 18).unwrap(),
                NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
            ),
            Utc,
        );
        let to = DateTime::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(current_year, 5, 18).unwrap(),
                NaiveTime::from_hms_opt(13, 0, 0).unwrap(),
            ),
            Utc,
        );
        let entries = parse_log_lines(
            "May 18 11:59:00 nas smbd[1]: info before\nMay 18 12:30:00 nas smbd[1]: error inside\nMay 18 13:30:00 nas smbd[1]: info after\n",
            Some("samba"),
            Some("error"),
            Some("inside"),
            Some(from),
            Some(to),
        );
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].severity, "error");
        assert!(entries[0].message.contains("inside"));
    }
}
