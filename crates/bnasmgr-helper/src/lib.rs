use async_trait::async_trait;
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
    SystemReport,
    ListNetworkInterfaces,
    ApplyNetworkInterfaceConfig {
        name: String,
        mode: String,
        ipv4_address: Option<String>,
        netmask: Option<String>,
        gateway: Option<String>,
    },
    ApplyDnsResolverConfig {
        nameservers: Vec<String>,
        search_domains: Vec<String>,
    },
    ApplyStaticRoutesConfig {
        routes: Vec<StaticRouteConfig>,
    },
    ListUpsStatus,
    ExecuteUpsShutdown {
        command: String,
    },
    ApplyDirectoryServiceSettings {
        enabled: bool,
        provider: String,
        domain: String,
        uri: String,
        base_dn: String,
        bind_dn: Option<String>,
        tls: bool,
        ca_cert_path: Option<String>,
        nss_enabled: bool,
        pam_enabled: bool,
    },
    ValidateDirectoryService {
        provider: String,
        domain: String,
        uri: String,
        tls: bool,
        ca_cert_path: Option<String>,
    },
    JoinActiveDirectory {
        domain: String,
        username: String,
        password: String,
    },
    LeaveActiveDirectory {
        domain: String,
        username: Option<String>,
        password: Option<String>,
    },
    ListSmartDisks,
    StartSmartTest {
        device: String,
        device_type: Option<String>,
        test: String,
    },
    ListSmartSelfTests {
        device: String,
        device_type: Option<String>,
    },
    PoolScrubStatus {
        pool: String,
    },
    PoolScrubAction {
        pool: String,
        action: PoolScrubAction,
    },
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
    CloneSnapshot {
        snapshot: String,
        target_dataset: String,
    },
    DiffSnapshots {
        snapshot: String,
        to_snapshot: Option<String>,
    },
    CreateDataset {
        name: String,
        compression: Option<String>,
        atime: Option<String>,
        quota: Option<String>,
        reservation: Option<String>,
        mountpoint: Option<String>,
    },
    UpdateDataset {
        name: String,
        compression: Option<String>,
        atime: Option<String>,
        quota: Option<String>,
        reservation: Option<String>,
        mountpoint: Option<String>,
    },
    DeleteDataset {
        name: String,
    },
    SetQuota {
        dataset: String,
        quota: String,
    },
    ApplySambaServerSettings {
        workgroup: String,
        server_string: String,
        netbios_name: String,
        security: String,
        map_to_guest: String,
        log_level: String,
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
    ApplyIscsiTarget {
        name: String,
        portal_group: String,
        initiator_name: Option<String>,
        auth_group: String,
        extent_name: String,
        path: String,
        size: Option<String>,
        lun_id: u32,
        readonly: bool,
    },
    DeleteIscsiTarget {
        name: String,
    },
    ListLocalUsers,
    UpsertLocalUser {
        username: String,
        full_name: Option<String>,
        shell: String,
        home: Option<String>,
        groups: Vec<String>,
        password: Option<String>,
        create_home: bool,
    },
    DeleteLocalUser {
        username: String,
        remove_home: bool,
    },
    ListLocalGroups,
    UpsertLocalGroup {
        name: String,
        members: Vec<String>,
    },
    DeleteLocalGroup {
        name: String,
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
    SearchSnapshotFiles {
        snapshot: String,
        search: Option<String>,
    },
    RestoreSnapshotFiles {
        snapshot: String,
        files: Vec<String>,
    },
    RunReplication {
        snapshot: String,
        base_snapshot: Option<String>,
        destination_dataset: String,
        remote_host: Option<String>,
        remote_user: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PoolScrubAction {
    Start,
    Stop,
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
pub struct StaticRouteConfig {
    pub destination: String,
    pub gateway: String,
    pub description: Option<String>,
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
                        {"name":"tank/media","used":"820G","available":"5.4T","quota":"6T","reservation":null,"mountpoint":"/mnt/tank/media","compression":"lz4","atime":"off","health":"online","snapshots":12},
                        {"name":"tank/backups","used":"410G","available":"1.4T","quota":"2T","reservation":null,"mountpoint":"/mnt/tank/backups","compression":"zstd","atime":"off","health":"online","snapshots":31}
                    ]
                }),
            },
            HelperOperation::SystemReport => HelperResponse {
                ok: true,
                category: "system_report".into(),
                target: "localhost".into(),
                message: "mock system report loaded".into(),
                data: serde_json::json!({
                    "hostname": "bnasmgr-mock",
                    "os": "FreeBSD",
                    "release": "14.2-RELEASE",
                    "uptime_seconds": 86400,
                    "cpu_model": "Mock CPU",
                    "cpu_cores": 8,
                    "memory_bytes": 17179869184u64,
                    "memory_free_bytes": 8589934592u64,
                    "swap_total_bytes": 4294967296u64,
                    "load_average": [0.12, 0.18, 0.21]
                }),
            },
            HelperOperation::ListNetworkInterfaces => HelperResponse {
                ok: true,
                category: "network".into(),
                target: "interfaces".into(),
                message: "mock network interfaces loaded".into(),
                data: serde_json::json!([
                    {"name":"em0","status":"active","mac":"02:00:00:00:00:01","ipv4":["192.168.1.50"],"ipv6":["fe80::1"],"mtu":1500},
                    {"name":"lo0","status":"active","mac":null,"ipv4":["127.0.0.1"],"ipv6":["::1"],"mtu":16384}
                ]),
            },
            HelperOperation::ApplyNetworkInterfaceConfig { name, mode, .. } => HelperResponse {
                ok: true,
                category: "network_config".into(),
                target: name,
                message: format!("mock network interface set to {mode}"),
                data: serde_json::json!({}),
            },
            HelperOperation::ApplyDnsResolverConfig {
                nameservers,
                search_domains,
            } => HelperResponse {
                ok: true,
                category: "network_dns".into(),
                target: "resolver".into(),
                message: "mock DNS resolver settings applied".into(),
                data: serde_json::json!({
                    "nameservers": nameservers,
                    "search_domains": search_domains,
                }),
            },
            HelperOperation::ApplyStaticRoutesConfig { routes } => HelperResponse {
                ok: true,
                category: "network_routes".into(),
                target: "static".into(),
                message: "mock static routes applied".into(),
                data: serde_json::json!({ "routes": routes }),
            },
            HelperOperation::ListUpsStatus => HelperResponse {
                ok: true,
                category: "ups".into(),
                target: "ups@localhost".into(),
                message: "mock UPS status loaded".into(),
                data: serde_json::json!({
                    "name": "ups@localhost",
                    "model": "Mock UPS 1500",
                    "status": "OL",
                    "state": "online",
                    "charge_percent": 96,
                    "runtime_seconds": 1840,
                    "load_percent": 18,
                    "input_voltage": "121.0",
                    "battery_voltage": "27.2"
                }),
            },
            HelperOperation::ExecuteUpsShutdown { command } => HelperResponse {
                ok: true,
                category: "ups".into(),
                target: "shutdown".into(),
                message: "mock UPS shutdown command executed".into(),
                data: serde_json::json!({ "command": command }),
            },
            HelperOperation::ApplyDirectoryServiceSettings {
                enabled,
                provider,
                domain,
                uri,
                base_dn,
                bind_dn,
                tls,
                ca_cert_path,
                nss_enabled,
                pam_enabled,
            } => HelperResponse {
                ok: true,
                category: "directory_service".into(),
                target: if domain.is_empty() { provider } else { domain },
                message: "mock directory service settings applied".into(),
                data: serde_json::json!({
                    "enabled": enabled,
                    "uri": uri,
                    "base_dn": base_dn,
                    "bind_dn": bind_dn,
                    "tls": tls,
                    "ca_cert_path": ca_cert_path,
                    "nss_enabled": nss_enabled,
                    "pam_enabled": pam_enabled
                }),
            },
            HelperOperation::ValidateDirectoryService {
                provider, domain, ..
            } => HelperResponse {
                ok: true,
                category: "directory_service".into(),
                target: if domain.is_empty() { provider } else { domain },
                message: "mock directory service validation passed".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::JoinActiveDirectory {
                domain, username, ..
            } => HelperResponse {
                ok: true,
                category: "directory_service".into(),
                target: domain,
                message: format!("mock Active Directory join requested for {username}"),
                data: serde_json::json!({}),
            },
            HelperOperation::LeaveActiveDirectory {
                domain, username, ..
            } => HelperResponse {
                ok: true,
                category: "directory_service".into(),
                target: domain,
                message: if let Some(username) = username {
                    format!("mock Active Directory leave requested for {username}")
                } else {
                    "mock Active Directory leave requested".into()
                },
                data: serde_json::json!({}),
            },
            HelperOperation::ListSmartDisks => HelperResponse {
                ok: true,
                category: "disk_health".into(),
                target: "all".into(),
                message: "mock disk health loaded".into(),
                data: serde_json::json!([
                    {"name":"/dev/ada0","device_type":"ata","model":"Mock SSD","serial":"MOCK0001","smart_status":"passed","state":"ok"},
                    {"name":"/dev/ada1","device_type":"ata","model":"Mock HDD","serial":"MOCK0002","smart_status":"passed","state":"ok"}
                ]),
            },
            HelperOperation::StartSmartTest { device, test, .. } => HelperResponse {
                ok: true,
                category: "smart_test".into(),
                target: device,
                message: format!("mock {test} SMART test started"),
                data: serde_json::json!({ "test": test }),
            },
            HelperOperation::ListSmartSelfTests { device, .. } => HelperResponse {
                ok: true,
                category: "smart_test".into(),
                target: device,
                message: "mock SMART self-test history loaded".into(),
                data: serde_json::json!([
                    {"number":1,"description":"Short offline","status":"Completed without error","remaining":"00%","lifetime_hours":"1234","lba_of_first_error":"-"}
                ]),
            },
            HelperOperation::PoolScrubStatus { pool } => HelperResponse {
                ok: true,
                category: "pool_scrub".into(),
                target: pool,
                message: "mock scrub status loaded".into(),
                data: serde_json::json!({
                    "state": "idle",
                    "message": "no scrub in progress",
                    "last_scrub": "scrub repaired 0B in 00:12:14 with 0 errors"
                }),
            },
            HelperOperation::PoolScrubAction { pool, action } => HelperResponse {
                ok: true,
                category: "pool_scrub".into(),
                target: pool,
                message: format!("scrub {action:?} requested"),
                data: serde_json::json!({ "state": if action == PoolScrubAction::Start { "running" } else { "idle" } }),
            },
            HelperOperation::ListSnapshots { dataset } => {
                let ds = dataset.unwrap_or_else(|| "tank/media".into());
                HelperResponse {
                    ok: true,
                    category: "snapshot".into(),
                    target: ds.clone(),
                    message: "mock snapshots loaded".into(),
                    data: serde_json::json!([
                        {"name": format!("{ds}@daily-2026-05-18"), "dataset": ds, "created_at": now, "used": "42M"},
                        {"name": format!("{ds}@repl-20260518-000000"), "dataset": ds, "created_at": now - chrono::Duration::days(2), "used": "18M"},
                        {"name": format!("{ds}@repl-20260519-000000"), "dataset": ds, "created_at": now - chrono::Duration::days(1), "used": "12M"}
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
            HelperOperation::CloneSnapshot {
                snapshot,
                target_dataset,
            } => HelperResponse {
                ok: true,
                category: "snapshot_clone".into(),
                target: target_dataset.clone(),
                message: "mock snapshot cloned".into(),
                data: serde_json::json!({ "snapshot": snapshot, "target_dataset": target_dataset }),
            },
            HelperOperation::DiffSnapshots {
                snapshot,
                to_snapshot,
            } => HelperResponse {
                ok: true,
                category: "snapshot_diff".into(),
                target: snapshot.clone(),
                message: "mock snapshot diff loaded".into(),
                data: serde_json::json!([
                    {"change":"M","file_type":"F","path":"/mnt/tank/media/report.txt","timestamp": now, "to_snapshot": to_snapshot}
                ]),
            },
            HelperOperation::CreateDataset { name, .. } => HelperResponse {
                ok: true,
                category: "dataset".into(),
                target: name.clone(),
                message: "mock dataset created".into(),
                data: serde_json::json!({ "name": name }),
            },
            HelperOperation::UpdateDataset { name, .. } => HelperResponse {
                ok: true,
                category: "dataset".into(),
                target: name.clone(),
                message: "mock dataset properties updated".into(),
                data: serde_json::json!({ "name": name }),
            },
            HelperOperation::DeleteDataset { name } => HelperResponse {
                ok: true,
                category: "dataset".into(),
                target: name.clone(),
                message: "mock dataset deleted".into(),
                data: serde_json::json!({ "deleted": name }),
            },
            HelperOperation::SetQuota { dataset, quota } => HelperResponse {
                ok: true,
                category: "quota".into(),
                target: dataset,
                message: format!("quota set to {quota}"),
                data: serde_json::json!({}),
            },
            HelperOperation::ApplySambaServerSettings { workgroup, .. } => HelperResponse {
                ok: true,
                category: "samba_settings".into(),
                target: workgroup,
                message: "samba server settings applied".into(),
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
            HelperOperation::ApplyIscsiTarget { name, .. } => HelperResponse {
                ok: true,
                category: "iscsi".into(),
                target: name,
                message: "mock iSCSI target applied".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::DeleteIscsiTarget { name } => HelperResponse {
                ok: true,
                category: "iscsi".into(),
                target: name,
                message: "mock iSCSI target deleted".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::ListLocalUsers => HelperResponse {
                ok: true,
                category: "local_user".into(),
                target: "all".into(),
                message: "mock local users loaded".into(),
                data: serde_json::json!([
                    {"username":"media","uid":1001,"gid":1001,"full_name":"Media User","home":"/home/media","shell":"/bin/sh"}
                ]),
            },
            HelperOperation::UpsertLocalUser { username, .. } => HelperResponse {
                ok: true,
                category: "local_user".into(),
                target: username,
                message: "mock local user saved".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::DeleteLocalUser { username, .. } => HelperResponse {
                ok: true,
                category: "local_user".into(),
                target: username,
                message: "mock local user deleted".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::ListLocalGroups => HelperResponse {
                ok: true,
                category: "local_group".into(),
                target: "all".into(),
                message: "mock local groups loaded".into(),
                data: serde_json::json!([
                    {"name":"media","gid":1001,"members":["media"]}
                ]),
            },
            HelperOperation::UpsertLocalGroup { name, .. } => HelperResponse {
                ok: true,
                category: "local_group".into(),
                target: name,
                message: "mock local group saved".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::DeleteLocalGroup { name } => HelperResponse {
                ok: true,
                category: "local_group".into(),
                target: name,
                message: "mock local group deleted".into(),
                data: serde_json::json!({}),
            },
            HelperOperation::ServiceStatus { service } => {
                let mut status = BTreeMap::new();
                status.insert("zfs".to_string(), "running".to_string());
                status.insert("samba_server".to_string(), "running".to_string());
                status.insert("nfsd".to_string(), "stopped".to_string());
                status.insert("mountd".to_string(), "stopped".to_string());
                status.insert("rpcbind".to_string(), "stopped".to_string());
                status.insert("ctld".to_string(), "unknown".to_string());
                status.insert("syslogd".to_string(), "running".to_string());
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
            HelperOperation::SearchSnapshotFiles { snapshot, search } => {
                let files = [
                    "Movies/example.mkv",
                    "Photos/2026/image.jpg",
                    "docs/report.txt",
                ]
                .into_iter()
                .filter(|file| {
                    search
                        .as_ref()
                        .map(|query| {
                            file.to_ascii_lowercase()
                                .contains(&query.to_ascii_lowercase())
                        })
                        .unwrap_or(true)
                })
                .map(|path| serde_json::json!({ "path": path, "kind": "file" }))
                .collect::<Vec<_>>();
                HelperResponse {
                    ok: true,
                    category: "snapshot_files".into(),
                    target: snapshot,
                    message: "mock snapshot files loaded".into(),
                    data: serde_json::json!(files),
                }
            }
            HelperOperation::RestoreSnapshotFiles { snapshot, files } => HelperResponse {
                ok: true,
                category: "snapshot_restore".into(),
                target: snapshot,
                message: format!("{} file(s) restored from snapshot", files.len()),
                data: serde_json::json!({ "restored": files }),
            },
            HelperOperation::RunReplication {
                snapshot,
                base_snapshot,
                destination_dataset,
                remote_host,
                ..
            } => HelperResponse {
                ok: true,
                category: "replication".into(),
                target: destination_dataset.clone(),
                message: "mock replication completed".into(),
                data: serde_json::json!({
                    "snapshot": snapshot,
                    "base_snapshot": base_snapshot,
                    "destination_dataset": destination_dataset,
                    "remote": remote_host.is_some()
                }),
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
                "name,used,avail,quota,reservation,mountpoint,compression,atime".into(),
            ],
            HelperOperation::SystemReport => vec![
                "sysctl".into(),
                "-n".into(),
                "kern.hostname".into(),
                "kern.ostype".into(),
                "kern.osrelease".into(),
                "kern.boottime".into(),
                "hw.physmem".into(),
                "hw.model".into(),
                "hw.ncpu".into(),
                "hw.pagesize".into(),
                "vm.stats.vm.v_free_count".into(),
                "vm.swap_total".into(),
                "vm.loadavg".into(),
            ],
            HelperOperation::ListNetworkInterfaces => vec!["ifconfig".into(), "-a".into()],
            HelperOperation::ApplyNetworkInterfaceConfig {
                name,
                mode,
                ipv4_address,
                netmask,
                ..
            } => build_network_sysrc_command(
                name,
                mode,
                ipv4_address.as_deref(),
                netmask.as_deref(),
            )?,
            HelperOperation::ApplyDnsResolverConfig {
                nameservers,
                search_domains,
            } => {
                validate_dns_resolver_config(nameservers, search_domains)?;
                vec!["resolvconf".into(), "-u".into()]
            }
            HelperOperation::ApplyStaticRoutesConfig { routes } => {
                validate_static_routes(routes)?;
                vec!["service".into(), "routing".into(), "restart".into()]
            }
            HelperOperation::ListUpsStatus => vec!["upsc".into(), "ups@localhost".into()],
            HelperOperation::ExecuteUpsShutdown { command } => parse_ups_shutdown_command(command)?,
            HelperOperation::ApplyDirectoryServiceSettings {
                enabled,
                provider,
                domain,
                uri,
                base_dn,
                bind_dn,
                ca_cert_path,
                ..
            } => {
                safe_arg(provider)?;
                if *enabled {
                    for value in [domain, uri, base_dn] {
                        safe_arg(value)?;
                    }
                    if let Some(bind_dn) = bind_dn {
                        safe_arg(bind_dn)?;
                    }
                    if let Some(ca_cert_path) = ca_cert_path {
                        safe_arg(ca_cert_path)?;
                    }
                }
                vec!["service".into(), "nslcd".into(), "restart".into()]
            }
            HelperOperation::ValidateDirectoryService {
                provider,
                domain,
                uri,
                tls,
                ca_cert_path,
            } => {
                safe_arg(provider)?;
                safe_arg(domain)?;
                if let Some(ca_cert_path) = ca_cert_path {
                    safe_arg(ca_cert_path)?;
                }
                match provider.as_str() {
                    "ldap" => build_ldap_validation_command(uri, *tls, ca_cert_path.as_deref())?,
                    "active_directory" => vec!["net".into(), "ads".into(), "testjoin".into()],
                    _ => {
                        return Err(HelperError::Rejected(
                            "directory provider must be ldap or active_directory".into(),
                        ))
                    }
                }
            }
            HelperOperation::JoinActiveDirectory {
                domain, username, ..
            } => {
                safe_arg(domain)?;
                safe_arg(username)?;
                vec![
                    "net".into(),
                    "ads".into(),
                    "join".into(),
                    "-U".into(),
                    username.clone(),
                ]
            }
            HelperOperation::LeaveActiveDirectory {
                domain, username, ..
            } => {
                safe_arg(domain)?;
                let mut cmd = vec!["net".into(), "ads".into(), "leave".into()];
                if let Some(username) = username {
                    safe_arg(username)?;
                    cmd.extend(["-U".into(), username.clone()]);
                }
                cmd
            }
            HelperOperation::ListSmartDisks => vec!["smartctl".into(), "--scan".into()],
            HelperOperation::StartSmartTest {
                device,
                device_type,
                test,
            } => {
                safe_arg(device)?;
                if let Some(device_type) = device_type {
                    safe_arg(device_type)?;
                }
                safe_arg(test)?;
                if !matches!(test.as_str(), "short" | "long" | "conveyance") {
                    return Err(HelperError::Rejected("invalid SMART test type".into()));
                }
                let mut cmd = vec!["smartctl".into(), "-t".into(), test.clone()];
                if let Some(device_type) = device_type {
                    cmd.push("-d".into());
                    cmd.push(device_type.clone());
                }
                cmd.push(device.clone());
                cmd
            }
            HelperOperation::ListSmartSelfTests {
                device,
                device_type,
            } => {
                safe_arg(device)?;
                if let Some(device_type) = device_type {
                    safe_arg(device_type)?;
                }
                let mut cmd = vec!["smartctl".into(), "-l".into(), "selftest".into()];
                if let Some(device_type) = device_type {
                    cmd.push("-d".into());
                    cmd.push(device_type.clone());
                }
                cmd.push(device.clone());
                cmd
            }
            HelperOperation::PoolScrubStatus { pool } => {
                safe_arg(pool)?;
                vec!["zpool".into(), "status".into(), pool.clone()]
            }
            HelperOperation::PoolScrubAction { pool, action } => {
                safe_arg(pool)?;
                match action {
                    PoolScrubAction::Start => vec!["zpool".into(), "scrub".into(), pool.clone()],
                    PoolScrubAction::Stop => {
                        vec!["zpool".into(), "scrub".into(), "-s".into(), pool.clone()]
                    }
                }
            }
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
            HelperOperation::CloneSnapshot {
                snapshot,
                target_dataset,
            } => {
                safe_arg(snapshot)?;
                safe_arg(target_dataset)?;
                vec![
                    "zfs".into(),
                    "clone".into(),
                    snapshot.clone(),
                    target_dataset.clone(),
                ]
            }
            HelperOperation::DiffSnapshots {
                snapshot,
                to_snapshot,
            } => {
                safe_arg(snapshot)?;
                let mut cmd = vec!["zfs".into(), "diff".into(), "-FHt".into(), snapshot.clone()];
                if let Some(to_snapshot) = to_snapshot {
                    safe_arg(to_snapshot)?;
                    cmd.push(to_snapshot.clone());
                }
                cmd
            }
            HelperOperation::CreateDataset {
                name,
                compression,
                atime,
                quota,
                reservation,
                mountpoint,
            } => {
                safe_arg(name)?;
                let mut cmd = vec!["zfs".into(), "create".into()];
                push_dataset_property(&mut cmd, "compression", compression.as_deref())?;
                push_dataset_property(&mut cmd, "atime", atime.as_deref())?;
                push_dataset_property(&mut cmd, "quota", quota.as_deref())?;
                push_dataset_property(&mut cmd, "reservation", reservation.as_deref())?;
                push_dataset_property(&mut cmd, "mountpoint", mountpoint.as_deref())?;
                cmd.push(name.clone());
                cmd
            }
            HelperOperation::UpdateDataset {
                name,
                compression,
                atime,
                quota,
                reservation,
                mountpoint,
            } => {
                safe_arg(name)?;
                let mut cmd = vec!["zfs".into(), "set".into()];
                push_dataset_set_property(&mut cmd, "compression", compression.as_deref())?;
                push_dataset_set_property(&mut cmd, "atime", atime.as_deref())?;
                push_dataset_set_property(&mut cmd, "quota", quota.as_deref())?;
                push_dataset_set_property(&mut cmd, "reservation", reservation.as_deref())?;
                push_dataset_set_property(&mut cmd, "mountpoint", mountpoint.as_deref())?;
                if cmd.len() == 2 {
                    return Err(HelperError::Rejected(
                        "no dataset properties provided".into(),
                    ));
                }
                cmd.push(name.clone());
                cmd
            }
            HelperOperation::DeleteDataset { name } => {
                safe_arg(name)?;
                vec!["zfs".into(), "destroy".into(), name.clone()]
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
            HelperOperation::ApplySambaServerSettings {
                workgroup,
                server_string,
                netbios_name,
                security,
                map_to_guest,
                log_level,
            } => {
                for value in [
                    workgroup,
                    server_string,
                    netbios_name,
                    security,
                    map_to_guest,
                    log_level,
                ] {
                    safe_arg(value)?;
                }
                vec!["service".into(), "samba_server".into(), "reload".into()]
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
            HelperOperation::ApplyIscsiTarget {
                name,
                portal_group,
                initiator_name,
                auth_group,
                extent_name,
                path,
                size,
                ..
            } => {
                for value in [name, portal_group, auth_group, extent_name, path] {
                    safe_arg(value)?;
                }
                if let Some(initiator_name) = initiator_name {
                    safe_arg(initiator_name)?;
                }
                if let Some(size) = size {
                    safe_arg(size)?;
                }
                vec!["service".into(), "ctld".into(), "reload".into()]
            }
            HelperOperation::DeleteIscsiTarget { name } => {
                safe_arg(name)?;
                vec!["service".into(), "ctld".into(), "reload".into()]
            }
            HelperOperation::ListLocalUsers => vec!["pw".into(), "usershow".into(), "-a".into()],
            HelperOperation::UpsertLocalUser {
                username,
                full_name,
                shell,
                home,
                groups,
                password,
                create_home,
            } => {
                safe_arg(username)?;
                safe_arg(shell)?;
                for group in groups {
                    safe_arg(group)?;
                }
                let mut cmd = vec!["pw".into(), "useradd".into(), username.clone()];
                if *create_home {
                    cmd.push("-m".into());
                }
                cmd.extend(["-s".into(), shell.clone()]);
                if let Some(full_name) = full_name {
                    safe_arg(full_name)?;
                    cmd.extend(["-c".into(), full_name.clone()]);
                }
                if let Some(home) = home {
                    safe_arg(home)?;
                    cmd.extend(["-d".into(), home.clone()]);
                }
                if !groups.is_empty() {
                    cmd.extend(["-G".into(), groups.join(",")]);
                }
                if password.is_some() {
                    cmd.extend(["-h".into(), "0".into()]);
                }
                cmd
            }
            HelperOperation::DeleteLocalUser {
                username,
                remove_home,
            } => {
                safe_arg(username)?;
                let mut cmd = vec!["pw".into(), "userdel".into(), username.clone()];
                if *remove_home {
                    cmd.push("-r".into());
                }
                cmd
            }
            HelperOperation::ListLocalGroups => vec!["pw".into(), "groupshow".into(), "-a".into()],
            HelperOperation::UpsertLocalGroup { name, members } => {
                safe_arg(name)?;
                for member in members {
                    safe_arg(member)?;
                }
                let mut cmd = vec!["pw".into(), "groupadd".into(), name.clone()];
                if !members.is_empty() {
                    cmd.extend(["-M".into(), members.join(",")]);
                }
                cmd
            }
            HelperOperation::DeleteLocalGroup { name } => {
                safe_arg(name)?;
                vec!["pw".into(), "groupdel".into(), name.clone()]
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
            HelperOperation::SearchSnapshotFiles { snapshot, search } => {
                safe_arg(snapshot)?;
                if let Some(search) = search {
                    safe_arg(search)?;
                }
                vec!["find".into(), snapshot.clone(), "-type".into(), "f".into()]
            }
            HelperOperation::RestoreSnapshotFiles { snapshot, files } => {
                safe_arg(snapshot)?;
                for file in files {
                    safe_arg(file)?;
                }
                vec!["cp".into(), "-p".into()]
            }
            HelperOperation::RunReplication {
                snapshot,
                base_snapshot,
                destination_dataset,
                remote_host,
                remote_user,
            } => {
                safe_arg(snapshot)?;
                if let Some(base_snapshot) = base_snapshot {
                    safe_arg(base_snapshot)?;
                }
                safe_arg(destination_dataset)?;
                if let Some(host) = remote_host {
                    safe_arg(host)?;
                }
                if let Some(user) = remote_user {
                    safe_arg(user)?;
                }
                let mut args = vec!["zfs".into(), "send".into()];
                if let Some(base_snapshot) = base_snapshot {
                    args.push("-i".into());
                    args.push(base_snapshot.clone());
                }
                args.extend([
                    snapshot.clone(),
                    "|".into(),
                    "zfs".into(),
                    "receive".into(),
                    "-F".into(),
                    destination_dataset.clone(),
                ]);
                args
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

pub fn valid_dataset_compression(value: &str) -> bool {
    matches!(value, "on" | "off" | "lz4" | "zstd" | "gzip")
        || value
            .strip_prefix("gzip-")
            .and_then(|level| level.parse::<u8>().ok())
            .is_some_and(|level| (1..=9).contains(&level))
        || value
            .strip_prefix("zstd-")
            .and_then(|level| level.parse::<u8>().ok())
            .is_some_and(|level| (1..=19).contains(&level))
}

pub fn valid_dataset_on_off(value: &str) -> bool {
    matches!(value, "on" | "off")
}

pub fn valid_dataset_mountpoint(value: &str) -> bool {
    matches!(value, "none" | "legacy")
        || (value.starts_with('/')
            && !value.contains('\0')
            && !value.contains('\n')
            && !value.contains(';')
            && !value.contains('&')
            && !value.contains('|')
            && !value.contains('`')
            && !value.contains("/../")
            && !value.ends_with("/.."))
}

fn valid_dataset_property(name: &str, value: &str) -> bool {
    match name {
        "compression" => valid_dataset_compression(value),
        "atime" => valid_dataset_on_off(value),
        "quota" | "reservation" => valid_quota(value),
        "mountpoint" => valid_dataset_mountpoint(value),
        _ => false,
    }
}

fn push_dataset_property(
    cmd: &mut Vec<String>,
    name: &str,
    value: Option<&str>,
) -> Result<(), HelperError> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(());
    };
    if !valid_dataset_property(name, value) {
        return Err(HelperError::Rejected(format!(
            "invalid dataset {name} value"
        )));
    }
    cmd.push("-o".into());
    cmd.push(format!("{name}={value}"));
    Ok(())
}

fn push_dataset_set_property(
    cmd: &mut Vec<String>,
    name: &str,
    value: Option<&str>,
) -> Result<(), HelperError> {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(());
    };
    if !valid_dataset_property(name, value) {
        return Err(HelperError::Rejected(format!(
            "invalid dataset {name} value"
        )));
    }
    cmd.push(format!("{name}={value}"));
    Ok(())
}

fn parse_ups_shutdown_command(command: &str) -> Result<Vec<String>, HelperError> {
    let parts = command.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "shutdown" {
        return Err(HelperError::Rejected(
            "UPS shutdown command must be shutdown -p now, shutdown -h now, or use +minutes".into(),
        ));
    }
    if !matches!(parts[1], "-p" | "-h") {
        return Err(HelperError::Rejected(
            "UPS shutdown command must use -p or -h".into(),
        ));
    }
    let valid_time = parts[2] == "now"
        || parts[2]
            .strip_prefix('+')
            .and_then(|value| value.parse::<u16>().ok())
            .is_some_and(|minutes| minutes <= 1440);
    if !valid_time {
        return Err(HelperError::Rejected(
            "UPS shutdown time must be now or +minutes up to 1440".into(),
        ));
    }
    Ok(parts.into_iter().map(str::to_string).collect())
}

fn valid_network_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

fn valid_ipv4_address(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok()
}

fn build_network_sysrc_command(
    name: &str,
    mode: &str,
    ipv4_address: Option<&str>,
    netmask: Option<&str>,
) -> Result<Vec<String>, HelperError> {
    if !valid_network_name(name) {
        return Err(HelperError::Rejected(
            "invalid network interface name".into(),
        ));
    }
    let value = match mode {
        "dhcp" => "DHCP".to_string(),
        "static" => {
            let address = ipv4_address
                .filter(|value| valid_ipv4_address(value))
                .ok_or_else(|| HelperError::Rejected("invalid IPv4 address".into()))?;
            let netmask = netmask
                .filter(|value| valid_ipv4_address(value))
                .ok_or_else(|| HelperError::Rejected("invalid IPv4 netmask".into()))?;
            format!("inet {address} netmask {netmask}")
        }
        _ => return Err(HelperError::Rejected("invalid network mode".into())),
    };
    Ok(vec!["sysrc".into(), format!("ifconfig_{name}={value}")])
}

fn valid_dns_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
}

fn validate_dns_resolver_config(
    nameservers: &[String],
    search_domains: &[String],
) -> Result<(), HelperError> {
    if nameservers.is_empty() || nameservers.len() > 3 {
        return Err(HelperError::Rejected(
            "DNS resolver requires 1 to 3 nameservers".into(),
        ));
    }
    for nameserver in nameservers {
        if nameserver.parse::<std::net::IpAddr>().is_err() {
            return Err(HelperError::Rejected("invalid DNS nameserver".into()));
        }
    }
    if search_domains.len() > 6 {
        return Err(HelperError::Rejected(
            "DNS resolver supports up to 6 search domains".into(),
        ));
    }
    for domain in search_domains {
        if !valid_dns_domain(domain) {
            return Err(HelperError::Rejected("invalid DNS search domain".into()));
        }
    }
    Ok(())
}

fn render_resolv_conf(nameservers: &[String], search_domains: &[String]) -> String {
    let mut lines = vec!["# Managed by bnasmgr".to_string()];
    if !search_domains.is_empty() {
        lines.push(format!("search {}", search_domains.join(" ")));
    }
    for nameserver in nameservers {
        lines.push(format!("nameserver {nameserver}"));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn valid_route_destination(value: &str) -> bool {
    if value == "default" {
        return true;
    }
    let Some((addr, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    }
}

fn valid_route_description(value: &str) -> bool {
    value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '_' | '-' | '.'))
}

fn validate_static_routes(routes: &[StaticRouteConfig]) -> Result<(), HelperError> {
    if routes.len() > 32 {
        return Err(HelperError::Rejected(
            "static route limit is 32 entries".into(),
        ));
    }
    for route in routes {
        if !valid_route_destination(&route.destination) {
            return Err(HelperError::Rejected(
                "invalid static route destination".into(),
            ));
        }
        if route.gateway.parse::<std::net::IpAddr>().is_err() {
            return Err(HelperError::Rejected("invalid static route gateway".into()));
        }
        if let Some(description) = route.description.as_deref() {
            if !valid_route_description(description) {
                return Err(HelperError::Rejected(
                    "invalid static route description".into(),
                ));
            }
        }
    }
    Ok(())
}

fn static_route_name(index: usize) -> String {
    format!("bnasmgr_route_{index}")
}

fn static_route_value(route: &StaticRouteConfig) -> String {
    if route.destination == "default" {
        format!("default {}", route.gateway)
    } else {
        format!("-net {} {}", route.destination, route.gateway)
    }
}

struct NslcdRenderSettings<'a> {
    enabled: bool,
    provider: &'a str,
    domain: &'a str,
    uri: &'a str,
    base_dn: &'a str,
    bind_dn: Option<&'a str>,
    tls: bool,
    ca_cert_path: Option<&'a str>,
}

fn render_nslcd_conf(settings: &NslcdRenderSettings<'_>) -> String {
    let mut lines = vec![
        "# Managed by bnasmgr".to_string(),
        format!("# provider {}", settings.provider),
    ];
    if !settings.enabled {
        lines.push("# directory service disabled".into());
        lines.push(String::new());
        return lines.join("\n");
    }
    lines.extend([
        format!("# domain {}", settings.domain),
        format!("uri {}", settings.uri),
        format!("base {}", settings.base_dn),
    ]);
    if let Some(bind_dn) = settings.bind_dn.filter(|value| !value.is_empty()) {
        lines.push(format!("binddn {bind_dn}"));
    }
    if settings.uri.starts_with("ldaps://") {
        lines.push("ssl on".into());
    } else {
        lines.push("ssl off".into());
        if settings.tls {
            lines.push("tls_start_tls yes".into());
        }
    }
    lines.push(if settings.tls {
        "tls_reqcert demand".into()
    } else {
        "tls_reqcert allow".into()
    });
    if let Some(ca_cert_path) = settings.ca_cert_path.filter(|value| !value.is_empty()) {
        lines.push(format!("tls_cacertfile {ca_cert_path}"));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn build_ldap_validation_command(
    uri: &str,
    tls: bool,
    ca_cert_path: Option<&str>,
) -> Result<Vec<String>, HelperError> {
    let (scheme, host, port) = parse_ldap_endpoint(uri)?;
    if scheme == "ldaps" || tls {
        let mut command = vec![
            "openssl".into(),
            "s_client".into(),
            "-connect".into(),
            format!("{host}:{port}"),
            "-servername".into(),
            host,
            "-verify_return_error".into(),
            "-brief".into(),
        ];
        if let Some(ca_cert_path) = ca_cert_path.filter(|value| !value.is_empty()) {
            command.extend(["-CAfile".into(), ca_cert_path.into()]);
        }
        if scheme == "ldap" {
            command.splice(2..2, ["-starttls".into(), "ldap".into()]);
        }
        Ok(command)
    } else {
        Ok(vec!["service".into(), "nslcd".into(), "status".into()])
    }
}

fn parse_ldap_endpoint(uri: &str) -> Result<(&'static str, String, u16), HelperError> {
    let (scheme, rest, default_port) = if let Some(rest) = uri.strip_prefix("ldaps://") {
        ("ldaps", rest, 636)
    } else if let Some(rest) = uri.strip_prefix("ldap://") {
        ("ldap", rest, 389)
    } else {
        return Err(HelperError::Rejected(
            "directory URI must start with ldap:// or ldaps://".into(),
        ));
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('[') {
        return Err(HelperError::Rejected("invalid LDAP URI host".into()));
    }
    let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| HelperError::Rejected("invalid LDAP URI port".into()))?;
        (host, port)
    } else {
        (authority, default_port)
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
    {
        return Err(HelperError::Rejected("invalid LDAP URI host".into()));
    }
    Ok((scheme, host.to_string(), port))
}

fn render_nsswitch_conf(enabled: bool) -> String {
    let identity_sources = if enabled { "files ldap" } else { "files" };
    [
        "# Managed by bnasmgr",
        &format!("group: {identity_sources}"),
        "group_compat: nis",
        "hosts: files dns",
        "networks: files",
        &format!("passwd: {identity_sources}"),
        "passwd_compat: nis",
        "shells: files",
        "services: compat",
        "services_compat: nis",
        "protocols: files",
        "rpc: files",
        "",
    ]
    .join("\n")
}

fn render_pam_system_conf(enabled: bool) -> String {
    let mut lines = vec![
        "# Managed by bnasmgr".to_string(),
        "auth sufficient pam_opie.so no_warn no_fake_prompts".into(),
        "auth requisite pam_opieaccess.so no_warn allow_local".into(),
        "auth sufficient pam_unix.so no_warn try_first_pass nullok".into(),
    ];
    if enabled {
        lines.push("auth sufficient /usr/local/lib/pam_ldap.so no_warn try_first_pass".into());
    }
    lines.extend([
        "auth required pam_deny.so".into(),
        "account required pam_login_access.so".into(),
        "account required pam_unix.so".into(),
    ]);
    if enabled {
        lines.push("account sufficient /usr/local/lib/pam_ldap.so".into());
    }
    lines.extend([
        "session required pam_lastlog.so no_fail".into(),
        "password required pam_unix.so no_warn try_first_pass".into(),
        String::new(),
    ]);
    lines.join("\n")
}

#[derive(Debug, Default)]
pub struct FreeBsdHelper;

#[async_trait]
impl HelperClient for FreeBsdHelper {
    async fn execute(&self, request: HelperRequest) -> Result<HelperResponse, HelperError> {
        let operation = request.operation;
        match &operation {
            HelperOperation::ListStorage => return freebsd_storage_overview().await,
            HelperOperation::SystemReport => return freebsd_system_report().await,
            HelperOperation::ListNetworkInterfaces => return freebsd_network_interfaces().await,
            HelperOperation::ApplyNetworkInterfaceConfig { .. } => {
                return freebsd_apply_network_interface_config(&operation).await
            }
            HelperOperation::ApplyDnsResolverConfig { .. } => {
                return freebsd_apply_dns_resolver_config(&operation).await
            }
            HelperOperation::ApplyStaticRoutesConfig { .. } => {
                return freebsd_apply_static_routes_config(&operation).await
            }
            HelperOperation::ListUpsStatus => return freebsd_ups_status().await,
            HelperOperation::ExecuteUpsShutdown { .. } => {
                return freebsd_execute_ups_shutdown(&operation).await
            }
            HelperOperation::ApplyDirectoryServiceSettings { .. } => {
                return freebsd_directory_service_settings(&operation).await
            }
            HelperOperation::ValidateDirectoryService { .. } => {
                return freebsd_validate_directory_service(&operation).await
            }
            HelperOperation::JoinActiveDirectory { .. } => {
                return freebsd_join_active_directory(&operation).await
            }
            HelperOperation::LeaveActiveDirectory { .. } => {
                return freebsd_leave_active_directory(&operation).await
            }
            HelperOperation::ListSmartDisks => return freebsd_smart_disks().await,
            HelperOperation::ListSmartSelfTests { .. } => {
                return freebsd_smart_self_tests(&operation).await
            }
            HelperOperation::PoolScrubStatus { .. } => {
                return freebsd_pool_scrub_status(&operation).await
            }
            HelperOperation::ListSnapshots { .. } => return freebsd_snapshots(&operation).await,
            HelperOperation::DiffSnapshots { .. } => {
                return freebsd_snapshot_diff(&operation).await
            }
            HelperOperation::ServiceStatus { .. } => {
                return freebsd_service_status(&operation).await
            }
            HelperOperation::ReadLogs { .. } => return freebsd_logs(&operation).await,
            HelperOperation::ApplySambaShare { .. }
            | HelperOperation::DeleteSambaShare { .. }
            | HelperOperation::ApplySambaServerSettings { .. }
            | HelperOperation::ApplyNfsExport { .. }
            | HelperOperation::DeleteNfsExport { .. }
            | HelperOperation::ApplyIscsiTarget { .. }
            | HelperOperation::DeleteIscsiTarget { .. } => {
                return freebsd_apply_share_fragment(&operation).await
            }
            HelperOperation::UpsertSambaUser { .. } => {
                return freebsd_upsert_samba_user(&operation).await
            }
            HelperOperation::SearchSnapshotFiles { .. } => {
                return freebsd_search_snapshot_files(&operation).await
            }
            HelperOperation::RestoreSnapshotFiles { .. } => {
                return freebsd_restore_snapshot_files(&operation).await
            }
            HelperOperation::RunReplication { .. } => {
                return freebsd_run_replication(&operation).await
            }
            HelperOperation::ListLocalUsers => return freebsd_local_users().await,
            HelperOperation::ListLocalGroups => return freebsd_local_groups().await,
            HelperOperation::UpsertLocalUser { .. } => {
                return freebsd_upsert_local_user(&operation).await
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

async fn freebsd_system_report() -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(
        &HelperOperation::SystemReport,
    )?)
    .await?;
    Ok(HelperResponse {
        ok: output.ok,
        category: "system_report".into(),
        target: "localhost".into(),
        message: if output.ok {
            "system report loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            parse_system_report(&output.stdout)
        } else {
            serde_json::json!({})
        },
    })
}

async fn freebsd_network_interfaces() -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(
        &HelperOperation::ListNetworkInterfaces,
    )?)
    .await?;
    Ok(HelperResponse {
        ok: output.ok,
        category: "network".into(),
        target: "interfaces".into(),
        message: if output.ok {
            "network interfaces loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            serde_json::json!(parse_ifconfig_interfaces(&output.stdout))
        } else {
            serde_json::json!([])
        },
    })
}

async fn freebsd_apply_network_interface_config(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::ApplyNetworkInterfaceConfig {
        name,
        mode,
        ipv4_address,
        netmask,
        gateway,
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected network interface config operation".into(),
        ));
    };
    let sysrc = run_command(FreeBsdCommandBuilder::build(operation)?).await?;
    if !sysrc.ok {
        return Ok(HelperResponse {
            ok: false,
            category: "network_config".into(),
            target: name.clone(),
            message: sysrc.stderr,
            data: serde_json::json!({ "status": sysrc.status }),
        });
    }
    if let Some(gateway) = gateway.as_deref().filter(|value| !value.is_empty()) {
        if !valid_ipv4_address(gateway) {
            return Err(HelperError::Rejected("invalid IPv4 gateway".into()));
        }
        let output = run_command(vec!["sysrc".into(), format!("defaultrouter={gateway}")]).await?;
        if !output.ok {
            return Ok(HelperResponse {
                ok: false,
                category: "network_config".into(),
                target: name.clone(),
                message: output.stderr,
                data: serde_json::json!({ "status": output.status }),
            });
        }
    }
    let restart = run_command(vec![
        "service".into(),
        "netif".into(),
        "restart".into(),
        name.clone(),
    ])
    .await?;
    if restart.ok && gateway.as_deref().is_some_and(|value| !value.is_empty()) {
        let _ = run_command(vec!["service".into(), "routing".into(), "restart".into()]).await?;
    }
    Ok(HelperResponse {
        ok: restart.ok,
        category: "network_config".into(),
        target: name.clone(),
        message: if restart.ok {
            format!("network interface set to {mode}")
        } else {
            restart.stderr
        },
        data: serde_json::json!({
            "status": restart.status,
            "ipv4_address": ipv4_address,
            "netmask": netmask,
            "gateway": gateway,
        }),
    })
}

async fn freebsd_apply_dns_resolver_config(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::ApplyDnsResolverConfig {
        nameservers,
        search_domains,
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected DNS resolver config operation".into(),
        ));
    };
    validate_dns_resolver_config(nameservers, search_domains)?;
    let path = std::env::var("BNASMGR_RESOLV_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/resolv.conf"));
    atomic_write(&path, &render_resolv_conf(nameservers, search_domains)).await?;
    Ok(HelperResponse {
        ok: true,
        category: "network_dns".into(),
        target: "resolver".into(),
        message: "DNS resolver settings applied".into(),
        data: serde_json::json!({
            "path": path,
            "nameservers": nameservers,
            "search_domains": search_domains,
        }),
    })
}

async fn freebsd_apply_static_routes_config(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::ApplyStaticRoutesConfig { routes } = operation else {
        return Err(HelperError::Rejected(
            "expected static routes config operation".into(),
        ));
    };
    validate_static_routes(routes)?;
    let names = (0..routes.len()).map(static_route_name).collect::<Vec<_>>();
    let output = run_command(vec![
        "sysrc".into(),
        format!("static_routes={}", names.join(" ")),
    ])
    .await?;
    if !output.ok {
        return Ok(HelperResponse {
            ok: false,
            category: "network_routes".into(),
            target: "static".into(),
            message: output.stderr,
            data: serde_json::json!({ "status": output.status }),
        });
    }
    for (index, route) in routes.iter().enumerate() {
        let route_name = static_route_name(index);
        let output = run_command(vec![
            "sysrc".into(),
            format!("route_{route_name}={}", static_route_value(route)),
        ])
        .await?;
        if !output.ok {
            return Ok(HelperResponse {
                ok: false,
                category: "network_routes".into(),
                target: "static".into(),
                message: output.stderr,
                data: serde_json::json!({ "status": output.status }),
            });
        }
    }
    let restart = run_command(vec!["service".into(), "routing".into(), "restart".into()]).await?;
    Ok(HelperResponse {
        ok: restart.ok,
        category: "network_routes".into(),
        target: "static".into(),
        message: if restart.ok {
            "static routes applied".into()
        } else {
            restart.stderr
        },
        data: serde_json::json!({ "routes": routes, "status": restart.status }),
    })
}

async fn freebsd_ups_status() -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(
        &HelperOperation::ListUpsStatus,
    )?)
    .await?;
    Ok(HelperResponse {
        ok: output.ok,
        category: "ups".into(),
        target: "ups@localhost".into(),
        message: if output.ok {
            "UPS status loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            parse_upsc_status(&output.stdout)
        } else {
            serde_json::json!({})
        },
    })
}

async fn freebsd_execute_ups_shutdown(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(operation)?).await?;
    Ok(HelperResponse {
        ok: output.ok,
        category: "ups".into(),
        target: "shutdown".into(),
        message: if output.ok {
            "UPS shutdown command executed".into()
        } else {
            output.stderr
        },
        data: serde_json::json!({ "status": output.status }),
    })
}

async fn freebsd_directory_service_settings(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::ApplyDirectoryServiceSettings {
        enabled,
        provider,
        domain,
        uri,
        base_dn,
        bind_dn,
        tls,
        ca_cert_path,
        nss_enabled,
        pam_enabled,
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected directory service settings operation".into(),
        ));
    };
    FreeBsdCommandBuilder::build(operation)?;
    let config_path = std::env::var("BNASMGR_NSLCD_CONF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/usr/local/etc/nslcd.conf"));
    atomic_write(
        &config_path,
        &render_nslcd_conf(&NslcdRenderSettings {
            enabled: *enabled,
            provider,
            domain,
            uri,
            base_dn,
            bind_dn: bind_dn.as_deref(),
            tls: *tls,
            ca_cert_path: ca_cert_path.as_deref(),
        }),
    )
    .await?;
    let nsswitch_path = if *nss_enabled {
        let path = std::env::var("BNASMGR_NSSWITCH_CONF")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/nsswitch.conf"));
        atomic_write(&path, &render_nsswitch_conf(*enabled)).await?;
        Some(path)
    } else {
        None
    };
    let pam_system_path = if *pam_enabled {
        let path = std::env::var("BNASMGR_PAM_SYSTEM_CONF")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/pam.d/system"));
        atomic_write(&path, &render_pam_system_conf(*enabled)).await?;
        Some(path)
    } else {
        None
    };
    let output = run_command(FreeBsdCommandBuilder::build(operation)?).await?;
    let (category, target) = operation_category_target(operation);
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "directory service settings applied".into()
        } else {
            output.stderr
        },
        data: serde_json::json!({
            "status": output.status,
            "config_path": config_path,
            "nsswitch_path": nsswitch_path,
            "pam_system_path": pam_system_path,
        }),
    })
}

async fn freebsd_validate_directory_service(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(operation)?).await?;
    let (category, target) = operation_category_target(operation);
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "directory service validation passed".into()
        } else {
            output.stderr
        },
        data: serde_json::json!({ "status": output.status }),
    })
}

async fn freebsd_join_active_directory(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::JoinActiveDirectory {
        domain,
        username,
        password,
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected Active Directory join operation".into(),
        ));
    };
    let mut stdin = password.clone();
    stdin.push('\n');
    let output =
        run_command_with_stdin(FreeBsdCommandBuilder::build(operation)?, stdin.as_bytes()).await?;
    Ok(HelperResponse {
        ok: output.ok,
        category: "directory_service".into(),
        target: domain.clone(),
        message: if output.ok {
            format!("Active Directory join requested for {username}")
        } else {
            output.stderr
        },
        data: serde_json::json!({ "status": output.status }),
    })
}

async fn freebsd_leave_active_directory(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::LeaveActiveDirectory {
        domain,
        username,
        password,
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected Active Directory leave operation".into(),
        ));
    };
    let output = if let Some(password) = password {
        let mut stdin = password.clone();
        stdin.push('\n');
        run_command_with_stdin(FreeBsdCommandBuilder::build(operation)?, stdin.as_bytes()).await?
    } else {
        run_command(FreeBsdCommandBuilder::build(operation)?).await?
    };
    Ok(HelperResponse {
        ok: output.ok,
        category: "directory_service".into(),
        target: domain.clone(),
        message: if output.ok {
            if let Some(username) = username {
                format!("Active Directory leave requested for {username}")
            } else {
                "Active Directory leave requested".into()
            }
        } else {
            output.stderr
        },
        data: serde_json::json!({ "status": output.status }),
    })
}

async fn freebsd_smart_disks() -> Result<HelperResponse, HelperError> {
    let scan = run_command(FreeBsdCommandBuilder::build(
        &HelperOperation::ListSmartDisks,
    )?)
    .await?;
    if !scan.ok {
        return Ok(HelperResponse {
            ok: false,
            category: "disk_health".into(),
            target: "all".into(),
            message: scan.stderr,
            data: serde_json::json!([]),
        });
    }
    let mut disks = Vec::new();
    for device in parse_smartctl_scan(&scan.stdout).into_iter().take(32) {
        let mut cmd = vec!["smartctl".into(), "-H".into(), "-i".into()];
        if let Some(device_type) = &device.device_type {
            cmd.push("-d".into());
            cmd.push(device_type.clone());
        }
        cmd.push(device.name.clone());
        let output = run_command(cmd).await?;
        disks.push(parse_smartctl_health(
            &device.name,
            device.device_type.as_deref(),
            &output.stdout,
            &output.stderr,
            output.ok,
        ));
    }
    Ok(HelperResponse {
        ok: true,
        category: "disk_health".into(),
        target: "all".into(),
        message: "disk health loaded".into(),
        data: serde_json::json!(disks),
    })
}

async fn freebsd_smart_self_tests(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let cmd = FreeBsdCommandBuilder::build(operation)?;
    let output = run_command(cmd).await?;
    let (category, target) = operation_category_target(operation);
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "SMART self-test history loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            serde_json::json!(parse_smartctl_selftests(&output.stdout))
        } else {
            serde_json::json!([])
        },
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

async fn freebsd_snapshot_diff(operation: &HelperOperation) -> Result<HelperResponse, HelperError> {
    let cmd = FreeBsdCommandBuilder::build(operation)?;
    let output = run_command(cmd).await?;
    let (category, target) = operation_category_target(operation);
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "snapshot diff loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            serde_json::json!(parse_zfs_diff(&output.stdout))
        } else {
            serde_json::json!([])
        },
    })
}

async fn freebsd_pool_scrub_status(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(operation)?).await?;
    let (category, target) = operation_category_target(operation);
    Ok(HelperResponse {
        ok: output.ok,
        category,
        target,
        message: if output.ok {
            "pool scrub status loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            parse_zpool_scrub_status(&output.stdout)
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
        HelperOperation::ApplySambaServerSettings {
            workgroup,
            server_string,
            netbios_name,
            security,
            map_to_guest,
            log_level,
        } => {
            let dir = config_dir(
                "BNASMGR_SAMBA_INCLUDE_DIR",
                "/usr/local/etc/bnasmgr/smb4.includes",
            );
            let file = dir.join("00-global.conf");
            atomic_write(
                &file,
                &render_samba_server_settings(
                    workgroup,
                    server_string,
                    netbios_name,
                    security,
                    map_to_guest,
                    log_level,
                ),
            )
            .await?;
        }
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
        HelperOperation::ApplyIscsiTarget {
            name,
            portal_group,
            initiator_name,
            auth_group,
            extent_name,
            path,
            size,
            lun_id,
            readonly,
        } => {
            let dir = config_dir(
                "BNASMGR_ISCSI_INCLUDE_DIR",
                "/usr/local/etc/bnasmgr/ctl.conf.d",
            );
            let file = dir.join(format!("{}.conf", safe_file_stem(name)?));
            atomic_write(
                &file,
                &render_iscsi_target(&IscsiTargetRender {
                    name,
                    portal_group,
                    initiator_name: initiator_name.as_deref(),
                    auth_group,
                    extent_name,
                    path,
                    size: size.as_deref(),
                    lun_id: *lun_id,
                    readonly: *readonly,
                }),
            )
            .await?;
        }
        HelperOperation::DeleteIscsiTarget { name } => {
            let dir = config_dir(
                "BNASMGR_ISCSI_INCLUDE_DIR",
                "/usr/local/etc/bnasmgr/ctl.conf.d",
            );
            remove_if_exists(dir.join(format!("{}.conf", safe_file_stem(name)?))).await?;
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

async fn freebsd_search_snapshot_files(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::SearchSnapshotFiles { snapshot, search } = operation else {
        return Err(HelperError::Rejected(
            "expected snapshot file search".into(),
        ));
    };
    validate_snapshot_name(snapshot)?;
    if let Some(search) = search {
        validate_search_text(search)?;
    }
    let root = snapshot_root(snapshot).await?;
    let output = run_command(vec![
        "find".into(),
        root.to_string_lossy().to_string(),
        "-type".into(),
        "f".into(),
    ])
    .await?;
    let query = search.as_ref().map(|value| value.to_ascii_lowercase());
    let files = if output.ok {
        output
            .stdout
            .lines()
            .filter_map(|line| relative_snapshot_file(&root, line).ok())
            .filter(|path| {
                query
                    .as_ref()
                    .map(|query| path.to_ascii_lowercase().contains(query))
                    .unwrap_or(true)
            })
            .map(|path| serde_json::json!({ "path": path, "kind": "file" }))
            .take(500)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    Ok(HelperResponse {
        ok: output.ok,
        category: "snapshot_files".into(),
        target: snapshot.clone(),
        message: if output.ok {
            "snapshot files loaded".into()
        } else {
            output.stderr
        },
        data: serde_json::json!(files),
    })
}

async fn freebsd_restore_snapshot_files(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::RestoreSnapshotFiles { snapshot, files } = operation else {
        return Err(HelperError::Rejected(
            "expected snapshot file restore".into(),
        ));
    };
    validate_snapshot_name(snapshot)?;
    if files.is_empty() {
        return Err(HelperError::Rejected("no files selected".into()));
    }
    if files.len() > 100 {
        return Err(HelperError::Rejected(
            "cannot restore more than 100 files at once".into(),
        ));
    }
    for file in files {
        validate_relative_file(file)?;
    }
    let dataset = snapshot_dataset(snapshot)?;
    let live_root = dataset_mountpoint(&dataset).await?;
    let snap_root = snapshot_root(snapshot).await?;
    let mut restored = Vec::new();
    for file in files {
        let source = snap_root.join(file);
        let destination = live_root.join(file);
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|err| HelperError::Other(err.into()))?;
        }
        let output = run_command(vec![
            "cp".into(),
            "-p".into(),
            source.to_string_lossy().to_string(),
            destination.to_string_lossy().to_string(),
        ])
        .await?;
        if !output.ok {
            return Ok(HelperResponse {
                ok: false,
                category: "snapshot_restore".into(),
                target: snapshot.clone(),
                message: output.stderr,
                data: serde_json::json!({ "restored": restored }),
            });
        }
        restored.push(file.clone());
    }
    Ok(HelperResponse {
        ok: true,
        category: "snapshot_restore".into(),
        target: snapshot.clone(),
        message: format!("{} file(s) restored from snapshot", restored.len()),
        data: serde_json::json!({ "restored": restored }),
    })
}

async fn freebsd_run_replication(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::RunReplication {
        snapshot,
        base_snapshot,
        destination_dataset,
        remote_host,
        remote_user,
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected replication operation".into(),
        ));
    };
    validate_snapshot_name(snapshot)?;
    if let Some(base_snapshot) = base_snapshot {
        validate_snapshot_name(base_snapshot)?;
    }
    FreeBsdCommandBuilder::build(operation)?;

    let mut send_command = Command::new("zfs");
    send_command.arg("send");
    if let Some(base_snapshot) = base_snapshot {
        send_command.arg("-i").arg(base_snapshot);
    }
    let mut send = send_command
        .arg(snapshot)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| HelperError::Other(err.into()))?;
    let mut send_stdout = send
        .stdout
        .take()
        .ok_or_else(|| HelperError::Rejected("zfs send stdout unavailable".into()))?;

    let mut receive = if let Some(host) = remote_host {
        let target = format!(
            "{}{}",
            remote_user
                .as_ref()
                .map(|user| format!("{user}@"))
                .unwrap_or_default(),
            host
        );
        let mut cmd = Command::new("ssh");
        cmd.arg(target)
            .arg("zfs")
            .arg("receive")
            .arg("-F")
            .arg(destination_dataset);
        cmd
    } else {
        let mut cmd = Command::new("zfs");
        cmd.arg("receive").arg("-F").arg(destination_dataset);
        cmd
    };
    let mut receive = receive
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| HelperError::Other(err.into()))?;
    let mut receive_stdin = receive
        .stdin
        .take()
        .ok_or_else(|| HelperError::Rejected("zfs receive stdin unavailable".into()))?;
    let mut buffer = Vec::new();
    send_stdout
        .read_to_end(&mut buffer)
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    receive_stdin
        .write_all(&buffer)
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    drop(receive_stdin);
    let receive_output = receive
        .wait_with_output()
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    let send_status = send
        .wait()
        .await
        .map_err(|err| HelperError::Other(err.into()))?;
    let ok = send_status.success() && receive_output.status.success();
    let stderr = String::from_utf8_lossy(&receive_output.stderr).to_string();
    Ok(HelperResponse {
        ok,
        category: "replication".into(),
        target: destination_dataset.clone(),
        message: if ok {
            "replication completed".into()
        } else {
            stderr.clone()
        },
        data: serde_json::json!({
            "snapshot": snapshot,
            "base_snapshot": base_snapshot,
            "destination_dataset": destination_dataset,
            "remote": remote_host.is_some(),
            "send_status": send_status.code(),
            "receive_status": receive_output.status.code(),
            "stderr": stderr,
        }),
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

fn validate_snapshot_name(snapshot: &str) -> Result<(), HelperError> {
    if snapshot.is_empty()
        || snapshot.contains('\0')
        || snapshot.contains('\n')
        || snapshot.contains("..")
        || !snapshot.contains('@')
    {
        return Err(HelperError::Rejected("invalid snapshot name".into()));
    }
    let (_, label) = snapshot
        .split_once('@')
        .ok_or_else(|| HelperError::Rejected("invalid snapshot name".into()))?;
    if label.is_empty() || label.contains('/') {
        return Err(HelperError::Rejected("invalid snapshot name".into()));
    }
    Ok(())
}

fn snapshot_dataset(snapshot: &str) -> Result<String, HelperError> {
    validate_snapshot_name(snapshot)?;
    snapshot
        .split_once('@')
        .map(|(dataset, _)| dataset.to_string())
        .ok_or_else(|| HelperError::Rejected("invalid snapshot name".into()))
}

fn snapshot_label(snapshot: &str) -> Result<String, HelperError> {
    validate_snapshot_name(snapshot)?;
    snapshot
        .split_once('@')
        .map(|(_, label)| label.to_string())
        .ok_or_else(|| HelperError::Rejected("invalid snapshot name".into()))
}

async fn dataset_mountpoint(dataset: &str) -> Result<PathBuf, HelperError> {
    let output = run_command(vec![
        "zfs".into(),
        "get".into(),
        "-Hp".into(),
        "-o".into(),
        "value".into(),
        "mountpoint".into(),
        dataset.into(),
    ])
    .await?;
    if !output.ok {
        return Err(HelperError::Rejected(output.stderr));
    }
    let mountpoint = output.stdout.lines().next().unwrap_or("").trim();
    if mountpoint.is_empty() || matches!(mountpoint, "-" | "none" | "legacy") {
        return Err(HelperError::Rejected(
            "snapshot dataset has no mounted filesystem".into(),
        ));
    }
    Ok(PathBuf::from(mountpoint))
}

async fn snapshot_root(snapshot: &str) -> Result<PathBuf, HelperError> {
    let dataset = snapshot_dataset(snapshot)?;
    let label = snapshot_label(snapshot)?;
    Ok(dataset_mountpoint(&dataset)
        .await?
        .join(".zfs")
        .join("snapshot")
        .join(label))
}

fn validate_search_text(value: &str) -> Result<(), HelperError> {
    if value.contains('\0') || value.contains('\n') || value.contains(';') || value.contains('|') {
        return Err(HelperError::Rejected("unsafe search text".into()));
    }
    Ok(())
}

fn validate_relative_file(value: &str) -> Result<(), HelperError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\0')
        || value.contains('\n')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(HelperError::Rejected("invalid snapshot file path".into()));
    }
    Ok(())
}

fn relative_snapshot_file(root: &Path, value: &str) -> Result<String, HelperError> {
    let relative = Path::new(value)
        .strip_prefix(root)
        .map_err(|_| HelperError::Rejected("snapshot file outside root".into()))?;
    let text = relative
        .to_string_lossy()
        .trim_start_matches('/')
        .to_string();
    validate_relative_file(&text)?;
    Ok(text)
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

fn render_samba_server_settings(
    workgroup: &str,
    server_string: &str,
    netbios_name: &str,
    security: &str,
    map_to_guest: &str,
    log_level: &str,
) -> String {
    [
        "[global]".to_string(),
        format!("    workgroup = {workgroup}"),
        format!("    server string = {server_string}"),
        format!("    netbios name = {netbios_name}"),
        format!("    security = {security}"),
        format!("    map to guest = {map_to_guest}"),
        format!("    log level = {log_level}"),
        String::new(),
    ]
    .join("\n")
}

fn render_nfs_export(path: &str, clients: &str, options: &str) -> String {
    format!("{path} {options} {clients}\n")
}

struct IscsiTargetRender<'a> {
    name: &'a str,
    portal_group: &'a str,
    initiator_name: Option<&'a str>,
    auth_group: &'a str,
    extent_name: &'a str,
    path: &'a str,
    size: Option<&'a str>,
    lun_id: u32,
    readonly: bool,
}

fn render_iscsi_target(target: &IscsiTargetRender<'_>) -> String {
    let mut lines = vec![
        format!("portal-group {} {{", target.portal_group),
        "    discovery-auth-group no-authentication".into(),
        "    listen 0.0.0.0".into(),
        "}".into(),
        String::new(),
        format!("extent {} {{", target.extent_name),
        format!("    path {}", target.path),
    ];
    if let Some(size) = target.size.filter(|value| !value.is_empty()) {
        lines.push(format!("    size {size}"));
    }
    if target.readonly {
        lines.push("    option readonly on".into());
    }
    lines.extend([
        "}".into(),
        String::new(),
        format!("target {} {{", target.name),
        format!("    auth-group {}", target.auth_group),
        format!("    portal-group {}", target.portal_group),
    ]);
    if let Some(initiator_name) = target.initiator_name.filter(|value| !value.is_empty()) {
        lines.push(format!("    initiator-name {initiator_name}"));
    }
    lines.extend([
        format!("    lun {} {{", target.lun_id),
        format!("        extent {}", target.extent_name),
        "    }".into(),
        "}".into(),
        String::new(),
    ]);
    lines.join("\n")
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

fn parse_zpool_scrub_status(stdout: &str) -> serde_json::Value {
    let scan = stdout
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("scan:"))
        .unwrap_or("scan: none requested")
        .trim_start_matches("scan:")
        .trim();
    let state = if scan.contains("scrub in progress") || scan.contains("resilver in progress") {
        "running"
    } else if scan.contains("scrub canceled") {
        "canceled"
    } else if scan.contains("repaired") || scan.contains("scrub repaired") {
        "finished"
    } else {
        "idle"
    };
    serde_json::json!({
        "state": state,
        "message": scan,
        "last_scrub": scan,
    })
}

fn parse_system_report(stdout: &str) -> serde_json::Value {
    let mut lines = stdout.lines();
    let hostname = lines.next().unwrap_or("unknown").trim();
    let os = lines.next().unwrap_or("unknown").trim();
    let release = lines.next().unwrap_or("unknown").trim();
    let boottime = lines.next().unwrap_or("").trim();
    let memory = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    let cpu_model = lines.next().unwrap_or("unknown").trim();
    let cpu_cores = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<u32>()
        .unwrap_or(0);
    let page_size = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    let free_pages = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    let swap_total = lines
        .next()
        .unwrap_or("0")
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    let load = lines.next().unwrap_or("").trim();
    let boot_seconds = boottime
        .split("sec =")
        .nth(1)
        .and_then(|value| value.split([',', '}']).next())
        .and_then(|value| value.trim().parse::<i64>().ok());
    let uptime_seconds = boot_seconds
        .and_then(|boot| Utc::now().timestamp().checked_sub(boot))
        .filter(|value| *value >= 0)
        .map(|value| value as u64);
    let load_average = load
        .trim_matches(|ch| ch == '{' || ch == '}')
        .split_whitespace()
        .filter_map(|value| value.parse::<f64>().ok())
        .take(3)
        .collect::<Vec<_>>();
    serde_json::json!({
        "hostname": if hostname.is_empty() { "unknown" } else { hostname },
        "os": if os.is_empty() { "unknown" } else { os },
        "release": if release.is_empty() { "unknown" } else { release },
        "uptime_seconds": uptime_seconds,
        "cpu_model": if cpu_model.is_empty() { "unknown" } else { cpu_model },
        "cpu_cores": cpu_cores,
        "memory_bytes": memory,
        "memory_free_bytes": page_size.saturating_mul(free_pages),
        "swap_total_bytes": swap_total,
        "load_average": load_average,
    })
}

fn parse_ifconfig_interfaces(stdout: &str) -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    let mut current: Option<BTreeMap<String, serde_json::Value>> = None;
    for line in stdout.lines() {
        if !line.starts_with(char::is_whitespace) && line.contains(':') {
            if let Some(row) = current.take() {
                rows.push(serde_json::json!(row));
            }
            let name = line.split(':').next().unwrap_or("unknown").trim();
            let mut row = BTreeMap::new();
            row.insert("name".into(), serde_json::json!(name));
            row.insert("status".into(), serde_json::json!("unknown"));
            row.insert("mac".into(), serde_json::Value::Null);
            row.insert("ipv4".into(), serde_json::json!([]));
            row.insert("ipv6".into(), serde_json::json!([]));
            if let Some(mtu) = line
                .split_whitespace()
                .collect::<Vec<_>>()
                .windows(2)
                .find_map(|pair| {
                    (pair[0] == "mtu")
                        .then(|| pair[1].parse::<u32>().ok())
                        .flatten()
                })
            {
                row.insert("mtu".into(), serde_json::json!(mtu));
            } else {
                row.insert("mtu".into(), serde_json::Value::Null);
            }
            current = Some(row);
            continue;
        }

        let Some(row) = current.as_mut() else {
            continue;
        };
        let line = line.trim();
        if let Some(value) = line.strip_prefix("status:") {
            row.insert("status".into(), serde_json::json!(value.trim()));
        } else if let Some(value) = line.strip_prefix("ether ") {
            row.insert("mac".into(), serde_json::json!(value.trim()));
        } else if let Some(value) = line.strip_prefix("inet ") {
            if let Some(address) = value.split_whitespace().next() {
                if let Some(list) = row.get_mut("ipv4").and_then(|value| value.as_array_mut()) {
                    list.push(serde_json::json!(address));
                }
            }
        } else if let Some(value) = line.strip_prefix("inet6 ") {
            if let Some(address) = value.split_whitespace().next() {
                if let Some(list) = row.get_mut("ipv6").and_then(|value| value.as_array_mut()) {
                    list.push(serde_json::json!(address));
                }
            }
        }
    }
    if let Some(row) = current.take() {
        rows.push(serde_json::json!(row));
    }
    rows
}

fn parse_upsc_status(stdout: &str) -> serde_json::Value {
    let mut values = BTreeMap::new();
    for line in stdout.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        values.insert(key.trim().to_string(), value.trim().to_string());
    }
    let status = values
        .get("ups.status")
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    let state = if status.split_whitespace().any(|part| part == "LB") {
        "low_battery"
    } else if status.split_whitespace().any(|part| part == "OB") {
        "on_battery"
    } else if status.split_whitespace().any(|part| part == "OL") {
        "online"
    } else {
        "unknown"
    };
    let model = values
        .get("ups.model")
        .or_else(|| values.get("device.model"))
        .cloned()
        .unwrap_or_else(|| "unknown".into());
    serde_json::json!({
        "name": "ups@localhost",
        "model": model,
        "manufacturer": values.get("device.mfr").cloned(),
        "status": status,
        "state": state,
        "charge_percent": values.get("battery.charge").and_then(|value| value.parse::<u8>().ok()),
        "runtime_seconds": values.get("battery.runtime").and_then(|value| value.parse::<u64>().ok()),
        "load_percent": values.get("ups.load").and_then(|value| value.parse::<u8>().ok()),
        "input_voltage": values.get("input.voltage").cloned(),
        "battery_voltage": values.get("battery.voltage").cloned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmartDevice {
    name: String,
    device_type: Option<String>,
}

fn parse_smartctl_scan(stdout: &str) -> Vec<SmartDevice> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?.to_string();
            if !name.starts_with("/dev/") {
                return None;
            }
            let mut device_type = None;
            while let Some(part) = parts.next() {
                if part == "-d" {
                    device_type = parts
                        .next()
                        .map(|value| value.trim_end_matches(',').to_string());
                    break;
                }
            }
            Some(SmartDevice { name, device_type })
        })
        .collect()
}

fn parse_smartctl_health(
    name: &str,
    device_type: Option<&str>,
    stdout: &str,
    stderr: &str,
    ok: bool,
) -> serde_json::Value {
    let model = first_smart_value(
        stdout,
        &[
            "Device Model:",
            "Product:",
            "Model Number:",
            "Vendor:",
            "Model Family:",
        ],
    )
    .unwrap_or_else(|| "unknown".into());
    let serial = first_smart_value(stdout, &["Serial Number:"]).unwrap_or_else(|| "unknown".into());
    let status = first_smart_value(
        stdout,
        &[
            "SMART overall-health self-assessment test result:",
            "SMART Health Status:",
        ],
    )
    .unwrap_or_else(|| {
        if ok {
            "unknown".into()
        } else {
            stderr
                .lines()
                .next()
                .unwrap_or("smartctl failed")
                .to_string()
        }
    });
    let lower = status.to_ascii_lowercase();
    let state = if lower.contains("passed") || lower == "ok" {
        "ok"
    } else if lower.contains("fail") || lower.contains("bad") {
        "fail"
    } else if ok {
        "unknown"
    } else {
        "warn"
    };
    serde_json::json!({
        "name": name,
        "device_type": device_type.unwrap_or("auto"),
        "model": model,
        "serial": serial,
        "smart_status": status,
        "state": state,
    })
}

fn first_smart_value(stdout: &str, keys: &[&str]) -> Option<String> {
    stdout.lines().find_map(|line| {
        let trimmed = line.trim();
        keys.iter().find_map(|key| {
            trimmed
                .strip_prefix(key)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
    })
}

fn parse_smartctl_selftests(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('#'))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                return None;
            }
            let (number, description_start) = if parts[0] == "#" {
                (parts.get(1)?.parse::<u32>().ok()?, 2)
            } else {
                (parts[0].trim_start_matches('#').parse::<u32>().ok()?, 1)
            };
            let remaining_idx = parts.iter().position(|part| part.ends_with('%'))?;
            let status_start = description_start + 2;
            if remaining_idx <= status_start || remaining_idx + 2 >= parts.len() {
                return None;
            }
            Some(serde_json::json!({
                "number": number,
                "description": parts[description_start..status_start].join(" "),
                "status": parts[status_start..remaining_idx].join(" ").replace('_', " "),
                "remaining": parts[remaining_idx],
                "lifetime_hours": parts[remaining_idx + 1],
                "lba_of_first_error": parts[remaining_idx + 2],
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
            let reservation = match fields.next().unwrap_or("none") {
                "none" | "-" => None,
                value => Some(value.to_string()),
            };
            let mountpoint = fields.next().unwrap_or("-").to_string();
            let compression = fields.next().unwrap_or("-").to_string();
            let atime = fields.next().unwrap_or("-").to_string();
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
                "reservation": reservation,
                "mountpoint": mountpoint,
                "compression": compression,
                "atime": atime,
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

fn parse_zfs_diff(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() < 3 {
                return None;
            }
            let (timestamp, change, file_type, path) = if fields.len() >= 4 {
                (
                    fields[0].parse::<i64>().ok(),
                    fields[1],
                    Some(fields[2]),
                    fields[3],
                )
            } else {
                (fields[0].parse::<i64>().ok(), fields[1], None, fields[2])
            };
            Some(serde_json::json!({
                "timestamp": timestamp.and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0)).map(|value| value.to_rfc3339()),
                "change": change,
                "file_type": file_type,
                "path": path,
            }))
        })
        .collect()
}

fn parse_pw_users(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() < 7 {
                return None;
            }
            Some(serde_json::json!({
                "username": fields[0],
                "uid": fields[2].parse::<u32>().ok(),
                "gid": fields[3].parse::<u32>().ok(),
                "full_name": fields[4],
                "home": fields[5],
                "shell": fields[6],
            }))
        })
        .collect()
}

fn parse_pw_groups(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter_map(|line| {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() < 4 {
                return None;
            }
            let members = fields[3]
                .split(',')
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            Some(serde_json::json!({
                "name": fields[0],
                "gid": fields[2].parse::<u32>().ok(),
                "members": members,
            }))
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

async fn freebsd_local_users() -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(
        &HelperOperation::ListLocalUsers,
    )?)
    .await?;
    Ok(HelperResponse {
        ok: output.ok,
        category: "local_user".into(),
        target: "all".into(),
        message: if output.ok {
            "local users loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            serde_json::json!(parse_pw_users(&output.stdout))
        } else {
            serde_json::json!([])
        },
    })
}

async fn freebsd_local_groups() -> Result<HelperResponse, HelperError> {
    let output = run_command(FreeBsdCommandBuilder::build(
        &HelperOperation::ListLocalGroups,
    )?)
    .await?;
    Ok(HelperResponse {
        ok: output.ok,
        category: "local_group".into(),
        target: "all".into(),
        message: if output.ok {
            "local groups loaded".into()
        } else {
            output.stderr
        },
        data: if output.ok {
            serde_json::json!(parse_pw_groups(&output.stdout))
        } else {
            serde_json::json!([])
        },
    })
}

async fn freebsd_upsert_local_user(
    operation: &HelperOperation,
) -> Result<HelperResponse, HelperError> {
    let HelperOperation::UpsertLocalUser {
        username, password, ..
    } = operation
    else {
        return Err(HelperError::Rejected(
            "expected local user operation".into(),
        ));
    };
    let output = if let Some(password) = password {
        let mut stdin = password.clone();
        stdin.push('\n');
        run_command_with_stdin(FreeBsdCommandBuilder::build(operation)?, stdin.as_bytes()).await?
    } else {
        run_command(FreeBsdCommandBuilder::build(operation)?).await?
    };
    Ok(HelperResponse {
        ok: output.ok,
        category: "local_user".into(),
        target: username.clone(),
        message: if output.ok {
            "local user saved".into()
        } else {
            output.stderr
        },
        data: serde_json::json!({ "status": output.status }),
    })
}

pub fn operation_category_target(operation: &HelperOperation) -> (String, String) {
    match operation {
        HelperOperation::ListStorage => ("storage".into(), "overview".into()),
        HelperOperation::SystemReport => ("system_report".into(), "localhost".into()),
        HelperOperation::ListNetworkInterfaces => ("network".into(), "interfaces".into()),
        HelperOperation::ApplyNetworkInterfaceConfig { name, .. } => {
            ("network_config".into(), name.clone())
        }
        HelperOperation::ApplyDnsResolverConfig { .. } => ("network_dns".into(), "resolver".into()),
        HelperOperation::ApplyStaticRoutesConfig { .. } => {
            ("network_routes".into(), "static".into())
        }
        HelperOperation::ListUpsStatus => ("ups".into(), "ups@localhost".into()),
        HelperOperation::ExecuteUpsShutdown { .. } => ("ups".into(), "shutdown".into()),
        HelperOperation::ApplyDirectoryServiceSettings {
            provider, domain, ..
        }
        | HelperOperation::ValidateDirectoryService {
            provider, domain, ..
        } => (
            "directory_service".into(),
            if domain.is_empty() {
                provider.clone()
            } else {
                domain.clone()
            },
        ),
        HelperOperation::JoinActiveDirectory { domain, .. }
        | HelperOperation::LeaveActiveDirectory { domain, .. } => {
            ("directory_service".into(), domain.clone())
        }
        HelperOperation::ListSmartDisks => ("disk_health".into(), "all".into()),
        HelperOperation::StartSmartTest { device, .. }
        | HelperOperation::ListSmartSelfTests { device, .. } => {
            ("smart_test".into(), device.clone())
        }
        HelperOperation::PoolScrubStatus { pool }
        | HelperOperation::PoolScrubAction { pool, .. } => ("pool_scrub".into(), pool.clone()),
        HelperOperation::ListSnapshots { dataset } => (
            "snapshot".into(),
            dataset.clone().unwrap_or_else(|| "all".into()),
        ),
        HelperOperation::CreateSnapshot { dataset, name } => {
            ("snapshot".into(), format!("{dataset}@{name}"))
        }
        HelperOperation::DeleteSnapshot { snapshot }
        | HelperOperation::RollbackSnapshot { snapshot } => ("snapshot".into(), snapshot.clone()),
        HelperOperation::CloneSnapshot {
            snapshot,
            target_dataset,
        } => (
            "snapshot_clone".into(),
            format!("{snapshot} -> {target_dataset}"),
        ),
        HelperOperation::DiffSnapshots { snapshot, .. } => {
            ("snapshot_diff".into(), snapshot.clone())
        }
        HelperOperation::CreateDataset { name, .. }
        | HelperOperation::UpdateDataset { name, .. }
        | HelperOperation::DeleteDataset { name } => ("dataset".into(), name.clone()),
        HelperOperation::SetQuota { dataset, .. } => ("quota".into(), dataset.clone()),
        HelperOperation::ApplySambaServerSettings { workgroup, .. } => {
            ("samba_settings".into(), workgroup.clone())
        }
        HelperOperation::ApplySambaShare { name, .. }
        | HelperOperation::DeleteSambaShare { name } => ("samba".into(), name.clone()),
        HelperOperation::UpsertSambaUser { username, .. }
        | HelperOperation::DeleteSambaUser { username } => ("samba_user".into(), username.clone()),
        HelperOperation::ApplyNfsExport { path, .. }
        | HelperOperation::DeleteNfsExport { path } => ("nfs".into(), path.clone()),
        HelperOperation::ApplyIscsiTarget { name, .. }
        | HelperOperation::DeleteIscsiTarget { name } => ("iscsi".into(), name.clone()),
        HelperOperation::ListLocalUsers => ("local_user".into(), "all".into()),
        HelperOperation::UpsertLocalUser { username, .. }
        | HelperOperation::DeleteLocalUser { username, .. } => {
            ("local_user".into(), username.clone())
        }
        HelperOperation::ListLocalGroups => ("local_group".into(), "all".into()),
        HelperOperation::UpsertLocalGroup { name, .. }
        | HelperOperation::DeleteLocalGroup { name } => ("local_group".into(), name.clone()),
        HelperOperation::ServiceStatus { service }
        | HelperOperation::ServiceAction { service, .. } => ("service".into(), service.clone()),
        HelperOperation::ReadLogs { service, .. } => (
            "logs".into(),
            service.clone().unwrap_or_else(|| "all".into()),
        ),
        HelperOperation::SearchSnapshotFiles { snapshot, .. } => {
            ("snapshot_files".into(), snapshot.clone())
        }
        HelperOperation::RestoreSnapshotFiles { snapshot, .. } => {
            ("snapshot_restore".into(), snapshot.clone())
        }
        HelperOperation::RunReplication {
            destination_dataset,
            ..
        } => ("replication".into(), destination_dataset.clone()),
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
    fn dataset_crud_commands_are_validated() {
        let create = FreeBsdCommandBuilder::build(&HelperOperation::CreateDataset {
            name: "tank/projects".into(),
            compression: Some("zstd".into()),
            atime: Some("off".into()),
            quota: Some("2T".into()),
            reservation: Some("none".into()),
            mountpoint: Some("/mnt/tank/projects".into()),
        })
        .unwrap();
        assert_eq!(
            create,
            vec![
                "zfs",
                "create",
                "-o",
                "compression=zstd",
                "-o",
                "atime=off",
                "-o",
                "quota=2T",
                "-o",
                "reservation=none",
                "-o",
                "mountpoint=/mnt/tank/projects",
                "tank/projects"
            ]
        );

        let update = FreeBsdCommandBuilder::build(&HelperOperation::UpdateDataset {
            name: "tank/projects".into(),
            compression: Some("lz4".into()),
            atime: None,
            quota: Some("none".into()),
            reservation: None,
            mountpoint: None,
        })
        .unwrap();
        assert_eq!(
            update,
            vec![
                "zfs",
                "set",
                "compression=lz4",
                "quota=none",
                "tank/projects"
            ]
        );

        let err = FreeBsdCommandBuilder::build(&HelperOperation::CreateDataset {
            name: "tank/bad".into(),
            compression: Some("bad;value".into()),
            atime: None,
            quota: None,
            reservation: None,
            mountpoint: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid dataset compression"));
    }

    #[test]
    fn pool_scrub_commands_are_limited_to_zpool_scrub() {
        let status = FreeBsdCommandBuilder::build(&HelperOperation::PoolScrubStatus {
            pool: "tank".into(),
        })
        .unwrap();
        assert_eq!(status, vec!["zpool", "status", "tank"]);

        let start = FreeBsdCommandBuilder::build(&HelperOperation::PoolScrubAction {
            pool: "tank".into(),
            action: PoolScrubAction::Start,
        })
        .unwrap();
        assert_eq!(start, vec!["zpool", "scrub", "tank"]);

        let stop = FreeBsdCommandBuilder::build(&HelperOperation::PoolScrubAction {
            pool: "tank".into(),
            action: PoolScrubAction::Stop,
        })
        .unwrap();
        assert_eq!(stop, vec!["zpool", "scrub", "-s", "tank"]);
    }

    #[test]
    fn smart_disk_scan_command_is_read_only() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::ListSmartDisks).unwrap();
        assert_eq!(cmd, vec!["smartctl", "--scan"]);
    }

    #[test]
    fn system_report_uses_read_only_sysctl_and_parses_output() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::SystemReport).unwrap();
        assert_eq!(
            cmd,
            vec![
                "sysctl",
                "-n",
                "kern.hostname",
                "kern.ostype",
                "kern.osrelease",
                "kern.boottime",
                "hw.physmem",
                "hw.model",
                "hw.ncpu",
                "hw.pagesize",
                "vm.stats.vm.v_free_count",
                "vm.swap_total",
                "vm.loadavg"
            ]
        );

        let report = parse_system_report(
            "nasbox\nFreeBSD\n14.2-RELEASE\n{ sec = 1710000000, usec = 0 } Fri Mar  9 10:00:00 2024\n17179869184\nAMD EPYC Mock\n8\n4096\n1048576\n4294967296\n{ 0.12 0.18 0.21 }\n",
        );
        assert_eq!(report["hostname"], "nasbox");
        assert_eq!(report["os"], "FreeBSD");
        assert_eq!(report["release"], "14.2-RELEASE");
        assert_eq!(report["memory_bytes"], 17179869184u64);
        assert_eq!(report["cpu_model"], "AMD EPYC Mock");
        assert_eq!(report["cpu_cores"], 8);
        assert_eq!(report["memory_free_bytes"], 4294967296u64);
        assert_eq!(report["swap_total_bytes"], 4294967296u64);
        assert_eq!(report["load_average"][0], 0.12);
    }

    #[test]
    fn network_interfaces_use_read_only_ifconfig_and_parse_addresses() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::ListNetworkInterfaces).unwrap();
        assert_eq!(cmd, vec!["ifconfig", "-a"]);

        let rows = parse_ifconfig_interfaces(
            "em0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\toptions=481249b<RXCSUM,TXCSUM,VLAN_MTU>\n\tether 02:00:00:00:00:01\n\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n\tinet6 fe80::1%em0 prefixlen 64 scopeid 0x1\n\tstatus: active\nlo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 ::1 prefixlen 128\n\tstatus: active\n",
        );
        assert_eq!(rows[0]["name"], "em0");
        assert_eq!(rows[0]["status"], "active");
        assert_eq!(rows[0]["mac"], "02:00:00:00:00:01");
        assert_eq!(rows[0]["ipv4"][0], "192.168.1.50");
        assert_eq!(rows[0]["ipv6"][0], "fe80::1%em0");
        assert_eq!(rows[0]["mtu"], 1500);
        assert_eq!(rows[1]["name"], "lo0");
    }

    #[test]
    fn network_interface_config_uses_sysrc_and_validates_ipv4() {
        let dhcp = FreeBsdCommandBuilder::build(&HelperOperation::ApplyNetworkInterfaceConfig {
            name: "em0".into(),
            mode: "dhcp".into(),
            ipv4_address: None,
            netmask: None,
            gateway: None,
        })
        .unwrap();
        assert_eq!(dhcp, vec!["sysrc", "ifconfig_em0=DHCP"]);

        let static_ip =
            FreeBsdCommandBuilder::build(&HelperOperation::ApplyNetworkInterfaceConfig {
                name: "em0".into(),
                mode: "static".into(),
                ipv4_address: Some("192.168.1.60".into()),
                netmask: Some("255.255.255.0".into()),
                gateway: Some("192.168.1.1".into()),
            })
            .unwrap();
        assert_eq!(
            static_ip,
            vec![
                "sysrc",
                "ifconfig_em0=inet 192.168.1.60 netmask 255.255.255.0"
            ]
        );

        let err = FreeBsdCommandBuilder::build(&HelperOperation::ApplyNetworkInterfaceConfig {
            name: "bad;if".into(),
            mode: "dhcp".into(),
            ipv4_address: None,
            netmask: None,
            gateway: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid network interface"));
    }

    #[test]
    fn dns_resolver_config_is_validated_and_rendered() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::ApplyDnsResolverConfig {
            nameservers: vec!["1.1.1.1".into(), "2001:4860:4860::8888".into()],
            search_domains: vec!["lan".into(), "example.test".into()],
        })
        .unwrap();
        assert_eq!(cmd, vec!["resolvconf", "-u"]);

        let rendered = render_resolv_conf(
            &["1.1.1.1".into(), "2001:4860:4860::8888".into()],
            &["lan".into(), "example.test".into()],
        );
        assert!(rendered.contains("search lan example.test"));
        assert!(rendered.contains("nameserver 1.1.1.1"));

        let err = FreeBsdCommandBuilder::build(&HelperOperation::ApplyDnsResolverConfig {
            nameservers: vec!["not-an-ip".into()],
            search_domains: vec![],
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid DNS nameserver"));
    }

    #[test]
    fn static_routes_are_validated_and_restart_routing() {
        let routes = vec![StaticRouteConfig {
            destination: "10.10.0.0/16".into(),
            gateway: "192.168.1.1".into(),
            description: Some("lab route".into()),
        }];
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::ApplyStaticRoutesConfig {
            routes: routes.clone(),
        })
        .unwrap();
        assert_eq!(cmd, vec!["service", "routing", "restart"]);
        assert_eq!(static_route_name(0), "bnasmgr_route_0");
        assert_eq!(
            static_route_value(&routes[0]),
            "-net 10.10.0.0/16 192.168.1.1"
        );

        let err = FreeBsdCommandBuilder::build(&HelperOperation::ApplyStaticRoutesConfig {
            routes: vec![StaticRouteConfig {
                destination: "not-cidr".into(),
                gateway: "192.168.1.1".into(),
                description: None,
            }],
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid static route destination"));
    }

    #[test]
    fn ups_status_uses_nut_upsc_and_parses_state() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::ListUpsStatus).unwrap();
        assert_eq!(cmd, vec!["upsc", "ups@localhost"]);

        let status = parse_upsc_status(
            "device.mfr: Example\nups.model: LinePower 1500\nups.status: OB LB\nbattery.charge: 12\nbattery.runtime: 140\nups.load: 37\ninput.voltage: 0.0\nbattery.voltage: 23.8\n",
        );
        assert_eq!(status["name"], "ups@localhost");
        assert_eq!(status["model"], "LinePower 1500");
        assert_eq!(status["state"], "low_battery");
        assert_eq!(status["charge_percent"], 12);
        assert_eq!(status["runtime_seconds"], 140);
        assert_eq!(status["load_percent"], 37);
    }

    #[test]
    fn ups_shutdown_command_is_narrowly_allowlisted() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::ExecuteUpsShutdown {
            command: "shutdown -p now".into(),
        })
        .unwrap();
        assert_eq!(cmd, vec!["shutdown", "-p", "now"]);

        let delayed = FreeBsdCommandBuilder::build(&HelperOperation::ExecuteUpsShutdown {
            command: "shutdown -h +10".into(),
        })
        .unwrap();
        assert_eq!(delayed, vec!["shutdown", "-h", "+10"]);

        let err = FreeBsdCommandBuilder::build(&HelperOperation::ExecuteUpsShutdown {
            command: "reboot now".into(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("UPS shutdown command"));
    }

    #[test]
    fn directory_service_settings_restart_nslcd_with_safe_args() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::ApplyDirectoryServiceSettings {
            enabled: true,
            provider: "ldap".into(),
            domain: "example.test".into(),
            uri: "ldaps://directory.example.test".into(),
            base_dn: "dc=example,dc=test".into(),
            bind_dn: Some("cn=readonly,dc=example,dc=test".into()),
            tls: true,
            ca_cert_path: Some("/usr/local/etc/ssl/certs/directory-ca.pem".into()),
            nss_enabled: true,
            pam_enabled: true,
        })
        .unwrap();
        assert_eq!(cmd, vec!["service", "nslcd", "restart"]);
        let rendered = render_nslcd_conf(&NslcdRenderSettings {
            enabled: true,
            provider: "ldap",
            domain: "example.test",
            uri: "ldaps://directory.example.test",
            base_dn: "dc=example,dc=test",
            bind_dn: Some("cn=readonly,dc=example,dc=test"),
            tls: true,
            ca_cert_path: Some("/usr/local/etc/ssl/certs/directory-ca.pem"),
        });
        assert!(rendered.contains("uri ldaps://directory.example.test"));
        assert!(rendered.contains("base dc=example,dc=test"));
        assert!(rendered.contains("binddn cn=readonly,dc=example,dc=test"));
        assert!(rendered.contains("ssl on"));
        assert!(rendered.contains("tls_reqcert demand"));
        assert!(rendered.contains("tls_cacertfile /usr/local/etc/ssl/certs/directory-ca.pem"));
        assert!(render_nsswitch_conf(true).contains("passwd: files ldap"));
        assert!(render_nsswitch_conf(false).contains("passwd: files"));
        assert!(render_pam_system_conf(true).contains("/usr/local/lib/pam_ldap.so"));
        assert!(!render_pam_system_conf(false).contains("/usr/local/lib/pam_ldap.so"));
        let ldap_validation =
            FreeBsdCommandBuilder::build(&HelperOperation::ValidateDirectoryService {
                provider: "ldap".into(),
                domain: "example.test".into(),
                uri: "ldap://directory.example.test".into(),
                tls: false,
                ca_cert_path: None,
            })
            .unwrap();
        assert_eq!(ldap_validation, vec!["service", "nslcd", "status"]);
        let ldap_tls_validation =
            FreeBsdCommandBuilder::build(&HelperOperation::ValidateDirectoryService {
                provider: "ldap".into(),
                domain: "example.test".into(),
                uri: "ldap://directory.example.test:1389".into(),
                tls: true,
                ca_cert_path: Some("/usr/local/etc/ssl/certs/directory-ca.pem".into()),
            })
            .unwrap();
        assert_eq!(
            ldap_tls_validation,
            vec![
                "openssl",
                "s_client",
                "-starttls",
                "ldap",
                "-connect",
                "directory.example.test:1389",
                "-servername",
                "directory.example.test",
                "-verify_return_error",
                "-brief",
                "-CAfile",
                "/usr/local/etc/ssl/certs/directory-ca.pem"
            ]
        );
        let ldaps_validation =
            FreeBsdCommandBuilder::build(&HelperOperation::ValidateDirectoryService {
                provider: "ldap".into(),
                domain: "example.test".into(),
                uri: "ldaps://directory.example.test".into(),
                tls: true,
                ca_cert_path: None,
            })
            .unwrap();
        assert_eq!(
            ldaps_validation,
            vec![
                "openssl",
                "s_client",
                "-connect",
                "directory.example.test:636",
                "-servername",
                "directory.example.test",
                "-verify_return_error",
                "-brief"
            ]
        );
        let ad_validation =
            FreeBsdCommandBuilder::build(&HelperOperation::ValidateDirectoryService {
                provider: "active_directory".into(),
                domain: "example.test".into(),
                uri: "ldaps://directory.example.test".into(),
                tls: true,
                ca_cert_path: None,
            })
            .unwrap();
        assert_eq!(ad_validation, vec!["net", "ads", "testjoin"]);
        let ad_join = FreeBsdCommandBuilder::build(&HelperOperation::JoinActiveDirectory {
            domain: "example.test".into(),
            username: "join-admin".into(),
            password: "not-in-argv".into(),
        })
        .unwrap();
        assert_eq!(ad_join, vec!["net", "ads", "join", "-U", "join-admin"]);
        assert!(!ad_join.iter().any(|arg| arg.contains("not-in-argv")));
        let ad_leave = FreeBsdCommandBuilder::build(&HelperOperation::LeaveActiveDirectory {
            domain: "example.test".into(),
            username: Some("join-admin".into()),
            password: Some("not-in-argv".into()),
        })
        .unwrap();
        assert_eq!(ad_leave, vec!["net", "ads", "leave", "-U", "join-admin"]);
        assert!(!ad_leave.iter().any(|arg| arg.contains("not-in-argv")));
        let ad_leave_without_credentials =
            FreeBsdCommandBuilder::build(&HelperOperation::LeaveActiveDirectory {
                domain: "example.test".into(),
                username: None,
                password: None,
            })
            .unwrap();
        assert_eq!(ad_leave_without_credentials, vec!["net", "ads", "leave"]);

        let disabled = render_nslcd_conf(&NslcdRenderSettings {
            enabled: false,
            provider: "ldap",
            domain: "",
            uri: "",
            base_dn: "",
            bind_dn: None,
            tls: false,
            ca_cert_path: None,
        });
        assert!(disabled.contains("directory service disabled"));

        let err = FreeBsdCommandBuilder::build(&HelperOperation::ApplyDirectoryServiceSettings {
            enabled: true,
            provider: "ldap".into(),
            domain: "bad;domain".into(),
            uri: "ldaps://directory.example.test".into(),
            base_dn: "dc=example,dc=test".into(),
            bind_dn: None,
            tls: true,
            ca_cert_path: None,
            nss_enabled: false,
            pam_enabled: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsafe command argument"));
    }

    #[test]
    fn smart_test_commands_are_allowlisted() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::StartSmartTest {
            device: "/dev/ada0".into(),
            device_type: Some("ata".into()),
            test: "short".into(),
        })
        .unwrap();
        assert_eq!(
            cmd,
            vec!["smartctl", "-t", "short", "-d", "ata", "/dev/ada0"]
        );

        let err = FreeBsdCommandBuilder::build(&HelperOperation::StartSmartTest {
            device: "/dev/ada0".into(),
            device_type: None,
            test: "bad".into(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid SMART test type"));
    }

    #[test]
    fn replication_command_builder_rejects_unsafe_targets() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::RunReplication {
            snapshot: "tank/media@repl-20260520".into(),
            base_snapshot: None,
            destination_dataset: "backup/media".into(),
            remote_host: None,
            remote_user: None,
        })
        .unwrap();
        assert_eq!(
            cmd,
            vec![
                "zfs",
                "send",
                "tank/media@repl-20260520",
                "|",
                "zfs",
                "receive",
                "-F",
                "backup/media"
            ]
        );

        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::RunReplication {
            snapshot: "tank/media@repl-20260521".into(),
            base_snapshot: Some("tank/media@repl-20260520".into()),
            destination_dataset: "backup/media".into(),
            remote_host: None,
            remote_user: None,
        })
        .unwrap();
        assert_eq!(
            cmd,
            vec![
                "zfs",
                "send",
                "-i",
                "tank/media@repl-20260520",
                "tank/media@repl-20260521",
                "|",
                "zfs",
                "receive",
                "-F",
                "backup/media"
            ]
        );

        let err = FreeBsdCommandBuilder::build(&HelperOperation::RunReplication {
            snapshot: "tank/media@bad;rm".into(),
            base_snapshot: None,
            destination_dataset: "backup/media".into(),
            remote_host: None,
            remote_user: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("unsafe command argument"));
    }

    #[test]
    fn parses_smart_selftest_history() {
        let rows = parse_smartctl_selftests(
            "# 1  Short offline       Completed without error       00%      1234         -\n",
        );
        assert_eq!(rows[0]["description"], "Short offline");
        assert_eq!(rows[0]["status"], "Completed without error");
        assert_eq!(rows[0]["lifetime_hours"], "1234");
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
    fn builds_snapshot_clone_and_diff_commands() {
        let clone = FreeBsdCommandBuilder::build(&HelperOperation::CloneSnapshot {
            snapshot: "tank/media@daily".into(),
            target_dataset: "tank/media-clone".into(),
        })
        .unwrap();
        assert_eq!(
            clone,
            vec!["zfs", "clone", "tank/media@daily", "tank/media-clone"]
        );

        let diff = FreeBsdCommandBuilder::build(&HelperOperation::DiffSnapshots {
            snapshot: "tank/media@daily".into(),
            to_snapshot: Some("tank/media@weekly".into()),
        })
        .unwrap();
        assert_eq!(
            diff,
            vec![
                "zfs",
                "diff",
                "-FHt",
                "tank/media@daily",
                "tank/media@weekly"
            ]
        );

        let rows = parse_zfs_diff("1779120000\tM\tF\t/mnt/tank/media/report.txt\n");
        assert_eq!(rows[0]["change"], "M");
        assert_eq!(rows[0]["file_type"], "F");
        assert_eq!(rows[0]["path"], "/mnt/tank/media/report.txt");
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

        let iscsi = FreeBsdCommandBuilder::build(&HelperOperation::ApplyIscsiTarget {
            name: "iqn.2026-05.local.bnasmgr:disk0".into(),
            portal_group: "pg0".into(),
            initiator_name: None,
            auth_group: "no-authentication".into(),
            extent_name: "disk0".into(),
            path: "/dev/zvol/tank/iscsi/disk0".into(),
            size: Some("10G".into()),
            lun_id: 0,
            readonly: false,
        })
        .unwrap();
        assert_eq!(iscsi, vec!["service", "ctld", "reload"]);
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
    fn local_identity_commands_do_not_include_passwords() {
        let cmd = FreeBsdCommandBuilder::build(&HelperOperation::UpsertLocalUser {
            username: "media".into(),
            full_name: Some("Media User".into()),
            shell: "/bin/sh".into(),
            home: Some("/home/media".into()),
            groups: vec!["wheel".into(), "media".into()],
            password: Some("not-in-argv".into()),
            create_home: true,
        })
        .unwrap();
        assert_eq!(
            cmd,
            vec![
                "pw",
                "useradd",
                "media",
                "-m",
                "-s",
                "/bin/sh",
                "-c",
                "Media User",
                "-d",
                "/home/media",
                "-G",
                "wheel,media",
                "-h",
                "0"
            ]
        );
        assert!(!cmd.iter().any(|arg| arg.contains("not-in-argv")));

        let group = FreeBsdCommandBuilder::build(&HelperOperation::UpsertLocalGroup {
            name: "media".into(),
            members: vec!["media".into(), "alice".into()],
        })
        .unwrap();
        assert_eq!(group, vec!["pw", "groupadd", "media", "-M", "media,alice"]);

        let users = parse_pw_users("media:*:1001:1001:Media User:/home/media:/bin/sh\n");
        assert_eq!(users[0]["username"], "media");
        assert_eq!(users[0]["uid"], 1001);
        let groups = parse_pw_groups("media:*:1001:media,alice\n");
        assert_eq!(groups[0]["members"][1], "alice");
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

        let iscsi = render_iscsi_target(&IscsiTargetRender {
            name: "iqn.2026-05.local.bnasmgr:disk0",
            portal_group: "pg0",
            initiator_name: None,
            auth_group: "no-authentication",
            extent_name: "disk0",
            path: "/dev/zvol/tank/iscsi/disk0",
            size: Some("10G"),
            lun_id: 0,
            readonly: true,
        });
        assert!(iscsi.contains("target iqn.2026-05.local.bnasmgr:disk0"));
        assert!(iscsi.contains("extent disk0"));
        assert!(iscsi.contains("path /dev/zvol/tank/iscsi/disk0"));
        assert!(iscsi.contains("option readonly on"));
    }

    #[test]
    fn renders_samba_server_settings_fragment() {
        let settings =
            render_samba_server_settings("HOME", "Home NAS", "BNAS", "user", "Bad User", "2");
        assert!(settings.contains("[global]"));
        assert!(settings.contains("workgroup = HOME"));
        assert!(settings.contains("netbios name = BNAS"));
        assert!(settings.contains("map to guest = Bad User"));
    }

    #[test]
    fn snapshot_file_paths_must_be_relative() {
        assert!(validate_relative_file("docs/report.txt").is_ok());
        assert!(validate_relative_file("/docs/report.txt").is_err());
        assert!(validate_relative_file("../report.txt").is_err());
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
            "tank/media\t879609302220\t5937362789990\t6597069766656\tnone\t/mnt/tank/media\tlz4\toff\n",
            &pools,
            &counts,
        );
        assert_eq!(pools[0]["name"], "tank");
        assert_eq!(pools[0]["health"], "online");
        assert_eq!(datasets[0]["name"], "tank/media");
        assert_eq!(datasets[0]["health"], "online");
        assert_eq!(datasets[0]["snapshots"], 2);
        assert_eq!(datasets[0]["compression"], "lz4");
        assert_eq!(datasets[0]["atime"], "off");
    }

    #[test]
    fn parses_pool_scrub_status() {
        let running = parse_zpool_scrub_status(
            "  pool: tank\n state: ONLINE\n  scan: scrub in progress since Tue May 19 12:00:00 2026\n",
        );
        assert_eq!(running["state"], "running");

        let finished = parse_zpool_scrub_status(
            "  pool: tank\n state: ONLINE\n  scan: scrub repaired 0B in 00:12:14 with 0 errors on Tue May 19 12:12:14 2026\n",
        );
        assert_eq!(finished["state"], "finished");
    }

    #[test]
    fn parses_smartctl_scan_and_health() {
        let devices = parse_smartctl_scan(
            "/dev/ada0 -d atacam # /dev/ada0, ATA device\n/dev/nvme0 -d nvme # NVMe device\n",
        );
        assert_eq!(
            devices[0],
            SmartDevice {
                name: "/dev/ada0".into(),
                device_type: Some("atacam".into())
            }
        );
        let health = parse_smartctl_health(
            "/dev/ada0",
            Some("atacam"),
            "Device Model:     Example SSD\nSerial Number:    ABC123\nSMART overall-health self-assessment test result: PASSED\n",
            "",
            true,
        );
        assert_eq!(health["state"], "ok");
        assert_eq!(health["model"], "Example SSD");
        assert_eq!(health["serial"], "ABC123");
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
