# Remaining Work

This file is the durable handoff for the recovered FreeBSD NAS Dashboard MVP plan.

## MVP Status

The recovered MVP implementation plan is functionally complete in this repo:

- Rust workspace with `bnasmgr-api` and `bnasmgr-helper`.
- Svelte dashboard for storage, snapshots, Samba/NFS/iSCSI shares, services, logs, audit, and dashboard users.
- Dashboard auth with seeded `admin` / `admin`, forced password change, Argon2id hashes, and legacy development hash migration.
- Local Unix user/group listing and mutation through typed helper operations.
- Operational configuration backup/restore for saved dashboard state with secret redaction.
- SQLite persistence for dashboard users, sessions, Samba/NFS/iSCSI share metadata, Samba users, audit events, helper history, and settings.
- Typed helper protocol over a Unix socket, with mock and FreeBSD backends.
- FreeBSD command construction/parsing for ZFS storage, snapshots, quotas, services, logs, Samba users, and Samba/NFS/iSCSI fragment application.
- Dataset create, property update, and delete workflows for compression, atime, quota, reservation, and mountpoint controls.
- Service monitoring/control for `zfs`, `samba_server`, `nfsd`, `mountd`, `rpcbind`, `ctld`, and `syslogd`.
- Pool scrub status plus start/stop controls.
- SMART disk health inventory with self-test launch and history.
- Computed alerts for degraded pools, unhealthy disks, stopped services, and failed helper operations.
- Alert notification channel settings with validation and test audit events.
- Background alert notification scan with HTTP/HTTPS webhook delivery, plain/authenticated/TLS SMTP delivery, and per-channel deduped delivery history.
- Helper history redacts Samba passwords.
- Destructive snapshot delete/rollback requires an exact `X-BNASMGR-CONFIRM` header.
- Snapshot clone and diff workflows for writable point-in-time recovery and change inspection.
- iSCSI target, extent, and LUN CRUD writes helper-owned `ctl.conf` fragments before `ctld` reload.
- Snapshot tasks can be stored, run automatically by the API scheduler, manually run, and pruned by retention count for matching task-created snapshot prefixes.
- Replication tasks can be stored, manually run, and automatically run by the API scheduler for local and remote ZFS send/receive, with local incremental bases and replication snapshot retention.
- FreeBSD deployment notes and manual smoke checklist.

## Traditional NAS Feature Plan

The next implementation track is modeled after common TrueNAS-style NAS administration:

- Scheduled snapshot tasks with cadence and retention metadata.
- Directory service integration.
- UPS integration, network configuration, directory service integration, and system reporting.

## Verification Commands

Run these before handing off or cutting a release:

```sh
cargo test --workspace
cd frontend
npm run check
npm run build
npm run test:e2e
```

The latest local verification passed with these commands.

## Still Left

- Validate scheduled snapshot task execution and retention pruning on FreeBSD with a disposable dataset.
- Run the FreeBSD manual acceptance checklist on an actual FreeBSD host with a disposable ZFS pool/dataset.
- Wire and validate Samba include fragments on the exact Samba package version installed on the target host.
- Wire and validate NFS export fragment consumption before relying on generated exports in production.
- Validate file-level snapshot restore on FreeBSD with a disposable dataset, including datasets where `.zfs/snapshot` visibility differs from defaults.
- Wire and validate iSCSI `ctl.conf` fragment inclusion before relying on dashboard-managed targets in production.
