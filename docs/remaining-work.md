# Remaining Work

This file is the durable handoff for the recovered FreeBSD NAS Dashboard MVP plan.

## MVP Status

The recovered MVP implementation plan is functionally complete in this repo:

- Rust workspace with `bnasmgr-api` and `bnasmgr-helper`.
- Svelte dashboard for storage, snapshots, Samba/NFS shares, services, logs, audit, and dashboard users.
- Dashboard auth with seeded `admin` / `admin`, forced password change, Argon2id hashes, and legacy development hash migration.
- SQLite persistence for dashboard users, sessions, Samba/NFS share metadata, Samba users, audit events, helper history, and settings.
- Typed helper protocol over a Unix socket, with mock and FreeBSD backends.
- FreeBSD command construction/parsing for ZFS storage, snapshots, quotas, services, logs, Samba users, and Samba/NFS fragment application.
- Service monitoring/control for `zfs`, `samba_server`, `nfsd`, `mountd`, `rpcbind`, `ctld`, and `syslogd`.
- Pool scrub status plus start/stop controls.
- Helper history redacts Samba passwords.
- Destructive snapshot delete/rollback requires an exact `X-BNASMGR-CONFIRM` header.
- Snapshot tasks can be stored, run automatically by the API scheduler, manually run, and pruned by retention count for matching task-created snapshot prefixes.
- FreeBSD deployment notes and manual smoke checklist.

## Traditional NAS Feature Plan

The next implementation track is modeled after common TrueNAS-style NAS administration:

- Scheduled snapshot tasks with cadence and retention metadata.
- SMART disk health, SMART test launch, and disk inventory.
- Alerts and notifications for degraded pools, failed helper operations, disk health, and service failures.
- Replication tasks for local and remote ZFS send/receive.
- Dataset CRUD, including compression, atime, quota, reservation, and mountpoint controls.
- Snapshot clone/diff workflows to improve point-in-time recovery.
- Full iSCSI target/extent/LUN CRUD.
- Local Unix users/groups and directory service integration.
- Config backup/restore, UPS integration, network configuration, and system reporting.

## Verification Commands

Run these before handing off or cutting a release:

```sh
cargo test --workspace
cd frontend
npm run check
npm run build
```

The latest local verification passed with these commands.

## Still Left

- Validate scheduled snapshot task execution and retention pruning on FreeBSD with a disposable dataset.
- Run the FreeBSD manual acceptance checklist on an actual FreeBSD host with a disposable ZFS pool/dataset.
- Wire and validate Samba include fragments on the exact Samba package version installed on the target host.
- Wire and validate NFS export fragment consumption before relying on generated exports in production.
- Validate file-level snapshot restore on FreeBSD with a disposable dataset, including datasets where `.zfs/snapshot` visibility differs from defaults.
- Add automated browser smoke tests for login, first-password-change, storage load, snapshot workflow, service controls, logs, and user management.
- Decide whether production should keep nginx serving the Svelte build or add static-file serving to `bnasmgr-api`.
- Implement full iSCSI target CRUD later; the MVP intentionally only monitors/controls `ctld` service status.
