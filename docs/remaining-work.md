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
- Helper history redacts Samba passwords.
- Destructive snapshot delete/rollback requires an exact `X-BNASMGR-CONFIRM` header.
- FreeBSD deployment notes and manual smoke checklist.

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

- Run the FreeBSD manual acceptance checklist on an actual FreeBSD host with a disposable ZFS pool/dataset.
- Wire and validate Samba include fragments on the exact Samba package version installed on the target host.
- Wire and validate NFS export fragment consumption before relying on generated exports in production.
- Validate file-level snapshot restore on FreeBSD with a disposable dataset, including datasets where `.zfs/snapshot` visibility differs from defaults.
- Add automated browser smoke tests for login, first-password-change, storage load, snapshot workflow, service controls, logs, and user management.
- Decide whether production should keep nginx serving the Svelte build or add static-file serving to `bnasmgr-api`.
- Implement full iSCSI target CRUD later; the MVP intentionally only monitors/controls `ctld` service status.
