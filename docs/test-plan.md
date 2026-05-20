# Test Plan

Automated coverage in this MVP includes:

- Helper command construction and unsafe-argument rejection.
- Helper-mediated Samba and NFS reload command construction.
- FreeBSD `zpool`, `zfs snapshot`, and service-status output parsing.
- Service allowlist enforcement and quota value validation.
- SMART disk inventory, self-test launch validation, and self-test history parsing.
- Computed alerts for failed helper operations and live NAS health signals.
- Alert notification channel settings validation, persistence, and test audit events.
- Background alert notification scan deduplication and delivery history.
- Plain HTTP webhook delivery request construction.
- Plain SMTP email message and command construction.
- Helper operation history API and audit UI.
- Samba storage user create/update/delete, password stdin handling, and helper-history redaction.
- Samba server settings persistence and helper-applied global fragment rendering.
- Samba/NFS share fragment rendering and safe fragment file-name generation.
- Log service/severity/search/date-range filtering and FreeBSD syslog timestamp parsing.
- Snapshot dataset/name validation and backend confirmation header enforcement for delete/rollback.
- Snapshot file search and selected-file restore validation.
- Replication task validation, persistence, listing, deletion, and manual run path.
- Scheduled replication task cadence handling.
- Argon2id password hashing with legacy development-hash verification.
- Dashboard user create, role change, password reset, delete, self-delete guard, and last-admin guard.
- Service status color mapping.
- API first-login enforcement for privileged actions.

Manual smoke coverage:

1. Start `cargo run -p bnasmgr-api`.
2. Log in as `admin` / `admin`.
3. Confirm privileged actions are blocked until the password is changed.
4. Change the dashboard password.
5. Open storage, snapshots, shares, services, logs, audit, and users.
6. Create a snapshot in mock mode and confirm audit entries are written.
7. Trigger service `start`, `stop`, and `restart` in mock mode.
8. On FreeBSD, validate real helper command execution against a disposable ZFS dataset before using production pools.

See `docs/remaining-work.md` for the current handoff checklist and post-MVP work.
