# Test Plan

Automated coverage in this MVP includes:

- Helper command construction and unsafe-argument rejection.
- Helper-mediated Samba and NFS reload command construction.
- FreeBSD `zpool`, `zfs snapshot`, and service-status output parsing.
- Service allowlist enforcement and quota value validation.
- System report command construction, sysctl CPU/memory/swap/load parsing, API exposure, and browser smoke coverage.
- Network inventory command construction, ifconfig output parsing, API exposure, and browser smoke coverage.
- Network DHCP/static IPv4 configuration validation, persistence, `sysrc` command construction, and browser smoke coverage.
- DNS resolver validation, resolv.conf rendering, persistence, and browser smoke coverage.
- Static route validation, persistence, routing restart command construction, and browser smoke coverage.
- Dataset create/update/delete command construction, property validation, and delete confirmation.
- SMART disk inventory, self-test launch validation, and self-test history parsing.
- UPS status command construction, NUT `upsc` output parsing, and API exposure.
- UPS policy persistence, validation, alert threshold handling, confirmed shutdown execution, and browser smoke coverage.
- Directory service settings validation, persistence, helper command construction, config backup inclusion, validation action, Active Directory join/leave actions, audit coverage, and browser smoke coverage.
- Directory service `nslcd.conf` rendering including optional CA certificate trust path, optional NSS/PAM rendering, helper-owned `nslcd` restart command construction, LDAP/LDAPS certificate probe command construction, and Active Directory validation command construction.
- Computed alerts for failed helper operations and live NAS health signals.
- Alert notification channel settings validation, persistence, and test audit events.
- Background alert notification scan deduplication and delivery history.
- Plain HTTP webhook delivery request construction.
- Plain SMTP email message and command construction.
- Helper operation history API and audit UI.
- Samba storage user create/update/delete, password stdin handling, and helper-history redaction.
- Samba server settings persistence and helper-applied global fragment rendering.
- Samba/NFS share fragment rendering and safe fragment file-name generation.
- iSCSI target/extent/LUN validation, persistence, fragment rendering, and `ctld` reload command construction.
- Log service/severity/search/date-range filtering and FreeBSD syslog timestamp parsing.
- Snapshot dataset/name validation and backend confirmation header enforcement for delete/rollback.
- Snapshot clone command construction and diff output parsing.
- Snapshot file search and selected-file restore validation.
- Replication task validation, persistence, listing, deletion, retention metadata, incremental base selection, and manual run path.
- Scheduled replication task cadence handling.
- Argon2id password hashing with legacy development-hash verification.
- Dashboard user create, role change, password reset, delete, self-delete guard, and last-admin guard.
- Local Unix user/group command construction, parsing, validation, and password redaction.
- Configuration backup import/export coverage with secret redaction.
- Service status color mapping.
- API first-login enforcement for privileged actions.
- Browser smoke coverage for seeded-admin login, first-password-change, storage load, destructive dataset confirmation, snapshot file restore, snapshot task run, Samba/NFS/iSCSI share create/delete, UPS policy and confirmed shutdown execution, alert webhook/email notification settings and tests, directory service settings and validation, configuration export/import including replace restore, service restart, log filtering, dashboard user management, audit persistence, and core dashboard navigation.

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
