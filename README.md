# bnasmgr

FreeBSD NAS dashboard MVP built with a Rust API/helper split and a Svelte frontend.

## Development

The backend defaults to mock helper mode so it can run on non-FreeBSD systems.

```sh
cargo run -p bnasmgr-api
```

The API listens on `127.0.0.1:8080` and stores SQLite data in `bnasmgr.db` unless overridden:

```sh
BNASMGR_DATABASE_URL='sqlite://bnasmgr.db?mode=rwc' BNASMGR_BIND=127.0.0.1:8080 cargo run -p bnasmgr-api
```

To run the API directly over HTTPS, provide a PEM certificate and key:

```sh
BNASMGR_BIND=0.0.0.0:8443 \
BNASMGR_TLS_CERT=/usr/local/etc/ssl/bnasmgr/fullchain.pem \
BNASMGR_TLS_KEY=/usr/local/etc/ssl/bnasmgr/privkey.pem \
cargo run -p bnasmgr-api
```

The API can also serve the built frontend directly when `BNASMGR_STATIC_DIR` points at the Svelte build output directory containing `index.html`. Unknown non-API routes fall back to `index.html`; unknown `/api/*` routes still return JSON 404 responses.

Run the frontend in another shell:

```sh
cd frontend
npm install
npm run dev
```

For HTTPS frontend development, give Vite a local certificate and point the proxy at the HTTPS API:

```sh
BNASMGR_API_ORIGIN=https://127.0.0.1:8443 \
BNASMGR_DEV_TLS_CERT=./certs/dev-cert.pem \
BNASMGR_DEV_TLS_KEY=./certs/dev-key.pem \
npm run dev
```

Default dashboard credentials are `admin` / `admin`. The first login is intentionally restricted until the password is changed. Dashboard passwords are stored with Argon2id; older development databases with the initial SHA-256 format are upgraded after a successful login.

## API Surface

All routes are under `/api`:

- `/api/auth/*`
- `/api/config/export` and `/api/config/import` for operational configuration backup and restore
- `/api/users` for listing, creating, deleting, role changes, and password resets
- `/api/system/report` for read-only host, OS, uptime, memory, and load reporting
- `/api/system/network` for read-only network interface inventory
- `/api/system/network/config` for DHCP/static IPv4 interface configuration
- `/api/system/network/dns` for resolver nameserver and search domain configuration
- `/api/system/network/routes` for static route configuration
- `/api/system/users` and `/api/system/groups` for local Unix identity management
- `/api/system/ups` for NUT UPS status monitoring
- `/api/system/ups/policy` for low charge/runtime threshold policy settings
- `/api/system/ups/shutdown` for confirmed execution of the configured UPS shutdown command
- `/api/system/directory-service` for LDAP/Active Directory connection settings
- `/api/storage/*` including dataset create, property updates, delete, quota, and pool scrub controls
- `/api/storage/disks/tests` for SMART self-test launch and history
- `/api/snapshots/*`
- `/api/snapshots/:snapshot/files` for searching snapshot contents and restoring selected files
- `/api/snapshots/:snapshot/clone` and `/api/snapshots/:snapshot/diff` for point-in-time clone and change inspection workflows
- `/api/replication/tasks` for local and remote ZFS replication task definitions and manual runs
- `/api/shares/samba/*` including server settings, shares, and Samba users
- `/api/shares/nfs/*`
- `/api/shares/iscsi/*` for iSCSI target, extent, and LUN definitions
- `/api/services/*`
- `/api/alerts` for computed storage, disk, service, and helper-failure alerts
- `/api/alerts/notifications` for alert notification channel settings
- `/api/alerts/notifications/history` for queued alert notification attempts
- `/api/logs`
- `/api/audit` and `/api/audit/helper-history`

The privileged boundary is represented by `bnasmgr-helper`. It accepts typed operations only; arbitrary shell commands are not part of the protocol. Snapshot, quota, service, Samba share, and NFS export mutations all pass through that helper path.

The FreeBSD helper adapter now normalizes `zpool`, `zfs`, `service`, and log output into the same JSON shape used by mock development mode, so the UI can switch adapters without changing API contracts.

System reporting uses read-only `sysctl` values for hostname, OS release, boot time, CPU model/core count, physical/free memory, swap total, and load averages. Network inventory uses read-only `ifconfig -a` output. Network configuration writes persist dashboard intent, apply DHCP/static IPv4 settings with `sysrc ifconfig_<iface>=...`, restart the target interface through `service netif restart <iface>`, write validated resolver settings to `/etc/resolv.conf`, and manage static route rc.conf entries before restarting routing.

Service control is restricted to the NAS service allowlist. Dataset create/update/delete and quota changes are validated before reaching the helper; destructive dataset delete requires an `X-BNASMGR-CONFIRM` header matching the dataset name.

UPS monitoring uses NUT's `upsc ups@localhost` command from the helper and normalizes line, battery, charge, runtime, and load fields for the dashboard.
UPS policy settings are stored in operational configuration and can raise dashboard alerts when charge or runtime falls below configured thresholds. Confirmed shutdown execution runs through the helper and only accepts `shutdown -p now`, `shutdown -h now`, or `shutdown -p|-h +minutes` up to 1440 minutes.

Directory service settings store LDAP or Active Directory connection metadata, validate required fields and LDAP URI schemes, and apply through the typed helper boundary. The FreeBSD helper renders `/usr/local/etc/nslcd.conf` before restarting `nslcd`; override the target path with `BNASMGR_NSLCD_CONF` for staged validation. NSS/PAM and domain join wiring still need target-host validation before relying on directory logins.

Local Unix users/groups and Samba storage users are managed separately from dashboard users. Local and Samba passwords are sent to the helper over the local socket and are redacted from helper history.

Dashboard admins can manage common Samba server settings such as workgroup, server string, NetBIOS name, security mode, guest mapping, and log level. The helper writes these as a Samba global fragment before reloading `samba_server`.

Samba and NFS share application writes helper-owned config fragments atomically before service reload. The default FreeBSD fragment roots are `/usr/local/etc/bnasmgr/smb4.includes` and `/usr/local/etc/bnasmgr/exports.d`.

iSCSI target application writes helper-owned `ctl.conf` fragments before reloading `ctld`. The default FreeBSD fragment root is `/usr/local/etc/bnasmgr/ctl.conf.d`; include those fragments from the host `ctl.conf` before relying on dashboard-managed targets.

The log viewer supports service, severity, search text, and date-range filters. FreeBSD syslog-style timestamps are parsed using the current year.

The alert notifier runs in the API process by default every five minutes. Set `BNASMGR_ALERT_NOTIFIER=off` to disable it or `BNASMGR_ALERT_NOTIFIER_SECONDS` to change the interval. `http://` and `https://` webhook URLs are POSTed directly, and email can be sent through SMTP with plain, STARTTLS, or implicit TLS transport. SMTP authentication uses AUTH PLAIN when a username and password are configured.

Replication tasks are scanned by the API process by default every minute. Set `BNASMGR_REPLICATION_SCHEDULER=off` to disable it or `BNASMGR_REPLICATION_SCHEDULER_SECONDS` to change the interval. Each run creates a `repl-*` snapshot, uses the newest prior local `repl-*` snapshot as the incremental send base when one exists, and prunes older local replication snapshots by the task retention count.

Destructive snapshot delete and rollback calls require an `X-BNASMGR-CONFIRM` header matching the exact snapshot name, in addition to UI confirmation.

File-level snapshot restore searches files under the dataset snapshot mount and restores selected relative paths back into the live dataset. Restore requests also require `X-BNASMGR-CONFIRM` matching the snapshot name because existing live files may be overwritten.

Snapshot clone creates a writable ZFS dataset from a selected snapshot. Snapshot diff uses `zfs diff -FHt` and returns normalized change rows for inspection before restore or rollback.

Configuration export/import covers saved operational dashboard state such as shares, iSCSI targets, Samba users, notification settings, and scheduled tasks. Sessions, audit/helper history, notification delivery history, and password hashes are intentionally excluded; SMTP passwords are redacted from exports.

## Project Layout

- `crates/bnasmgr-api`: Axum API, SQLite persistence, session auth, audit records.
- `crates/bnasmgr-helper`: typed helper protocol, mock backend, FreeBSD command builder.
- `frontend`: Svelte dashboard.
- `docs/freebsd-deployment.md`: FreeBSD deployment and operations notes.
