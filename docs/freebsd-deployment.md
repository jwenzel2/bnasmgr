# FreeBSD Deployment Notes

This MVP uses a split privilege model:

- `bnasmgr-api` runs as an unprivileged service account.
- A small root-owned helper accepts typed JSON operations over a local Unix socket.
- Mutating operations require a dashboard admin whose initial password has been changed.
- Dashboard passwords are stored with Argon2id.
- Every helper operation records audit and helper history entries in SQLite.

## Packages and Services

Install the platform components used by the dashboard:

```sh
pkg install sqlite3 samba419 rust npm nginx
```

Enable the storage and sharing services that match the host role:

```sh
sysrc zfs_enable=YES
sysrc samba_server_enable=YES
sysrc nfs_server_enable=YES
sysrc mountd_enable=YES
sysrc rpcbind_enable=YES
sysrc syslogd_enable=YES
```

iSCSI target management uses the `ctld` service:

```sh
sysrc ctld_enable=YES
```

Dashboard-managed iSCSI targets are written as helper-owned fragments under `/usr/local/etc/bnasmgr/ctl.conf.d` by default. Include those fragments from `/etc/ctl.conf` using the target host's supported include mechanism before relying on dashboard-managed targets.

## Build and Install

Build on the FreeBSD target:

```sh
cargo build --release -p bnasmgr-api
cd frontend
npm install
npm run build
```

Suggested installation layout:

```text
/usr/local/sbin/bnasmgr-api
/usr/local/sbin/bnasmgr-helper
/usr/local/etc/bnasmgr/bnasmgr.db
/usr/local/etc/bnasmgr/smb4.includes
/usr/local/etc/bnasmgr/exports.d
/usr/local/www/bnasmgr
/var/run/bnasmgr/helper.sock
```

The helper socket should be owned by root and a dedicated group such as `bnasmgr`, with write access only for the API service account.

## rc.d Service

Create `/usr/local/etc/rc.d/bnasmgr`:

```sh
#!/bin/sh

# PROVIDE: bnasmgr
# REQUIRE: NETWORKING zfs
# KEYWORD: shutdown

. /etc/rc.subr

name="bnasmgr"
rcvar="bnasmgr_enable"
command="/usr/local/sbin/bnasmgr-api"
bnasmgr_user="bnasmgr"
pidfile="/var/run/${name}.pid"
command_args="--daemon"

load_rc_config $name
: ${bnasmgr_enable:="NO"}
: ${bnasmgr_env:="BNASMGR_DATABASE_URL=sqlite:///usr/local/etc/bnasmgr/bnasmgr.db?mode=rwc BNASMGR_BIND=127.0.0.1:8080"}

run_rc_command "$1"
```

Then enable it:

```sh
chmod 555 /usr/local/etc/rc.d/bnasmgr
sysrc bnasmgr_enable=YES
service bnasmgr start
```

The daemon flag is a deployment placeholder for the rc script. If supervised directly by `daemon(8)` or another runner, adapt `command_args` accordingly.

Snapshot task scheduling is enabled in the API process by default. Set `BNASMGR_SNAPSHOT_SCHEDULER=off` to disable it, or set `BNASMGR_SNAPSHOT_SCHEDULER_SECONDS=60` to control how often the API scans for due tasks. Values below 10 seconds are ignored.

## HTTPS

Use a certificate issued by an internal CA or ACME DNS challenge for the NAS hostname. Do not expose the dashboard over plain HTTP on the LAN.

### Option A: nginx TLS Termination

Terminate TLS with nginx or another reverse proxy. Bind the Rust API to loopback and expose HTTPS on the LAN:

```nginx
server {
    listen 443 ssl;
    server_name nas.lan;

    ssl_certificate /usr/local/etc/ssl/bnasmgr/fullchain.pem;
    ssl_certificate_key /usr/local/etc/ssl/bnasmgr/privkey.pem;

    root /usr/local/www/bnasmgr;

    location /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        try_files $uri /index.html;
    }
}
```

This is the preferred production layout when serving the built Svelte files from `/usr/local/www/bnasmgr`.

### Option B: Direct API TLS

The Rust API can also bind HTTPS directly when a certificate and key are configured:

```sh
BNASMGR_DATABASE_URL='sqlite:///usr/local/etc/bnasmgr/bnasmgr.db?mode=rwc' \
BNASMGR_BIND=0.0.0.0:8443 \
BNASMGR_TLS_CERT=/usr/local/etc/ssl/bnasmgr/fullchain.pem \
BNASMGR_TLS_KEY=/usr/local/etc/ssl/bnasmgr/privkey.pem \
/usr/local/sbin/bnasmgr-api
```

If using direct TLS, either serve the frontend through a separate HTTPS static file server or set `BNASMGR_STATIC_DIR` so `bnasmgr-api` serves the built frontend itself. The recommended production layout remains nginx serving the frontend and proxying `/api/`, but direct static serving is available for simpler deployments.

To serve the built Svelte frontend directly from `bnasmgr-api`, set `BNASMGR_STATIC_DIR` to the directory containing `index.html`. Unknown non-API routes fall back to `index.html` for client-side routing, while unknown `/api/*` routes still return JSON 404 responses:

```sh
BNASMGR_DATABASE_URL='sqlite:///usr/local/etc/bnasmgr/bnasmgr.db?mode=rwc' \
BNASMGR_BIND=0.0.0.0:8443 \
BNASMGR_TLS_CERT=/usr/local/etc/ssl/bnasmgr/fullchain.pem \
BNASMGR_TLS_KEY=/usr/local/etc/ssl/bnasmgr/privkey.pem \
BNASMGR_STATIC_DIR=/usr/local/www/bnasmgr \
/usr/local/sbin/bnasmgr-api
```

### rc.d HTTPS Environment

For direct API TLS in the rc.d service, include the TLS paths in `bnasmgr_env`:

```sh
: ${bnasmgr_env:="BNASMGR_DATABASE_URL=sqlite:///usr/local/etc/bnasmgr/bnasmgr.db?mode=rwc BNASMGR_BIND=0.0.0.0:8443 BNASMGR_TLS_CERT=/usr/local/etc/ssl/bnasmgr/fullchain.pem BNASMGR_TLS_KEY=/usr/local/etc/ssl/bnasmgr/privkey.pem"}
```

For nginx TLS termination, keep `BNASMGR_BIND=127.0.0.1:8080` and omit `BNASMGR_TLS_CERT` and `BNASMGR_TLS_KEY`.

## Helper Operation Policy

The helper allowlist covers:

- ZFS dataset, quota, and snapshot operations.
- Service status and `start`, `stop`, `restart` through `service(8)`.
- Samba metadata and password-management integration points.
- NFS export metadata integration points.
- Log reads from known system log locations.

Arguments are passed as process arguments, not shell strings. Inputs containing shell-control characters are rejected before command construction.

Service control is restricted to the intended NAS services: `zfs`, `samba_server`, `nfsd`, `mountd`, `rpcbind`, `ctld`, and `syslogd`. Quota values are limited to `none`, `off`, or numeric values with optional binary-size suffixes.

Storage and snapshot reads are parsed from `zpool list -Hp`, `zfs list -Hp`, and `zfs list -Hp -t snapshot` output. Service status reads are normalized so stopped services show as dashboard state instead of helper transport failures.

Log reads tail known log files and support service, severity, search text, and date-range filters. FreeBSD syslog-style timestamps do not carry a year, so they are interpreted with the current year.

Samba server settings and Samba/NFS share metadata are persisted by the API and applied through typed helper operations. The FreeBSD command backend validates the requested settings/share/export data, writes helper-owned fragments, and reloads the relevant service (`samba_server` or `mountd`).

Share application now uses helper-owned fragments:

- Samba global settings default to `/usr/local/etc/bnasmgr/smb4.includes/00-global.conf`.
- Samba fragments default to `/usr/local/etc/bnasmgr/smb4.includes/*.conf`.
- NFS export fragments default to `/usr/local/etc/bnasmgr/exports.d/*.exports`.
- Override these with `BNASMGR_SAMBA_INCLUDE_DIR` and `BNASMGR_NFS_EXPORTS_DIR` in the helper environment.

Wire Samba by including the generated fragment set from `smb4.conf` according to the Samba version installed on the host. Wire NFS by configuring the system export workflow to consume the generated export fragments before `mountd` reloads. The helper writes each fragment through a temporary file and atomic rename before reloading the relevant service.

## Operational Safety

Snapshot delete and rollback are destructive. The UI requires confirmation and the backend requires a changed admin password before those actions are accepted.

Snapshot delete and rollback also require `X-BNASMGR-CONFIRM` to exactly match the target snapshot name. This protects the API if a request bypasses the browser confirmation dialog.

File-level snapshot restore uses the dataset snapshot mount at `<mountpoint>/.zfs/snapshot/<snapshot-name>` and copies selected relative file paths back into the live dataset. It does not roll back the entire dataset. Restore requests still require `X-BNASMGR-CONFIRM` because existing live files can be overwritten.

UPS shutdown execution requires the dashboard policy to be enabled and an exact `X-BNASMGR-CONFIRM: EXECUTE UPS SHUTDOWN` header. The helper accepts only `shutdown -p now`, `shutdown -h now`, or `shutdown -p|-h +minutes` up to 1440 minutes.

Network configuration writes use `sysrc ifconfig_<iface>=...` for DHCP/static IPv4 settings, optionally update `defaultrouter`, then restart the target interface with `service netif restart <iface>`. DNS resolver writes render validated nameserver/search-domain settings to `/etc/resolv.conf`; override the target path with `BNASMGR_RESOLV_CONF` in the helper environment for staged validation. Static routes are written through `static_routes` and `route_*` rc.conf entries before `service routing restart`. Validate these workflows from console access on the target host before managing the active administrative interface.

Dashboard users are separate from FreeBSD users and Samba users. Use dashboard users only for web access; use the local identity and Samba user panels for storage identities.

Dashboard admins can create users, promote/demote roles, reset temporary passwords, and delete other dashboard users. The API prevents deleting your own account and prevents deleting or demoting the last remaining dashboard admin.

Local Unix users and groups are managed through `pw` helper operations. Samba users are storage identities, not dashboard identities. The dashboard can set or rotate a Samba password through `smbpasswd -a -s`, enable/disable the user, and delete the Samba account through `pdbedit -x -u`. Passwords are provided through stdin and are redacted from helper history before the operation is persisted.

Directory service settings capture LDAP or Active Directory connection metadata, render `/usr/local/etc/nslcd.conf`, and restart `nslcd` through the helper after saving. Override the rendered config path with `BNASMGR_NSLCD_CONF` for staged validation. Before relying on directory-backed identity lookup, wire and validate the target host's NSS/PAM settings, certificate trust, and any Active Directory join steps outside the dashboard.

Configuration backup/export covers saved dashboard operational state only. It excludes sessions, audit/helper history, notification delivery attempts, and dashboard password hashes. SMTP passwords are redacted from exported alert notification settings and must be re-entered after restore if email delivery uses authentication.

The audit screen shows both high-level audit events and raw helper operation history, which is useful for reviewing privileged operations and failed helper requests.

Primary references:

- FreeBSD ZFS Handbook: https://docs.freebsd.org/en/books/handbook/zfs/
- FreeBSD Network Servers Handbook: https://docs.freebsd.org/en/books/handbook/network-servers/
- FreeBSD service and rc.d Handbook: https://docs.freebsd.org/en/books/handbook/config/
