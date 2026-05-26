# FreeBSD Deployment Notes

This MVP uses a split privilege model:

- `bnasmgr-api` runs as an unprivileged service account.
- A small root-owned helper accepts typed JSON operations over a local Unix socket.
- Mutating operations require a dashboard admin whose initial password has been changed.
- Dashboard passwords are stored with Argon2id.
- Every helper operation records audit and helper history entries in SQLite.

## Packages and Services

Install the baseline platform components used by the dashboard:

```sh
pkg install sqlite3 samba419 rust npm nginx
```

Install optional host integrations for the features you plan to validate:

```sh
pkg install smartmontools nut openldap26-client nss-pam-ldapd
```

Directory service package names can vary by FreeBSD quarterly branch and site policy. Validate the installed LDAP/NSS/PAM tooling on the target host before enabling dashboard-managed directory authentication.

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
/var/db/bnasmgr/bnasmgr.db
/usr/local/etc/bnasmgr/smb4.includes
/usr/local/etc/bnasmgr/exports.d
/usr/local/www/bnasmgr
/var/run/bnasmgr/helper.sock
```

The helper socket should be owned by root and a dedicated group such as `bnasmgr`, with write access only for the API service account.

Create the service account, group, persistent configuration directory, and runtime socket directory before starting services:

```sh
pw groupadd bnasmgr
pw useradd bnasmgr -g bnasmgr -d /nonexistent -s /usr/sbin/nologin -c "bnasmgr API"
install -d -o root -g bnasmgr -m 2750 /var/run/bnasmgr
install -d -o bnasmgr -g bnasmgr -m 0750 /var/db/bnasmgr
install -d -o root -g wheel -m 0755 /usr/local/etc/bnasmgr
```

The SQLite database belongs under `/var/db/bnasmgr` so the unprivileged API can create the database and SQLite journal files without being able to write helper-managed service fragments. The helper-managed config root under `/usr/local/etc/bnasmgr` stays root-owned.

The helper sets the socket mode to `0660` after binding. The setgid bit on `/var/run/bnasmgr` keeps the recreated socket in the `bnasmgr` group, while the directory mode prevents the API service account from replacing entries in that directory.

For production FreeBSD operation, run `bnasmgr-helper` with `BNASMGR_HELPER_BACKEND=freebsd` and set the same `BNASMGR_HELPER_SOCKET` path for both `bnasmgr-helper` and `bnasmgr-api`. If `BNASMGR_HELPER_SOCKET` is omitted, the API uses the in-process mock helper backend for development.

## rc.d Services

Create `/usr/local/etc/rc.d/bnasmgr_helper` for the privileged helper:

```sh
#!/bin/sh

# PROVIDE: bnasmgr_helper
# REQUIRE: NETWORKING zfs
# KEYWORD: shutdown

. /etc/rc.subr

name="bnasmgr_helper"
rcvar="bnasmgr_helper_enable"
command="/usr/sbin/daemon"
procname="/usr/local/sbin/bnasmgr-helper"
pidfile="/var/run/${name}.pid"
command_args="-p ${pidfile} ${procname}"
start_precmd="${name}_prestart"

bnasmgr_helper_prestart()
{
    install -d -o root -g bnasmgr -m 2750 /var/run/bnasmgr
}

load_rc_config $name
: ${bnasmgr_helper_enable:="NO"}
: ${bnasmgr_helper_env:="BNASMGR_HELPER_BACKEND=freebsd BNASMGR_HELPER_SOCKET=/var/run/bnasmgr/helper.sock"}

run_rc_command "$1"
```

Create `/usr/local/etc/rc.d/bnasmgr`:

```sh
#!/bin/sh

# PROVIDE: bnasmgr
# REQUIRE: NETWORKING zfs bnasmgr_helper
# KEYWORD: shutdown

. /etc/rc.subr

name="bnasmgr"
rcvar="bnasmgr_enable"
command="/usr/sbin/daemon"
procname="/usr/local/sbin/bnasmgr-api"
bnasmgr_user="bnasmgr"
pidfile="/var/run/${name}.pid"
command_args="-p ${pidfile} -u ${bnasmgr_user} ${procname}"
start_precmd="${name}_prestart"

bnasmgr_prestart()
{
    install -d -o bnasmgr -g bnasmgr -m 0750 /var/db/bnasmgr
}

load_rc_config $name
: ${bnasmgr_enable:="NO"}
: ${bnasmgr_env:="BNASMGR_DATABASE_URL=sqlite:///var/db/bnasmgr/bnasmgr.db?mode=rwc BNASMGR_BIND=127.0.0.1:8080 BNASMGR_HELPER_SOCKET=/var/run/bnasmgr/helper.sock"}

run_rc_command "$1"
```

Then enable them:

```sh
chmod 555 /usr/local/etc/rc.d/bnasmgr_helper
chmod 555 /usr/local/etc/rc.d/bnasmgr
sysrc bnasmgr_helper_enable=YES
sysrc bnasmgr_enable=YES
service bnasmgr_helper start
service bnasmgr start
```

The rc.d examples use `daemon(8)` to supervise the foreground Rust binaries. If you use another supervisor, keep the same environment variables and helper socket permissions.

Snapshot task scheduling is enabled in the API process by default. Set `BNASMGR_SNAPSHOT_SCHEDULER=off` to disable it, or set `BNASMGR_SNAPSHOT_SCHEDULER_SECONDS=60` to control how often the API scans for due tasks. Values below 10 seconds are ignored.

Replication task scheduling is also enabled in the API process by default. Set `BNASMGR_REPLICATION_SCHEDULER=off` to disable it, or set `BNASMGR_REPLICATION_SCHEDULER_SECONDS=60` to control the scan interval. Values below 10 seconds are ignored.

Alert notification delivery is enabled by default and scans every five minutes. Set `BNASMGR_ALERT_NOTIFIER=off` to disable it, or set `BNASMGR_ALERT_NOTIFIER_SECONDS=300` to change the scan interval. Values below 30 seconds are ignored.

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
BNASMGR_DATABASE_URL='sqlite:///var/db/bnasmgr/bnasmgr.db?mode=rwc' \
BNASMGR_BIND=0.0.0.0:8443 \
BNASMGR_HELPER_SOCKET=/var/run/bnasmgr/helper.sock \
BNASMGR_TLS_CERT=/usr/local/etc/ssl/bnasmgr/fullchain.pem \
BNASMGR_TLS_KEY=/usr/local/etc/ssl/bnasmgr/privkey.pem \
/usr/local/sbin/bnasmgr-api
```

If using direct TLS, either serve the frontend through a separate HTTPS static file server or set `BNASMGR_STATIC_DIR` so `bnasmgr-api` serves the built frontend itself. The recommended production layout remains nginx serving the frontend and proxying `/api/`, but direct static serving is available for simpler deployments.

To serve the built Svelte frontend directly from `bnasmgr-api`, set `BNASMGR_STATIC_DIR` to the directory containing `index.html`. Unknown non-API routes fall back to `index.html` for client-side routing, while unknown `/api/*` routes still return JSON 404 responses:

```sh
BNASMGR_DATABASE_URL='sqlite:///var/db/bnasmgr/bnasmgr.db?mode=rwc' \
BNASMGR_BIND=0.0.0.0:8443 \
BNASMGR_HELPER_SOCKET=/var/run/bnasmgr/helper.sock \
BNASMGR_TLS_CERT=/usr/local/etc/ssl/bnasmgr/fullchain.pem \
BNASMGR_TLS_KEY=/usr/local/etc/ssl/bnasmgr/privkey.pem \
BNASMGR_STATIC_DIR=/usr/local/www/bnasmgr \
/usr/local/sbin/bnasmgr-api
```

### rc.d HTTPS Environment

For direct API TLS in the rc.d service, include the TLS paths in `bnasmgr_env`:

```sh
: ${bnasmgr_env:="BNASMGR_DATABASE_URL=sqlite:///var/db/bnasmgr/bnasmgr.db?mode=rwc BNASMGR_BIND=0.0.0.0:8443 BNASMGR_HELPER_SOCKET=/var/run/bnasmgr/helper.sock BNASMGR_TLS_CERT=/usr/local/etc/ssl/bnasmgr/fullchain.pem BNASMGR_TLS_KEY=/usr/local/etc/ssl/bnasmgr/privkey.pem"}
```

For nginx TLS termination, keep `BNASMGR_BIND=127.0.0.1:8080` and omit `BNASMGR_TLS_CERT` and `BNASMGR_TLS_KEY`.

## Helper Operation Policy

The helper allowlist covers:

- ZFS dataset, quota, and snapshot operations.
- ZFS pool scrub status and start/stop operations.
- Local and remote ZFS replication send/receive operations.
- Read-only host, network interface, UPS, SMART, and log inventory.
- Network interface, DNS resolver, and static route configuration.
- Service status and `start`, `stop`, `restart` through `service(8)`.
- Samba metadata and password-management integration points.
- NFS export metadata integration points.
- iSCSI `ctl.conf` fragment integration points.
- Local Unix user/group management through `pw(8)`.
- Directory service validation, `nslcd.conf` rendering, optional NSS/PAM file rendering, and Active Directory join/leave commands.
- UPS shutdown execution through a restricted `shutdown(8)` command shape.
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

iSCSI target metadata is persisted by the API and applied through typed helper operations. The FreeBSD command backend writes helper-owned `ctl.conf` fragments under `/usr/local/etc/bnasmgr/ctl.conf.d` by default and reloads `ctld`. Override the fragment root with `BNASMGR_ISCSI_INCLUDE_DIR` in the helper environment for staged validation.

Replication tasks create task-owned `repl-*` snapshots, use the newest prior local `repl-*` snapshot as an incremental base when one exists, and prune older local replication snapshots by the configured retention count. Remote replication invokes `zfs send` locally and receives through `ssh <remote_user>@<remote_host> zfs receive`; validate SSH keys, dataset permissions, and receive targets on disposable datasets before enabling scheduled remote replication.

## Operational Safety

Snapshot delete and rollback are destructive. The UI requires confirmation and the backend requires a changed admin password before those actions are accepted.

Snapshot delete and rollback also require `X-BNASMGR-CONFIRM` to exactly match the target snapshot name. This protects the API if a request bypasses the browser confirmation dialog.

File-level snapshot restore uses the dataset snapshot mount at `<mountpoint>/.zfs/snapshot/<snapshot-name>` and copies selected relative file paths back into the live dataset. It does not roll back the entire dataset. Restore requests still require `X-BNASMGR-CONFIRM` because existing live files can be overwritten.

UPS shutdown execution requires the dashboard policy to be enabled and an exact `X-BNASMGR-CONFIRM: EXECUTE UPS SHUTDOWN` header. The helper accepts only `shutdown -p now`, `shutdown -h now`, or `shutdown -p|-h +minutes` up to 1440 minutes.

Network configuration writes use `sysrc ifconfig_<iface>=...` for DHCP/static IPv4 settings, optionally update `defaultrouter`, then restart the target interface with `service netif restart <iface>`. DNS resolver writes render validated nameserver/search-domain settings to `/etc/resolv.conf`; override the target path with `BNASMGR_RESOLV_CONF` in the helper environment for staged validation. Static routes are written through `static_routes` and `route_*` rc.conf entries before `service routing restart`. Validate these workflows from console access on the target host before managing the active administrative interface.

Dashboard users are separate from FreeBSD users and Samba users. Use dashboard users only for web access; use the local identity and Samba user panels for storage identities.

Dashboard admins can create users, promote/demote roles, reset temporary passwords, and delete other dashboard users. The API prevents deleting your own account and prevents deleting or demoting the last remaining dashboard admin.

Local Unix users and groups are managed through `pw` helper operations. Samba users are storage identities, not dashboard identities. The dashboard can set or rotate a Samba password through `smbpasswd -a -s`, enable/disable the user, and delete the Samba account through `pdbedit -x -u`. Passwords are provided through stdin and are redacted from helper history before the operation is persisted.

Directory service settings capture LDAP or Active Directory connection metadata, render `/usr/local/etc/nslcd.conf`, and restart `nslcd` through the helper after saving. Admins can optionally provide a CA certificate file path for LDAP trust, which is rendered as `tls_cacertfile` and passed to validation probes as `openssl s_client -CAfile`. Admins can also let the helper render NSS and PAM wiring for directory-backed identity lookup and authentication. The default target paths are `/etc/nsswitch.conf` and `/etc/pam.d/system`; override them with `BNASMGR_NSSWITCH_CONF` and `BNASMGR_PAM_SYSTEM_CONF` for staged validation, and override `nslcd.conf` with `BNASMGR_NSLCD_CONF`. The dashboard validation action runs `service nslcd status` for plain LDAP, an `openssl s_client` certificate-verifying probe for LDAPS or StartTLS-required LDAP, and `net ads testjoin` for Active Directory settings. Active Directory join runs `net ads join -U <username>` with the provided password sent over stdin and redacted from helper history. Active Directory leave runs `net ads leave`, optionally with `-U <username>` and a redacted stdin password. Validate NSS/PAM and domain join or leave changes from console access on the target host before relying on directory logins.

Configuration backup/export covers saved dashboard operational state only. It excludes sessions, audit/helper history, notification delivery attempts, and dashboard password hashes. SMTP passwords are redacted from exported alert notification settings and must be re-entered after restore if email delivery uses authentication.

The audit screen shows both high-level audit events and raw helper operation history, which is useful for reviewing privileged operations and failed helper requests.

Primary references:

- FreeBSD ZFS Handbook: https://docs.freebsd.org/en/books/handbook/zfs/
- FreeBSD Network Servers Handbook: https://docs.freebsd.org/en/books/handbook/network-servers/
- FreeBSD service and rc.d Handbook: https://docs.freebsd.org/en/books/handbook/config/
