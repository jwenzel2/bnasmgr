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
- `/api/users` for listing, creating, deleting, role changes, and password resets
- `/api/storage/*`
- `/api/snapshots/*`
- `/api/shares/samba/*`
- `/api/shares/nfs/*`
- `/api/services/*`
- `/api/logs`
- `/api/audit` and `/api/audit/helper-history`

The privileged boundary is represented by `bnasmgr-helper`. It accepts typed operations only; arbitrary shell commands are not part of the protocol. Snapshot, quota, service, Samba share, and NFS export mutations all pass through that helper path.

The FreeBSD helper adapter now normalizes `zpool`, `zfs`, `service`, and log output into the same JSON shape used by mock development mode, so the UI can switch adapters without changing API contracts.

Service control is restricted to the NAS service allowlist, and quota updates are validated before reaching the helper.

Samba storage users are managed separately from dashboard users. Samba passwords are sent to the helper over the local socket and are redacted from helper history.

Samba and NFS share application writes helper-owned config fragments atomically before service reload. The default FreeBSD fragment roots are `/usr/local/etc/bnasmgr/smb4.includes` and `/usr/local/etc/bnasmgr/exports.d`.

The log viewer supports service, severity, search text, and date-range filters. FreeBSD syslog-style timestamps are parsed using the current year.

Destructive snapshot delete and rollback calls require an `X-BNASMGR-CONFIRM` header matching the exact snapshot name, in addition to UI confirmation.

## Project Layout

- `crates/bnasmgr-api`: Axum API, SQLite persistence, session auth, audit records.
- `crates/bnasmgr-helper`: typed helper protocol, mock backend, FreeBSD command builder.
- `frontend`: Svelte dashboard.
- `docs/freebsd-deployment.md`: FreeBSD deployment and operations notes.
