# AutoStream Observability Host Install

This archive contains the Linux binary, systemd example, and placeholder environment file for AutoStream Observability.

## Requirements

- Linux amd64 or arm64 matching the archive name.
- Root access through `sudo`; the installer creates the `autostream` system
  account when it is absent.
- `jq`, `sha256sum`, `tar`, systemd, and `/usr/bin/mariadb-dump`. `curl` is used
  by the post-start health check.
- Authenticated GitHub CLI (`gh`) on the server for the required
  release-manifest attestation check.
- Database and notification provider settings supplied outside Git.
- Network access to the Control Panel and monitored services.

## Install a verified managed release

Download these four assets from the same authenticated official GitHub Release
to `/tmp`:

- `autostream-observability_vX.Y.Z_linux_amd64.tar.gz`
- `autostream-observability_vX.Y.Z_linux_amd64.tar.gz.sha256`
- `release-manifest.json`
- `release-manifest.json.sha256`

Copy them into a root-owned staging directory:

```bash
sudo install -d -o root -g root -m 0755 /opt/autostream/releases
sudo install -d -o root -g root -m 0755 /opt/autostream/releases/artifacts
sudo install -o root -g root -m 0644 /tmp/autostream-observability_vX.Y.Z_linux_amd64.tar.gz /opt/autostream/releases/artifacts/autostream-observability_vX.Y.Z_linux_amd64.tar.gz
sudo install -o root -g root -m 0644 /tmp/autostream-observability_vX.Y.Z_linux_amd64.tar.gz.sha256 /opt/autostream/releases/artifacts/autostream-observability_vX.Y.Z_linux_amd64.tar.gz.sha256
sudo install -o root -g root -m 0644 /tmp/release-manifest.json /opt/autostream/releases/artifacts/release-manifest.json
sudo install -o root -g root -m 0644 /tmp/release-manifest.json.sha256 /opt/autostream/releases/artifacts/release-manifest.json.sha256
cd /opt/autostream/releases/artifacts
```

As the ordinary login user, verify both the root-owned archive and manifest
copies. Do not continue if either command fails:

```bash
gh attestation verify autostream-observability_vX.Y.Z_linux_amd64.tar.gz --repo Kome-Lab/Autostream-Observability --signer-workflow Kome-Lab/Autostream-Observability/.github/workflows/release-host.yml --deny-self-hosted-runners
gh attestation verify release-manifest.json --repo Kome-Lab/Autostream-Observability --signer-workflow Kome-Lab/Autostream-Observability/.github/workflows/release-host.yml --deny-self-hosted-runners
```

The direct archive attestation authenticates the installer before root executes
it. The separately attested manifest binds that same archive by name, size,
digest, version, service, and architecture. Extract the root-owned archive,
then run its bundled installer:

```bash
sudo test ! -e autostream-observability_vX.Y.Z_linux_amd64
sudo test ! -L autostream-observability_vX.Y.Z_linux_amd64
sudo tar --no-same-owner --no-same-permissions -xzf autostream-observability_vX.Y.Z_linux_amd64.tar.gz
cd autostream-observability_vX.Y.Z_linux_amd64
sudo ./install-autostream-observability
```

The installer verifies the archive checksum, release-manifest tuple, archive
layout, inner checksums, architecture, and embedded binary version. It creates
the `autostream` system account when needed, prepares the state and backup
directories, preserves an existing `/etc/autostream/observability.env`
byte-for-byte, installs the systemd unit, and runs `systemctl daemon-reload`.
It does not enable, start, or restart the service.

`/usr/local/bin/autostream-observability` and `/usr/local/bin/observability`
remain the stable operator-facing commands. The verified releases, markers,
and `current` link under `/opt/autostream/observability` are installer-owned
rollback state; do not create or edit them manually.

When migrating a direct installation, the installer retains the replaced
regular binaries, unit, and backup executable under the root-only
`/var/backups/autostream/install-migrations/observability` tree, outside the
service-writable state directory. Its final message prints `restart` for a
service that was already active, or `enable --now` for a fresh or inactive
installation; it never runs either command automatically.

## Configure the updater backup command

The installer places the verified backup executable at
`/usr/local/sbin/autostream-backup-observability`, prepares
`/var/backups/autostream/observability`, and safely creates an empty
`/etc/autostream-local-executor/mariadb-backup.cnf` only when it is absent.
Existing credentials are preserved byte-for-byte.

Set the root-only Local Executor defaults file to a dedicated backup account.
Keep it separate from the service environment under `/etc/autostream`; never
copy a service `DATABASE_URL` or application database credentials into it. A
shared host may reuse this account/file for the Control Panel if that account
also has the Observability grant:

```ini
[client]
host=127.0.0.1
port=3306
protocol=tcp
user=autostream_backup
password=replace-with-a-long-random-password
```

From an interactive MariaDB root session, create the account if necessary.
Replace the password before executing the `CREATE USER` statement; do not put
the real password in a shell command or shell history:

```sql
CREATE USER IF NOT EXISTS 'autostream_backup'@'127.0.0.1' IDENTIFIED BY 'replace-with-a-long-random-password';
```

The script defaults to `autostream_observability`. If `DATABASE_URL` uses a
different database, pass its exact name as the single fixed argument. The name
must contain 1-64 ASCII letters, digits, underscores, or hyphens and must start
with a letter or digit.

Select the database name once below, then keep the same shell open. The same
exact `DATABASE_NAME` must be used for the MariaDB grant, the real dump, and the
server-owned target setting. In this example, replace the default with the
final path component of the real `DATABASE_URL` when they differ:

```bash
set -euo pipefail
DATABASE_NAME='autostream_observability'
if [[ ! "$DATABASE_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]]; then
  echo "Invalid DATABASE_NAME" >&2
  exit 1
fi

sudo mariadb <<SQL
GRANT SELECT, SHOW VIEW, TRIGGER ON \`${DATABASE_NAME}\`.* TO 'autostream_backup'@'127.0.0.1';
SQL

test "$(sudo stat -c '%u:%a' /etc/autostream-local-executor/mariadb-backup.cnf)" = "0:600"
test "$(sudo stat -c '%u:%a' /usr/local/sbin/autostream-backup-observability)" = "0:700"
sudo /usr/local/sbin/autostream-backup-observability "$DATABASE_NAME"
printf 'Database name to save in System Updates: %s\n' "$DATABASE_NAME"
```

Save the printed value for the Observability target in **Application Info > System Updates**.
It is persisted as the server-owned `database_name` and
combined only with the compiled fixed backup executable. Do not edit `/etc/autostream-local-executor/policy.json`;
rerun the Host Agent configure flow after saving so it can stage the canonical
root policy.

The script uses `umask 077` and atomically renames a timestamped, non-empty
dump only after `mariadb-dump` succeeds. Configure retention and encrypted
off-host copying separately. The updater rejects a missing backup executable,
a symlink, or a path that is not root-owned or is writable by group/other
users; a nonzero dump exit aborts the update before stopping Observability.

Edit `/etc/autostream/observability.env` with real environment-specific values.
`OBSERVABILITY_BIND_ADDR` accepts an arbitrary unprivileged port from `1024`
through `65535`; the shipped systemd env uses the standard IPv4 loopback value
`127.0.0.1:8082`. The binary retains the legacy `127.0.0.1:8080` fallback only
when the variable is absent, so upgrading an older installation does not move
its port. The systemd unit does not hard-code a port. An invalid address or an
out-of-range port makes the service fail closed before it connects to MariaDB.

Keep this root-owned file at mode `0640` and include
`AUTOSTREAM_CONFIG_REVISION=1`. The revision must be a positive integer;
increment it after applying a new service configuration. Invalid values stop
Observability before it connects to MariaDB or starts serving HTTP.

For a fresh or currently stopped installation, edit the environment file and
start the service:

```bash
sudo vi /etc/autostream/observability.env
sudo systemctl enable --now autostream-observability
sudo systemctl status --no-pager autostream-observability
autostream-observability --version
curl --fail --silent --show-error http://127.0.0.1:8082/health
curl --fail --silent --show-error http://127.0.0.1:8082/updater/version | jq .
```

When replacing a service that is already running, use these commands after
editing the environment file:

```bash
sudo systemctl restart autostream-observability
sudo systemctl status --no-pager autostream-observability
```

The curl examples use the default IPv4 loopback port. If
`OBSERVABILITY_BIND_ADDR` uses another port, use that configured port in both
URLs. For an IPv6 loopback such as `[::1]:18082`, use brackets in the URL:
`http://[::1]:18082/health`.

`/updater/version` is the unauthenticated, identity-bound local executor probe.
Its exact response fields are version, service_id, service_type, and config_revision.
The service ID comes from the same Control Panel node config used by
registration. Block this exact path at any public reverse proxy.

Do not fabricate `.artifact-sha256` or `.version` from a local binary. The
installer creates those markers only after verifying the immutable release
inputs. Releases without `release-manifest.json` remain manual-only; publish a
new release instead of modifying an existing release asset.

Do not commit real `.env` files, provider credentials, tokens, logs, screenshots, or verification record.
