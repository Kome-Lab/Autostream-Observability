# AutoStream Observability Host Install

This archive contains the Linux binary, systemd example, and placeholder environment file for AutoStream Observability.

## Requirements

- Linux amd64 or arm64 matching the archive name.
- A dedicated `autostream` user and group.
- Authenticated `gh`, `jq`, `sha256sum`, and `curl` for release verification, plus
  `/usr/bin/mariadb-dump` for the required pre-update backup.
- Database and notification provider settings supplied outside Git.
- Network access to the Control Panel and monitored services.

## Install a verified managed release

The systemd unit runs the binary through
`/opt/autostream/observability/current`. Seed that link from the same immutable
release manifest and checksum that supplied the archive. `autostream-updater`
refuses an unseeded target because it would have no verified rollback release.
When replacing an existing Observability service manually, record the current
link and complete a database backup before running the switch below.

```bash
set -euo pipefail
VERSION="${VERSION:?export VERSION=vX.Y.Z before continuing}"
ARCH="${ARCH:-amd64}"
ASSET="autostream-observability_${VERSION}_linux_${ARCH}.tar.gz"
ARTIFACT_ROOT=/opt/autostream/releases

sudo install -d -o root -g root -m 0755 "$ARTIFACT_ROOT"
sudo install -d -o "$USER" -g "$USER" -m 0755 "$ARTIFACT_ROOT/artifacts"
gh release download "$VERSION" \
  --repo Kome-Lab/Autostream-Observability \
  --pattern "$ASSET" \
  --pattern "$ASSET.sha256" \
  --pattern release-manifest.json \
  --pattern release-manifest.json.sha256 \
  --dir "$ARTIFACT_ROOT/artifacts" \
  --clobber
(cd "$ARTIFACT_ROOT/artifacts" && sha256sum --check --strict "$ASSET.sha256")
(cd "$ARTIFACT_ROOT/artifacts" && sha256sum --check --strict release-manifest.json.sha256)

DIGEST="$(awk 'NR == 1 { print $1 }' "$ARTIFACT_ROOT/artifacts/$ASSET.sha256")"
[[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]]
jq -e --arg version "$VERSION" --arg asset "$ASSET" --arg sha "$DIGEST" \
  '.schema_version == 1 and .release_id == $version and .channel == "host" and
   ([.components[] | select(.service == "observability" and .source_version == $version) |
     .artifacts[] | select(.name == $asset and .sha256 == $sha)] | length == 1)' \
  "$ARTIFACT_ROOT/artifacts/release-manifest.json"

RELEASE_ROOT=/opt/autostream/observability/releases
RELEASE_DIR="$RELEASE_ROOT/${VERSION}-${DIGEST:0:12}"
CURRENT_LINK=/opt/autostream/observability/current
sudo test ! -e "$RELEASE_DIR"
sudo install -d -o root -g root -m 0755 "$RELEASE_DIR"
sudo tar --no-same-owner --strip-components=1 -xzf "$ARTIFACT_ROOT/artifacts/$ASSET" -C "$RELEASE_DIR"
(cd "$RELEASE_DIR" && sha256sum --check --strict checksums.txt)
printf '%s\n' "$DIGEST" | sudo tee "$RELEASE_DIR/.artifact-sha256" >/dev/null
printf '%s\n' "$VERSION" | sudo tee "$RELEASE_DIR/.version" >/dev/null
sudo chown root:root "$RELEASE_DIR/.artifact-sha256" "$RELEASE_DIR/.version"
sudo chmod 0444 "$RELEASE_DIR/.artifact-sha256" "$RELEASE_DIR/.version"
sudo /usr/sbin/runuser -u autostream -- "$RELEASE_DIR/bin/autostream-observability" --version | grep -F -- "$VERSION"

sudo ln -s "$RELEASE_DIR" "${CURRENT_LINK}.next"
sudo mv -Tf "${CURRENT_LINK}.next" "$CURRENT_LINK"
sudo ln -sfn "$CURRENT_LINK/bin/autostream-observability" /usr/local/bin/autostream-observability
sudo ln -sfn /usr/local/bin/autostream-observability /usr/local/bin/observability
sudo install -d -o autostream -g autostream /var/lib/autostream/observability
sudo install -d -o root -g root -m 0750 /etc/autostream
sudo install -o root -g root -m 0644 "$RELEASE_DIR/systemd/autostream-observability.service.example" /etc/systemd/system/autostream-observability.service
if ! sudo test -e /etc/autostream/observability.env; then
  sudo install -o root -g root -m 0640 "$RELEASE_DIR/.env.example" /etc/autostream/observability.env
else
  echo "preserving existing /etc/autostream/observability.env; review .env.example for new settings"
fi
```

## Prepare the updater backup command

An Observability target is fail-closed unless its fixed backup command exists
and succeeds. Install the verified script from this release and prepare its
private directory and MariaDB client defaults:

```bash
set -euo pipefail
RELEASE_DIR="$(readlink -f /opt/autostream/observability/current)"
test -x "$RELEASE_DIR/backup/autostream-backup-observability"
sudo install -d -o root -g root -m 0700 /var/backups/autostream/observability
sudo install -o root -g root -m 0700 "$RELEASE_DIR/backup/autostream-backup-observability" /usr/local/sbin/autostream-backup-observability
sudo install -d -o root -g root -m 0750 /etc/autostream
if ! sudo test -e /etc/autostream/mariadb-backup.cnf; then
  sudo install -o root -g root -m 0600 /dev/null /etc/autostream/mariadb-backup.cnf
else
  echo "preserving existing /etc/autostream/mariadb-backup.cnf"
fi
sudo chown root:root /etc/autostream/mariadb-backup.cnf
sudo chmod 0600 /etc/autostream/mariadb-backup.cnf
```

Set the root-only defaults file to a dedicated backup account. A shared host
may reuse the same account/file used by the Control Panel if that account also
has the Observability grant:

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
second `backup_argv` item. In this example, replace the default with the final
path component of the real `DATABASE_URL` when they differ:

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

test "$(sudo stat -c '%u:%a' /etc/autostream/mariadb-backup.cnf)" = "0:600"
test "$(sudo stat -c '%u:%a' /usr/local/sbin/autostream-backup-observability)" = "0:700"
sudo /usr/local/sbin/autostream-backup-observability "$DATABASE_NAME"
printf 'Use this exact database name as the second backup_argv item: %s\n' "$DATABASE_NAME"
```

Copy the value printed by that command into the root-owned host policy. It is
never supplied by an update job or the browser:

```json
"backup_argv": [
  "/usr/local/sbin/autostream-backup-observability",
  "replace-with-the-exact-DATABASE_NAME-printed-above"
]
```

The script uses `umask 077` and atomically renames a timestamped, non-empty
dump only after `mariadb-dump` succeeds. Configure retention and encrypted
off-host copying separately. The updater rejects a missing backup executable,
a symlink, or a path that is not root-owned or is writable by group/other
users; a nonzero dump exit aborts the update before stopping Observability.

Edit `/etc/autostream/observability.env` with real environment-specific values, then run:

```bash
set -euo pipefail
VERSION="${VERSION:?export VERSION=vX.Y.Z before continuing}"
sudo systemctl daemon-reload
sudo systemctl enable autostream-observability
sudo systemctl restart autostream-observability
PID="$(sudo systemctl show --property=MainPID --value autostream-observability)"
EXPECTED="$(sudo readlink -f /opt/autostream/observability/current/bin/autostream-observability)"
test "$(sudo readlink -f "/proc/$PID/exe")" = "$EXPECTED"
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8082/health >/dev/null
test "$(curl --fail --silent --show-error --max-time 10 \
  http://127.0.0.1:8082/updater/version | jq -r '.version')" = "$VERSION"
```

Use the host's configured loopback port if it differs from `8082`.
`/updater/version` is the unauthenticated, minimal endpoint used only to prove
the running binary's embedded release version to the update helper. Block this
exact path at any public reverse proxy.

Do not fabricate `.artifact-sha256` or `.version` from an unverified local
binary. Releases without `release-manifest.json` remain manual-only; publish a
new release instead of modifying an existing release asset.

Do not commit real `.env` files, provider credentials, tokens, logs, screenshots, or verification record.
