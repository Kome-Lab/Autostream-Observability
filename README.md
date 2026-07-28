# autostream-observability

Distributed observability service for AutoStream incidents, diagnostics, remediation suggestions, and notification delivery.

## Features

- Signal ingest for service health, metrics, warnings, and errors.
- Rule-based detection and incident deduplication.
- Diagnostic reports and remediation action records.
- Discord, Slack, generic webhook, and email notification channels.
- Secret-safe notification delivery history for the Control Panel.

## Configuration

```text
AUTOSTREAM_NODE_CONFIG=/etc/autostream-observability/config.yml

DATABASE_URL=mysql://autostream_observability:<PASSWORD>@tcp(db.example.com:3306)/autostream_observability?parseTime=true
AUTOSTREAM_SECRET_ENCRYPTION_KEY=<32_BYTE_BASE64_OR_HEX_ENCRYPTION_KEY>
OBSERVABILITY_BIND_ADDR=127.0.0.1:8082
AUTOSTREAM_CONFIG_REVISION=1

REMEDIATION_MODE=suggest_only
TZ=Asia/Tokyo
```

`AUTOSTREAM_CONFIG_REVISION` is a root-owned positive integer used by the local
executor to bind `/updater/version` to the applied service configuration.
It defaults to `1`; increment it after a configuration change. Invalid, signed,
fractional, padded, zero, or negative values stop Observability before it
connects to MariaDB or starts serving HTTP.

The Control Panel local executor writes managed bind/revision overrides to
`/opt/autostream/local-executor/ports/observability.env`. systemd loads this optional root-owned
sidecar after `observability.env`, so managed values win without breaking
existing hosts where the sidecar does not exist.

systemd 版の待受ポートは `/etc/autostream/observability.env` の
`OBSERVABILITY_BIND_ADDR` で変更できます。ポートは非特権範囲の
`1024`～`65535` を指定してください。標準の env ファイルは IPv4
loopback の `127.0.0.1:8082` を明示します。変数自体がない既存環境では、
アップグレードだけでポートを移動しないようバイナリの従来値
`127.0.0.1:8080` を維持します。
例えば `127.0.0.1:18082` に変更した場合、`/health` と
`/updater/version` も同じ `18082` で待ち受けます。不正な形式、範囲外、
または特権ポートを指定した場合は Observability がデータベース接続前に
起動を停止します。
IPv6 loopback を明示的に使う場合は `[::1]:18082` のように角括弧を含めて
指定し、プローブURLも `http://[::1]:18082/...` とします。

Docker 版ではホスト公開ポートを `AUTOSTREAM_OBSERVABILITY_PORT`、
コンテナ内の待受ポートを `AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT`
で個別に変更できます。既定値はそれぞれ `8082` と `8080` で、どちらも
`1024`～`65535` を使用してください。

Compose published ports are a host/reverse-proxy responsibility. The Control
Panel Updater manages only host ports `1024` through `65535`; manually
publishing a privileged or conflicting Docker host port is outside the managed
update contract.

The production health authority is the host Local Executor. These Compose files
intentionally omit an in-container `healthcheck`: the runtime image has no
purpose-built HTTP probe client, and the image contract does not add or repurpose `curl`, `wget`, or another unrelated executable solely for container health.
For managed Docker changes, the Local Executor probes the loopback published port for both `/health` and `/updater/version`; the published port is the health port.
A recreate is accepted only when health, service identity, version, and
`AUTOSTREAM_CONFIG_REVISION` match; otherwise the executor rolls back or reports
`rollback_failed`.

```powershell
$env:AUTOSTREAM_OBSERVABILITY_PORT = "18082"
$env:AUTOSTREAM_OBSERVABILITY_CONTAINER_PORT = "18080"
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Control Panel calls Observability with the Node Runtime Token stored in the Panel-generated `AUTOSTREAM_NODE_CONFIG`. Do not configure a separate Observability admin token or direct ingest token.

The Observability service does not serve a browser UI. `GET /` and `GET /status` return safe operator status JSON. `GET /updater/version` returns the embedded release version together with the Control Panel service identity and applied config revision for the loopback local executor. API data such as `GET /metrics` is token protected and is normally read through the Control Panel `/observability/metrics` proxy. A browser request to `/metrics` without the Node Runtime Token should return an authorization error.

## Platform and Metrics Reporting

The `configure` subcommand reports the node version, hostname, OS, and arch to Control Panel when it consumes the Configure Token. After the service starts with `AUTOSTREAM_NODE_CONFIG`, heartbeat reports the same platform fields plus `observability.goroutines`, heap metrics, and `observability.uptime_seconds`.

If the Node registration screen shows `OS未取得` / `Arch未取得` or no Metrics, verify that the latest `autostream-observability configure` command wrote the same path used by `AUTOSTREAM_NODE_CONFIG`, that the config is readable by the `autostream` user, and that heartbeat is succeeding in `journalctl -u autostream-observability`.

Webhook URLs and SMTP passwords are stored encrypted with `AUTOSTREAM_SECRET_ENCRYPTION_KEY`. API responses and delivery history must expose only configured state, masked targets, fingerprints, status, and timestamps.

## Development

```powershell
go test ./...
go build ./...
```

## Security

- Do not log raw tokens, webhook URLs, SMTP passwords, credential-bearing URLs, or provider secrets.
- Register the Observability node in Control Panel and keep the generated `config.yml` readable only by the service user.
- Keep dangerous remediation actions manual unless a separate approval policy explicitly allows them.
- Apply request size limits and rate limits to sensitive endpoints.

Detailed deployment and security documentation is maintained in the `autostream-docs` repository.
