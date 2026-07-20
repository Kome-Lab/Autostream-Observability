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

REMEDIATION_MODE=suggest_only
TZ=Asia/Tokyo
```

Control Panel calls Observability with the Node Runtime Token stored in the Panel-generated `AUTOSTREAM_NODE_CONFIG`. Do not configure a separate Observability admin token or direct ingest token.

The Observability service does not serve a browser UI. `GET /` and `GET /status` return safe operator status JSON. `GET /updater/version` returns only the embedded release version for the loopback update helper. API data such as `GET /metrics` is token protected and is normally read through the Control Panel `/observability/metrics` proxy. A browser request to `/metrics` without the Node Runtime Token should return an authorization error.

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
