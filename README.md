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
AUTOSTREAM_NODE_CONFIG=/etc/autostream-node/config.yml

DATABASE_URL=mysql://autostream_observability:<PASSWORD>@tcp(db.example.com:3306)/autostream_observability?parseTime=true
AUTOSTREAM_SECRET_ENCRYPTION_KEY=<32_BYTE_BASE64_OR_HEX_ENCRYPTION_KEY>

OBSERVABILITY_ADMIN_TOKEN_SHA256=<SHA256_OF_ADMIN_TOKEN>
OBSERVABILITY_ADMIN_TOKEN_BINDINGS=<SHA256_OF_ADMIN_TOKEN>:observability.read|observability.ingest|incidents.update|notifications.read|notifications.manage|remediation.read|remediation.approve|remediation.execute
OBSERVABILITY_REQUIRE_ADMIN_TOKEN_BINDINGS=true

REMEDIATION_MODE=suggest_only
TZ=Asia/Tokyo
```

Standard Worker and Encoder/Recorder signal ingest is proxied by the Control Panel with the admin token scope `observability.ingest`. Direct ingest token hashes are compatibility fallback only:

```text
OBSERVABILITY_INGEST_TOKEN_SHA256=<SHA256_OF_INGEST_TOKEN>
OBSERVABILITY_INGEST_TOKEN_BINDINGS=<TOKEN_SHA256>:encoder_recorder:encoder-recorder-01,<TOKEN_SHA256>:worker:worker-01
OBSERVABILITY_REQUIRE_INGEST_TOKEN_BINDINGS=true
```

Webhook URLs and SMTP passwords are stored encrypted with `AUTOSTREAM_SECRET_ENCRYPTION_KEY`. API responses and delivery history must expose only configured state, masked targets, fingerprints, status, and timestamps.

## Development

```powershell
go test ./...
go build ./...
```

## Security

- Do not log raw tokens, webhook URLs, SMTP passwords, credential-bearing URLs, or provider secrets.
- Bind admin tokens to explicit scopes and use direct ingest bindings only for compatibility fallback.
- Keep dangerous remediation actions manual unless a separate approval policy explicitly allows them.
- Apply request size limits and rate limits to sensitive endpoints.

Detailed deployment and security documentation is maintained in the `autostream-docs` repository.
