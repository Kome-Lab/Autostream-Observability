# AutoStream Observability Host Install

This archive contains the Linux binary, systemd example, and placeholder environment file for AutoStream Observability.

## Requirements

- Linux amd64 or arm64 matching the archive name.
- A dedicated `autostream` user and group.
- Database and notification provider settings supplied outside Git.
- Network access to the Control Panel and monitored services.

## Install

```bash
sudo install -o root -g root -m 0755 bin/observability /usr/local/bin/observability
sudo ln -sf /usr/local/bin/observability /usr/local/bin/autostream-observability
sudo install -d -o autostream -g autostream /var/lib/autostream/observability
sudo install -o root -g root -m 0644 systemd/autostream-observability.service.example /etc/systemd/system/autostream-observability.service
sudo install -o root -g root -m 0640 .env.example /etc/autostream/observability.env
```

Edit `/etc/autostream/observability.env` with real environment-specific values, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now autostream-observability
```

Do not commit real `.env` files, provider credentials, tokens, logs, screenshots, or verification record.
