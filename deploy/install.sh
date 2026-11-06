#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$PATH:/usr/local/go/bin"

(cd "$repository_root/admin" && go build -o /tmp/hause-admin .)

id hause-admin >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin hause-admin

sudo install -m 0755 /tmp/hause-admin /usr/local/bin/hause-admin
rm /tmp/hause-admin

sudo install -m 0440 "$repository_root/deploy/hause-admin.sudoers" /etc/sudoers.d/hause-admin
sudo visudo -cf /etc/sudoers.d/hause-admin

sudo install -m 0644 "$repository_root/deploy/hause-admin.service" /etc/systemd/system/hause-admin.service
sudo systemctl daemon-reload
sudo systemctl enable hause-admin >/dev/null
sudo systemctl restart hause-admin

sudo install -m 0644 "$repository_root/deploy/Caddyfile" /etc/caddy/Caddyfile
sudo install -m 0644 "$repository_root/deploy/su.caddy" /etc/caddy/sites/su.caddy
sudo rsync -a --delete "$repository_root/site/" /var/www/hause/
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
sudo systemctl reload caddy

systemctl --no-pager --lines=0 status hause-admin
