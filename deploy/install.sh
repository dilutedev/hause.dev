#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$PATH:/usr/local/go/bin"

environment_file="$repository_root/deploy/hause.env"
if [ ! -f "$environment_file" ]; then
	echo "Missing deploy/hause.env. Copy deploy/hause.env.example to deploy/hause.env and fill it in." >&2
	exit 1
fi
source "$environment_file"
: "${HAUSE_ACME_EMAIL:?Set HAUSE_ACME_EMAIL in deploy/hause.env}"
: "${HAUSE_SITE_DOMAIN:?Set HAUSE_SITE_DOMAIN in deploy/hause.env}"
: "${HAUSE_ADMIN_DOMAIN:?Set HAUSE_ADMIN_DOMAIN in deploy/hause.env}"
if [[ "$HAUSE_ACME_EMAIL" == *@example.com ]]; then
	echo "HAUSE_ACME_EMAIL in deploy/hause.env is still the example address." >&2
	exit 1
fi

rendered_directory="$(mktemp -d)"
trap 'rm -rf "$rendered_directory"' EXIT
for template in Caddyfile su.caddy hause-admin.service; do
	sed -e "s|{{HAUSE_ACME_EMAIL}}|$HAUSE_ACME_EMAIL|g" \
		-e "s|{{HAUSE_SITE_DOMAIN}}|$HAUSE_SITE_DOMAIN|g" \
		-e "s|{{HAUSE_ADMIN_DOMAIN}}|$HAUSE_ADMIN_DOMAIN|g" \
		"$repository_root/deploy/$template" > "$rendered_directory/$template"
done

(cd "$repository_root/admin" && go build -o /tmp/hause-admin .)

id hause-admin >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin hause-admin

sudo install -m 0755 /tmp/hause-admin /usr/local/bin/hause-admin
rm /tmp/hause-admin

sudo install -m 0440 "$repository_root/deploy/hause-admin.sudoers" /etc/sudoers.d/hause-admin
sudo visudo -cf /etc/sudoers.d/hause-admin

sudo install -m 0644 "$rendered_directory/hause-admin.service" /etc/systemd/system/hause-admin.service
sudo systemctl daemon-reload
sudo systemctl enable hause-admin >/dev/null
sudo systemctl restart hause-admin

sudo install -m 0644 "$rendered_directory/Caddyfile" /etc/caddy/Caddyfile
sudo install -m 0644 "$rendered_directory/su.caddy" /etc/caddy/sites/su.caddy
sudo rsync -a --delete "$repository_root/site/" /var/www/hause/
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
sudo systemctl reload caddy

systemctl --no-pager --lines=0 status hause-admin
