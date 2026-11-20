#!/bin/sh
# Install/refresh the pilot release copy and user unit. Secrets are NOT handled here:
# create ~/.config/auth-audit-jev/{typesafe.key,admin.token,metrics.token} (mode 0600) first.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
app="$HOME/.local/share/auth-audit-jev/app"
mkdir -p "$app" "$HOME/.config/systemd/user" "$HOME/.local/state/auth-audit-jev"
rm -rf "$app/auth_audit_jev"
cp -r "$here/src/auth_audit_jev" "$app/"
find "$app" -name __pycache__ -prune -exec rm -rf {} +
cp "$here/deploy/auth-audit-jev-pilot.service" "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now auth-audit-jev-pilot.service
systemctl --user restart auth-audit-jev-pilot.service
