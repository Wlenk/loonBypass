#!/usr/bin/env bash
# Repair an existing CloudVPN deployment; never replaces credentials or ports.
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run this recovery script on the HK server as root.'; exit 1; }
revision=${1:-main}
[[ $revision == main || $revision =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid source revision.'; exit 1; }
[[ -f /etc/cloudvpn-hy2/relay-config.json && -f /etc/cloudvpn-hy2/server.yaml ]] || {
  echo 'Existing CloudVPN configuration not found; recovery did not change anything.'; exit 1;
}
scratch=$(mktemp -d /var/tmp/cloudvpn-hk-repair.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 60 \
  "https://raw.githubusercontent.com/Wlenk/loonBypass/$revision/deploy/hk-relay.py" \
  -o "$scratch/hk-relay.py"
printf '%s  %s\n' '13811529cb007737d6617a928717cb08e706a4a2a7ca05dbefdb47cf1d3fe8fb' "$scratch/hk-relay.py" | sha256sum --check --status
python3 -m py_compile "$scratch/hk-relay.py"
if [[ ! -e /usr/local/libexec/cloudvpn-hk-relay.py.before-firewall-fix ]]; then
  cp -p /usr/local/libexec/cloudvpn-hk-relay.py /usr/local/libexec/cloudvpn-hk-relay.py.before-firewall-fix
fi
install -m 0755 "$scratch/hk-relay.py" /usr/local/libexec/cloudvpn-hk-relay.py
if command -v restorecon >/dev/null; then
  restorecon /usr/local/libexec/cloudvpn-hk-relay.py
fi
systemctl daemon-reload
systemctl enable --now cloudvpn-hk-hy2.service
systemctl reset-failed cloudvpn-hk-relay.service
if ! systemctl restart cloudvpn-hk-relay.service; then
  journalctl -u cloudvpn-hk-relay.service -n 40 --no-pager -o cat
  exit 1
fi
systemctl enable --now cloudvpn-hk-relay.timer
systemctl is-active cloudvpn-hk-hy2.service cloudvpn-hk-relay.timer
systemctl show cloudvpn-hk-relay.service --property=Result --property=ExecMainStatus
journalctl -u cloudvpn-hk-relay.service -n 6 --no-pager -o cat
echo 'Recovery completed. The Loon configuration and both UDP ports are unchanged.'
