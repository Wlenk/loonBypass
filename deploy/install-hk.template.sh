#!/usr/bin/env bash
# This template is public. The generated private installer has a sealed payload.
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run on the Hong Kong server as root (or sudo bash).'; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'This verified binary is for x86_64.'; exit 1; }
command -v systemctl >/dev/null
command -v dnf >/dev/null || { echo 'This installer targets AlmaLinux/RHEL with dnf.'; exit 1; }
if [[ -f /etc/cloudvpn-hy2/deployment.id ]] &&
   [[ $(cat /etc/cloudvpn-hy2/deployment.id) != '__DEPLOYMENT_ID__' ]]; then
  echo 'A different deployment already exists; refusing to replace its credentials.'; exit 1
fi
scratch=$(mktemp -d /var/tmp/cloudvpn-hk.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
dnf install -y curl openssl python3 nftables iproute
python3 - "$scratch" <<'PY'
import base64, hashlib, io, pathlib, sys, tarfile
data = base64.b64decode('__PAYLOAD__')
assert hashlib.sha256(data).hexdigest() == '__PAYLOAD_SHA256__'
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    for member in archive.getmembers():
        assert member.isfile() and '/' not in member.name and member.name not in ('.', '..')
        (pathlib.Path(sys.argv[1]) / member.name).write_bytes(archive.extractfile(member).read())
PY
for port in __DIRECT_PORT__ __RELAY_PORT__; do
  if ss -H -lun "sport = :$port" | grep -q .; then
    if ! systemctl is-active --quiet cloudvpn-hk-hy2 || [[ $port != __DIRECT_PORT__ ]]; then
      echo "UDP port $port is occupied; stopped without changing firewall rules."; exit 1
    fi
  fi
done
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 240 --retry 2 \
  'https://github.com/HyNetworks/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64' \
  -o "$scratch/hysteria"
printf '%s  %s\n' '907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691' "$scratch/hysteria" | sha256sum --check --status
chmod 0755 "$scratch/hysteria"
"$scratch/hysteria" version
getent passwd cloudvpn-hy2 >/dev/null || useradd --system --no-create-home --shell /sbin/nologin cloudvpn-hy2
install -d -m 0750 -o root -g cloudvpn-hy2 /etc/cloudvpn-hy2
install -d -m 0700 /var/lib/cloudvpn-hy2
install -d -m 0755 /usr/local/libexec
install -m 0755 "$scratch/hysteria" /usr/local/libexec/cloudvpn-hysteria
for file in server.yaml server.crt server.key; do
  install -m 0640 -o root -g cloudvpn-hy2 "$scratch/$file" "/etc/cloudvpn-hy2/$file"
done
install -m 0600 "$scratch/relay-config.json" /etc/cloudvpn-hy2/relay-config.json
install -m 0755 "$scratch/hk-relay.py" /usr/local/libexec/cloudvpn-hk-relay.py
install -m 0644 "$scratch/cloudvpn-hk-hy2.service" /etc/systemd/system/cloudvpn-hk-hy2.service
install -m 0644 "$scratch/cloudvpn-hk-relay.service" /etc/systemd/system/cloudvpn-hk-relay.service
install -m 0644 "$scratch/cloudvpn-hk-relay.timer" /etc/systemd/system/cloudvpn-hk-relay.timer
printf '%s\n' '__DEPLOYMENT_ID__' >/etc/cloudvpn-hy2/deployment.id
cat >/etc/sysctl.d/90-cloudvpn-hk.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
SYSCTL
sysctl -p /etc/sysctl.d/90-cloudvpn-hk.conf
command -v restorecon >/dev/null && restorecon -RF /usr/local/libexec /etc/cloudvpn-hy2 /etc/systemd/system/cloudvpn-hk* || true
systemctl daemon-reload
systemctl enable cloudvpn-hk-hy2.service
systemctl restart cloudvpn-hk-hy2.service
sleep 1
systemctl is-active --quiet cloudvpn-hk-hy2.service || {
  journalctl -u cloudvpn-hk-hy2.service -n 20 --no-pager; exit 1;
}
if ! systemctl start cloudvpn-hk-relay.service; then
  journalctl -u cloudvpn-hk-relay.service -n 30 --no-pager -o cat
  exit 1
fi
systemctl enable --now cloudvpn-hk-relay.timer
# Real SOCKS-over-QUIC tests check the local server and the existing Fuzhou upstream.
# The public Hong Kong relay still requires an external client after security-group opening.
python3 "$scratch/selftest.py" /usr/local/libexec/cloudvpn-hysteria "$scratch"
echo 'HK_HY2_ACTIVE=1'
echo 'HK_DIRECT_UDP=__DIRECT_PORT__'
echo 'HK_FUZHOU_RELAY_UDP=__RELAY_PORT__'
echo 'PUBLIC_RELAY_EXTERNAL_TEST=PENDING'
echo 'Done. Open these two UDP ports in the cloud security group, then test both Loon nodes.'
