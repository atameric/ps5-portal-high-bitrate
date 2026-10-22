#!/bin/sh
# install-alpine.sh - install the automatic relay inside Alpine Linux from this checkout.
#
# Used two ways:
#   - Proxmox LXC: deploy/pve/create-lxc.sh copies the relay files and deploy/ into the
#     container and runs this script (OpenRC service, not enabled until you test).
#   - Docker: deploy/docker/Dockerfile runs it with PORTAL_CONTAINER=1 (no OpenRC).
# Re-running it updates the code and keeps enrollment and runtime state. Because the
# baseline receipt is bound to the code, run 'portal baseline' again after an update.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/.." && pwd)              # repository root (relay .py files)
APP=/opt/portal-bitrate-auto
RT=/var/lib/portal-bitrate-auto
ETC=/etc/portal-bitrate
CONTAINER=${PORTAL_CONTAINER:-}
FILES="portal_active_probe.py portal_auto.py portal_auto_platform.py portal_capture.py
       portal_egress_witness.py portal_windows.py portal_windows_network.py protocol.py
       requirements.txt LICENSE"

for f in $FILES deploy/portal deploy/portal-bitrate.initd; do
	[ -f "$SRC/$f" ] || { echo "xx $SRC/$f missing - run from a complete checkout"; exit 1; }
done

if [ -z "${PORTAL_SKIP_APK:-}" ]; then   # PORTAL_SKIP_APK: CI on non-Alpine runners only
	echo "==> apk packages"
	PKGS="python3 iproute2 libpcap"
	[ -n "$CONTAINER" ] || PKGS="$PKGS tcpdump"
	# shellcheck disable=SC2086
	apk add --no-cache $PKGS >/dev/null
fi

if [ -z "$CONTAINER" ]; then
	echo "==> IPv4 forwarding off in this container's namespace (the relay refuses to run with it on)"
	cat > /etc/sysctl.d/90-portal-relay.conf <<-'EOF'
	# PS5 Portal relay: it forwards in user space and refuses to start while the kernel
	# forwards. A new LXC network namespace can inherit ip_forward=1 from the PVE host.
	net.ipv4.ip_forward = 0
	EOF
	sysctl -qw net.ipv4.ip_forward=0 || true
	rc-update add sysctl boot >/dev/null 2>&1 || true
fi

WAS_RUNNING=
if [ -z "$CONTAINER" ] && rc-service -q portal-bitrate status >/dev/null 2>&1; then
	echo "==> Stopping the running service for the update"
	rc-service portal-bitrate stop
	WAS_RUNNING=1
fi

echo "==> Relay code -> $APP"
umask 077
mkdir -p "$APP/tests" "$RT" "$ETC"
chmod 700 "$APP" "$RT" "$ETC"
for f in $FILES; do cp "$SRC/$f" "$APP/$f"; done
cp "$SRC"/tests/*.py "$APP/tests/"
echo "${PORTAL_SOURCE_REV:-unknown}" > "$APP/SOURCE_REV"

echo "==> Python venv + pinned requirements"
if [ ! -x "$APP/.venv/bin/python" ]; then
	python3 -m venv "$APP/.venv" 2>/dev/null || {
		rm -rf "$APP/.venv"; apk add --no-cache py3-virtualenv >/dev/null; virtualenv -q "$APP/.venv"; }
fi
"$APP/.venv/bin/python" -m pip install -q --no-cache-dir --disable-pip-version-check -r "$APP/requirements.txt"

echo "==> Self-test: libpcap BPF compile + offline unit tests"
"$APP/.venv/bin/python" - <<-'EOF'
	from scapy.arch.common import compile_filter
	from scapy.data import DLT_EN10MB
	compile_filter('ether dst 02:00:00:00:00:01 and ether src 02:00:00:00:00:03 and ip '
	               'and src host 10.0.0.2 and dst host 10.0.0.1', linktype=DLT_EN10MB)
	print('   BPF filter compile: ok')
	EOF
# Keep unittest's exit status: a pipe to tail/sed would hide failures under POSIX sh.
# Show the complete failure output and stop before publishing the helper/service.
( cd "$APP" && .venv/bin/python -m unittest discover -s tests )
find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} +

echo "==> Helper"
umask 022
install -m 755 "$SRC/deploy/portal" /usr/local/bin/portal
# pct enter/exec hand the container the PATH PVE sets in
# PVE::CLIHandler::run_cli_handler (/sbin:/bin:/usr/sbin:/usr/bin), and their
# non-login shell never reads /etc/profile, so /usr/local/bin is not searched.
# Link the helper where that PATH looks, otherwise the documented bare `portal`
# fails with "not found"; /usr/local/bin/portal keeps working as before.
ln -sf /usr/local/bin/portal /usr/bin/portal
if [ -z "$CONTAINER" ]; then
	install -m 755 "$SRC/deploy/portal-bitrate.initd" /etc/init.d/portal-bitrate
	echo "==> OpenRC service installed (not enabled; run 'portal enable' after testing)"
fi

if [ -n "$WAS_RUNNING" ]; then
	if /usr/local/bin/portal check >/dev/null 2>&1; then
		rc-service portal-bitrate start
	else
		echo "!! The code changed, so the old baseline no longer matches. Run 'portal baseline', then 'portal start'."
	fi
fi
echo "==> Installed: $(/usr/local/bin/portal version)"
