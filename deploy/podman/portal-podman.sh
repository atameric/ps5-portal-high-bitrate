#!/bin/sh
# portal-podman.sh - run the automatic relay with rootful Podman on the host network.
# See deploy/README.md. The container shares the host's network namespace, so the relay
# checks the HOST's ip_forward: it must stay 0. This script never changes it.
set -eu
cd "$(dirname "$0")/../.."

IMAGE=localhost/portal-relay:local
DATA=/var/lib/portal-relay
UNIT=portal-relay
QUADLET=/etc/containers/systemd/portal-relay.container

[ "$(id -u)" = 0 ] || exec sudo "$0" "$@"

# Optional answers for 'configure' (sudo drops env vars, so they live in a file).
ENVFILE=deploy/podman/portal.env
[ -f "$ENVFILE" ] && . "./$ENVFILE"

running() { systemctl is-active -q "$UNIT" 2>/dev/null || podman container exists "$UNIT"; }
relay() {
	if running; then echo "portal-relay is running; '$0 disable' first."; exit 1; fi
	if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 0 ]; then
		echo "Host IPv4 forwarding is on. A rootful Podman bridge network (netavark) or Docker"
		echo "may have enabled it. Find the cause before turning it off; see deploy/README.md."
		exit 1
	fi
	mkdir -p -m 700 "$DATA/config" "$DATA/runtime"
	podman run --rm -i $([ -t 0 ] && echo -t) --init --network host --cap-add NET_RAW --tmpfs /run \
		-v "$DATA/config:/etc/portal-bitrate:Z" -v "$DATA/runtime:/var/lib/portal-bitrate-auto:Z" \
		"$IMAGE" "$@"
}

case "${1:-help}" in
	build)
		# --network host: a bridge network makes netavark set the host's ip_forward=1.
		podman build --network host --format docker --ignorefile deploy/docker/Dockerfile.dockerignore \
			--build-arg SOURCE_REV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
			-f deploy/docker/Dockerfile -t "$IMAGE" . ;;
	configure)
		profile=${2:-${PROFILE:-65}}
		if [ -n "${LAN_IFACE:-}" ] && [ -n "${PS5_IP:-}" ] && [ -n "${PORTAL_IP:-}" ]; then
			printf '%s\n%s\n%s\n' "$LAN_IFACE" "$PS5_IP" "$PORTAL_IP" | relay configure "$profile"
		else
			echo "Use the HOST interface name (see 'ip -br link'), not eth0."; relay configure "$profile"
		fi ;;
	status|log)
		# Read-only: look inside the running service instead of starting a new container.
		if podman container exists "$UNIT"; then podman exec "$UNIT" portal "$@"; else relay "$@"; fi ;;
	baseline|try|repair|check) relay "$@" ;;
	enable)
		relay check
		install -m 644 deploy/podman/portal-relay.container "$QUADLET"
		systemctl daemon-reload
		systemctl start "$UNIT"
		systemctl --no-pager status "$UNIT" ;;
	disable)
		systemctl stop "$UNIT" 2>/dev/null || true
		rm -f "$QUADLET"; systemctl daemon-reload ;;
	logs) journalctl -u "$UNIT" -n "${2:-50}" --no-pager ;;
	*) echo "Commands: build, configure [65|100|200], baseline, try, check, status, log, repair, enable, disable, logs" ;;
esac
