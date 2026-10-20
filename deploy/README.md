# Proxmox LXC and Docker deployment (experimental community preview)

These files run the [automatic relay](../AUTOMATION.md) (`portal_auto.py run`) in a
**Proxmox VE LXC** or a **Docker container** instead of on a native Linux host. The relay
code, its limits and its safety checks are unchanged. Everything in the main README and
AUTOMATION.md still applies: it's experimental, it was tested on Portal firmware 7.1.7,
it's not a 4K unlock, and lower latency isn't guaranteed.

## Why this works in a container

The relay redirects the Portal with ARP, so it needs its **own MAC address on the same
layer-2 LAN** as the PS5 and Portal. A NAT'd Docker bridge or a VM behind NAT can't
provide that, which is why AUTOMATION.md lists them as unsupported. These two setups do:

- **Proxmox:** an unprivileged Alpine LXC whose `eth0` is bridged on `vmbr0`.
- **Docker:** a container on a `macvlan` network.

Each gets its own network namespace, so the relay's "forwarding must be off" check
applies to the container, not the host. The helper turns forwarding off inside the LXC;
in Docker, `compose.yaml` sets it with `sysctls`. Host IP forwarding stays unchanged
when these scripts run inside the documented containers. Run the Alpine installer and
`portal` helper only inside the relay container, not on a shared native host.

## Before you start

- Reserve both device IPs in your router, use the same subnet with no client isolation,
  and use a wired relay host. Start with profile 65.
- Proxmox: don't run Docker on the PVE host (see Troubleshooting) or inside the relay's CT.

## Proxmox VE (LXC)

Creates an unprivileged Alpine CT (1 core, 384 MB, 2 GB; about 180 MB in use) on `vmbr0`
with DHCP, `firewall=0` on its NIC, and `onboot=1`. It then installs the relay from this
checkout with an OpenRC service, which stays disabled until you've tested. Run this in the
PVE host shell:

```sh
wget -qO- https://github.com/atameric/ps5-portal-high-bitrate/archive/refs/heads/main.tar.gz | tar xz
bash ps5-portal-high-bitrate-main/deploy/pve/create-lxc.sh
# Options: CTID=215 BRIDGE=vmbr0 VLAN= NET_IP=192.168.1.215/24 GATEWAY=192.168.1.1
#          ROOTFS_STORAGE=local-lvm CORES=1 MEMORY=384 SWAP=256 DISK_GB=2
```

Then, inside the CT (`pct enter <CTID>`):

```sh
portal configure 65   # PS5 + Portal awake; interface: eth0; enter both IPv4 addresses
portal baseline       # disconnect Portal; connect after BASELINE READY; check 60 s
portal try            # connect after AUTO READY; check the Portal's network display; Ctrl+C
portal enable         # only after a good 'try': starts now and at boot
```

**Firewall scope:** the script creates the relay CT with `firewall=0` on `net0`. This
disables Proxmox firewall filtering on that container NIC so its ARP replies can use
the PS5's address. It does not turn off the host-wide Proxmox firewall, router firewall,
or filtering on other containers. The relay CT is exposed to its attached LAN without
that NIC filtering. Use a trusted LAN, keep the CT dedicated to this relay, and do not
install unrelated services or expose it to the Internet. If you require NIC filtering,
review a narrowly scoped rule design before using this deployment; no such rule set
has been validated here. An existing CT's firewall setting is only warned about,
not automatically changed.

To update, re-run the script with `CTID=<id>`, then run
`portal baseline` again (the receipt is bound to the code).

## Docker (Linux host, macvlan)

You need a Linux Docker host with a **wired** NIC on the PS5/Portal LAN. Docker Desktop
on macOS/Windows, WSL and Wi-Fi macvlan parents won't work. Run these from
`deploy/docker/`:

```sh
cp .env.example .env    # LAN_PARENT, LAN_SUBNET, LAN_GATEWAY, RELAY_IP (outside the DHCP pool)
docker compose build
docker compose run --rm relay configure 65
docker compose run --rm relay baseline
docker compose run --rm relay try
docker compose up -d
```

What `compose.yaml` sets, and why:

- **`sysctls: net.ipv4.ip_forward: "0"`**: Docker hosts forward, and a new namespace can
  inherit that.
- **`init: true` and `stop_grace_period: 60s`**: `docker compose down` lets the guardian
  repair the Portal. That takes about 3 s.
- **`tmpfs: /run`**: clears the relay's lock file on each start.
- **`cap_add: NET_RAW`**: needed for Podman, which doesn't grant it by default.

Enrollment and runtime state are kept in `deploy/docker/data/`, which is git-ignored.
Don't share it.

With macvlan, the Docker host itself can't reach the relay's IP. That's expected.
`docker compose run` reuses the fixed IP, so it can't start a second relay while the
service is up.

## Podman (Linux host, host network, community)

[`podman/portal-podman.sh`](podman/portal-podman.sh) runs the same image with rootful
Podman in the **host's** network namespace, plus a Quadlet unit for systemd. Use it when
macvlan isn't available, for example when the relay host only has Wi-Fi. This is the
native Linux relay packaged in a container: the relay uses the host's MAC and checks the
host's IPv4 forwarding, which must stay off. Wired Ethernet is still preferred.

```sh
cp deploy/podman/portal.env.example deploy/podman/portal.env   # optional: answers for configure
deploy/podman/portal-podman.sh build
deploy/podman/portal-podman.sh configure 65   # host interface, e.g. wlp1s0 (not eth0)
deploy/podman/portal-podman.sh baseline
deploy/podman/portal-podman.sh try
deploy/podman/portal-podman.sh enable         # Quadlet unit portal-relay, starts now and at boot
```

`status`, `log` and `logs` work while the service runs; `disable` stops it and removes
the unit. Enrollment and runtime state are kept in `/var/lib/portal-relay/`. To change
the profile: `disable`, `configure <N>`, `baseline`, `enable`.

**Host forwarding.** Rootful Podman's netavark enables the host's `net.ipv4.ip_forward`
when it sets up a bridge network, including the default network used by `podman build`.
The script builds with `--network host` for that reason. Any other rootful bridge
container on the same host turns forwarding back on and the relay then refuses to start.
Rootless containers don't affect it. Use a dedicated relay host if you need those
containers; don't remove the relay's check.

The container gets only `NET_RAW`, not `--privileged`, so it can't change host sysctls.
Volumes use `:Z` for SELinux hosts.

Real-device status: one community report on openSUSE Leap 16 (Podman, Wi-Fi relay host)
with a real PS5 and Portal: baseline, `try`, Quadlet start at boot, fresh reconnect and
PS5 waking from rest mode worked with profile 65. Crash recovery wasn't tested.

## The `portal` helper

| | LXC | Docker |
| --- | --- | --- |
| Status / logs | `portal status`, `portal log` | `docker compose ps`, `docker compose logs -f` |
| Stop / start | `portal stop`, `portal start` | `docker compose down`, `up -d` |
| Change profile | stop, `portal configure 100`, `portal baseline`, start | `down`, `run --rm relay configure 100`, `run --rm relay baseline`, `up -d` |
| After an unclean stop | `portal repair` | `docker compose run --rm relay repair` |

`portal service` is what OpenRC and the container run. It checks forwarding, the
enrollment, the baseline receipt and the recovery marker, then starts `portal_auto.py
run` in the background. It forwards SIGTERM/SIGINT to the relay and waits for the
guardian to finish its ARP repair before exiting, so a supervisor or a container stop
can't cut the repair short.

It also repeats the guardian's repair once, about 1.5 s after both processes have
exited. Linux-based clients ignore an ARP change that arrives within about 1 s of the
previous one (`locktime`). Without the repeat, a stop right after the Portal switched to
the relay could leave it pointing at a stopped relay until its neighbor entry expired.
The frames are the same ones `portal_auto.py repair` sends.

## Troubleshooting

**The Portal is redirected but loses the session, and `forwarded_out` stays 0.** Bridged
IPv4 is being filtered on the host. The usual cause is Docker on the same host as the
bridge the relay sits on (for example, Docker installed on the PVE host). Docker sets the
iptables `FORWARD` policy to `DROP`, and `br_netfilter` sends bridged traffic through it.
ARP still passes, so the Portal follows the relay, but its packets never arrive. Inspect
the host's bridge/firewall policy or use a dedicated relay host. Avoid blindly allowing
all `vmbr0` traffic or removing Docker from a shared host; either can affect unrelated
workloads and isolation. Any firewall exception must be scoped and reviewed for your
own topology.

**"IPv4 forwarding is enabled".** In Docker, keep the `sysctls` entry. In the LXC,
`portal` turns it off automatically; if it can't, check `/etc/sysctl.d/90-portal-relay.conf`.

**Nothing reaches the LXC.** Check `firewall=0` on `net0`, and that the bridge and VLAN
match the PS5/Portal LAN.

## Tests

[`tests/netns-e2e.sh`](tests/netns-e2e.sh) and [`tests/docker-e2e.sh`](tests/docker-e2e.sh)
build a fake LAN from network namespaces (fake PS5, fake Portal and the relay on one
Linux bridge, or a macvlan uplink for Docker). They run configure, baseline, `try` with
Ctrl+C, service stop, and a relay crash with restart. They check that:

- the startup packet is rewritten with valid UDP checksums;
- PS5 → Portal traffic stays direct;
- the Portal's ARP entry is repaired every time;
- the Docker healthcheck, restart policy and same-IP guard work.

The workflow `.github/workflows/deploy-e2e.yml` runs them. They use synthetic packets
built like the offline test fixture, not a real console.

`python3 deploy/tests/test_install.py` also runs the installer in a temporary sandbox
with a controlled self-test result. It checks that a failed self-test stops installation
before publishing the helper and that a successful self-test continues. It needs no
root, container or network access.

Real-device status: [contributor SDNick484](https://github.com/SDNick484) reports using
the Proxmox LXC path with a real PS5 and Portal. This is a community report, not a
maintainer hardware test or broad compatibility guarantee. The contributor's original
commit passed synthetic network-namespace and Docker tests in their fork. Those tests
use fake peers; Docker has no reported real PS5/Portal validation. Maintainer changes
are checked locally on macOS and require fresh Linux/Proxmox/Docker testing. Exact
Proxmox/Alpine versions, real-device reboot/crash recovery and long-duration stability
still need reports. Gentoo/OpenRC outside the Alpine container has not been validated.

This deployment contribution is from SDNick484 in [PR #1](https://github.com/atameric/ps5-portal-high-bitrate/pull/1).
