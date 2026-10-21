# Raspberry Pi 4 Same-Interface Ethernet Header NAT Relay — Technical Setup

## 1. Package Layout and Standalone Module Imports

This directory is a self-contained standalone folder. `linux_native.py` resolves its working root from its own file location (`ROOT = Path(__file__).resolve().parent`) and imports sibling modules directly from the same folder:

- `linux_native.py` — CLI entry point, read-only Linux preflight, `AF_PACKET` RX/TX sockets, classic BPF capture filter, packet loop, baseline/active gate, and status reporting.
- `guardian.py` — child guardian process holding TCP/UDP port reservations (`58001–58064`), scoped `nftables` table (`inet portal_native_nat`), `pidfd` parent tracking, and fail-closed ARP/nft recovery.
- `nat.py` — same-interface IPv4/TCP/UDP flow pool (`58001–58064`), fragment cache, capture filter builder, and strict peer direction matching.
- `header_nat.py` — IPv4/TCP/UDP header parsing, RFC 1624 incremental checksum update, and L2/L3/L4 header rewrite.
- `portal_active_probe.py` — bounded UDP 9296 LaunchSpec startup mutation and PS5 telemetry observation.
- `protocol.py` — minimal protobuf wire reader used by `portal_active_probe.py`.
- `portal_capture.py` / `portal_egress_witness.py` — reference modules imported by `portal_active_probe.py` (macOS live functions are never called on Linux; `portal_windows_network` is not imported or needed).

`linux_native.py` computes a SHA-256 fingerprint (`code_sha256`) across `linux_native.py`, `nat.py`, `guardian.py`, `header_nat.py`, `portal_active_probe.py`, and `protocol.py`. Both `baseline-run.json` and the persistent `baseline-accepted.json` receipt are cryptographically bound to `code_sha256`, the interface name (`eth0`), and the Pi, PS5, and Portal IPv4/MAC addresses.

---

## 2. Topology and Host Prerequisites

- **Directly connected IPv4 LAN:** The Raspberry Pi 4, PS5, and PlayStation Portal (via the local Wi-Fi AP bridged to the same LAN) must share the same IPv4 subnet with direct unicast routes (`ip -4 route get <peer_ip>` must resolve on `eth0` with no gateway). Pi, PS5, and Portal IPv4 and MAC addresses must all be distinct.
- **Single physical Ethernet interface (`eth0`):** Only physical Ethernet `eth0` (`ARPHRD_ETHER`) is supported. Wi-Fi, VLANs, bridges, bonds, and virtual `veth` interfaces are rejected in production.
- **Standard MTU:** `eth0` MTU must be `<= 1500` (`68..1500`).
- **IPv4 forwarding disabled:** Both `/proc/sys/net/ipv4/ip_forward` and `/proc/sys/net/ipv4/conf/eth0/forwarding` must be `0`.
- **No competing relays or port/table conflicts:** No other relay or process may bind TCP/UDP ports `58001–58064` on the Pi IPv4 address or own the `nftables` table `inet portal_native_nat`.
- **Manual peer enrollment only:** There is no automatic peer IP discovery. You must manually enroll your actual PS5 and Portal IPv4 and unicast MAC addresses in `/etc/portal-relay-pi4/config.json`.
- **No global sysctl or firewall edits:** Do **not** modify global `sysctl` settings and do **not** flush or edit global firewall rulesets (never run `nft flush ruleset`). The guardian creates and deletes only its own scoped table `inet portal_native_nat` (`prerouting priority -450`) verified by `portal_run_token`.

---

## 3. Prominent Hardware / Receive Offload Assumption (`ethtool -k eth0`)

> **IMPORTANT — Read Before Changing Interface Offloads or Installing the Service**
>
> `linux_native.py` preflight is strictly read-only and requires `generic-receive-offload` (`gro`), `large-receive-offload` (`lro`), `rx-gro-hw`, and `rx-gro-list` to be `off` on `eth0` so coalesced `>MTU` frames do not corrupt packet framing.
>
> The included `portal-relay-pi4.service` template was physically tested on Raspberry Pi 4 (`bcmgenet`) under the following hardware assumption:
> - **Original `eth0` state:** `generic-receive-offload: on` (`gro on`), while `large-receive-offload: off`, `rx-gro-hw: off`, and `rx-gro-list: off` are already `off`.
> - **Service behavior:** `portal-relay-pi4.service` runs `ExecStartPre=/usr/sbin/ethtool -K eth0 gro off` on startup and `ExecStopPost=/usr/sbin/ethtool -K eth0 gro on` on stop.
> - **Foreground behavior:** For manual foreground commands (`preflight`, `baseline`, `accept-baseline`, bounded `active`), you must manually disable GRO before running (`sudo /usr/sbin/ethtool -K eth0 gro off`).
>
> **Before making any changes, record your original `eth0` offload state:**
> ```bash
> ethtool -k eth0 | tee ~/eth0-offloads-before.txt
> ```
> Inspect `generic-receive-offload`, `large-receive-offload`, `rx-gro-hw`, and `rx-gro-list`. **If your hardware's original values differ from this assumption (for example, if `gro` is originally `off`, or if `lro`, `rx-gro-hw`, or `rx-gro-list` are `on`), do not blindly install `portal-relay-pi4.service`; adjust the `ethtool -K` offload commands for your hardware before use.**

---

## 4. Installation to `/opt/portal-relay-pi4`

Install required Debian / Raspberry Pi OS packages:

```bash
sudo apt-get update
sudo apt-get install -y python3-venv iproute2 nftables ethtool
```

From the freshly extracted `raspberry-pi` directory (without a `.venv`), install into the final folder before running `preflight` or `baseline`. Creating the virtual environment in this stable folder avoids relocation; using the same installed files and configuration keeps baseline binding consistent across `baseline`, `accept-baseline`, bounded `active`, and the service. `code_sha256` hashes source filenames and contents, not the installation path. If an installation already exists, stop and leave it untouched. If any installation command fails, stop and resolve the error before continuing with this guide.

```bash
if sudo test -e /opt/portal-relay-pi4 || sudo test -L /opt/portal-relay-pi4; then
    echo "Existing installation: stop and leave /opt/portal-relay-pi4 untouched."
else
    sudo install -d -m 0755 /opt/portal-relay-pi4 &&
    sudo cp -a . /opt/portal-relay-pi4 &&
    sudo python3 -m venv /opt/portal-relay-pi4/.venv &&
    sudo /opt/portal-relay-pi4/.venv/bin/python -m pip install -r /opt/portal-relay-pi4/requirements.txt &&
    sudo chown -R root:root /opt/portal-relay-pi4
fi
```

---

## 5. Manual Peer Configuration (`/etc/portal-relay-pi4/config.json`)

`config.example.json` contains RFC 5737 documentation IPs (`192.0.2.10`, `192.0.2.20`) and RFC 7042 synthetic unicast MACs (`02:00:5e:00:53:10`, `02:00:5e:00:53:20`). Install it to `/etc/portal-relay-pi4/config.json` with `root:root` ownership and `0600` permissions:

```bash
sudo install -d -m 0755 /etc/portal-relay-pi4
sudo install -m 0600 -o root -g root /opt/portal-relay-pi4/config.example.json /etc/portal-relay-pi4/config.json
sudo nano /etc/portal-relay-pi4/config.json
```

Edit `/etc/portal-relay-pi4/config.json` with your actual device IPv4 and unicast MAC addresses:

```json
{
  "network": {
    "interface": "eth0",
    "ps5_ip": "192.0.2.10",
    "portal_ip": "192.0.2.20"
  },
  "profile": "100",
  "ps5_mac": "02:00:5e:00:53:10",
  "portal_mac": "02:00:5e:00:53:20"
}
```

Verify permissions:

```bash
sudo chown root:root /etc/portal-relay-pi4/config.json
sudo chmod 0600 /etc/portal-relay-pi4/config.json
```

### Profile Semantics (`100`)

- `"profile": "100"` (`--profile 100`) is a **suggested target request mutation** in the Portal startup LaunchSpec, **not** a guarantee of actual video bitrate or stream quality.
- `forwarded_mbps` and PS5 `target_bitrate_raw` (`CONNECTIONQUALITY`) are separate metrics; neither alone proves visual quality.
- Other profile keys (`65`, `150`, `200`) exist in code but are **not validated** for this Raspberry Pi 4 package.

---

## 6. Verification Workflow (`preflight` -> `baseline` -> `accept-baseline` -> Bounded `active`)

### Step 1: Manually Disable `eth0` GRO and Run Read-Only Preflight

After recording `ethtool -k eth0`, disable GRO for foreground verification and run `preflight`:

```bash
sudo /usr/sbin/ethtool -K eth0 gro off

sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py preflight \
  --config /etc/portal-relay-pi4/config.json \
  --runtime /run/portal-linux-native \
  --state-dir /var/lib/portal-linux-native
```

`preflight` prints the verified JSON state (`own_ip`, `own_mac`, `mtu`, `offloads`) and makes zero changes to the system.

### Step 2: Run Finite 180s Baseline (Zero Packet Mutation)

Keep PlayStation Portal disconnected initially, then start the finite 180-second baseline run:

```bash
sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py baseline \
  --seconds 180 \
  --config /etc/portal-relay-pi4/config.json \
  --runtime /run/portal-linux-native \
  --state-dir /var/lib/portal-linux-native
```

#### Readiness Semantics (Actual Source Behavior)

- `linux_native.py` does **not** print a `READY` banner to stdout during execution; stdout outputs the final JSON status summary only when the run finishes.
- Internally, `linux_native.py` spawns `guardian.py`, completes the internal pipe handshake (`PORTS_RESERVED` -> `RX_READY` -> `GUARD_READY`), sends initial Portal ARP frames, and writes `/run/portal-linux-native/status.json` with `"state": "running"`.
- In a second terminal, query live status as `root` (`sudo` is required because `/run/portal-linux-native` and `/var/lib/portal-linux-native` are `0700` and their JSON files are `0600`):
  ```bash
  sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py status \
    --runtime /run/portal-linux-native \
    --state-dir /var/lib/portal-linux-native
  ```
- Once `status.state` is `"running"` (and `status.recovery.state` is `"active_guardian"`), connect your PlayStation Portal to the PS5 and verify live video picture and controller input.
- Wait for the 180-second run to complete and restore cleanly (`"state": "stopped"`, `"recovery": {"state": "recovered", ...}`).

### Step 3: Record Human Physical Baseline Acceptance (`accept-baseline`)

Transport completion and packet counters never self-accept baseline. **Only after** you have physically verified clean Portal picture and controls during the 180-second baseline run and confirmed clean restoration, record your human assertion into `/var/lib/portal-linux-native/baseline-accepted.json`:

```bash
sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py accept-baseline \
  --config /etc/portal-relay-pi4/config.json \
  --runtime /run/portal-linux-native \
  --state-dir /var/lib/portal-linux-native \
  --assert-physical-ok "Verified clean Portal picture and controls on eth0 during 180s baseline and clean restoration."
```

### Step 4: Run Bounded 300s Active Mode (`--profile 100 --seconds 300`)

Before enabling any background service, run active mode for a bounded 300 seconds and perform a fresh Portal connection and physical gameplay check:

```bash
sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py active \
  --profile 100 \
  --seconds 300 \
  --config /etc/portal-relay-pi4/config.json \
  --runtime /run/portal-linux-native \
  --state-dir /var/lib/portal-linux-native
```

While running, check `status` with `sudo` in another terminal (`status.state == "running"`), connect the Portal from a disconnected state so the startup handshake is processed, and physically verify video stability and controls. Wait for the 300-second run to exit cleanly (`"state": "stopped"`).

---

## 7. Optional `systemd` Service (`portal-relay-pi4.service`)

Only after bounded 300s active mode and physical gameplay verification succeed, you may optionally install the `systemd` unit.

Verify the offload assumption in Section 3 first. The exact tested unit file (`portal-relay-pi4.service`) is:

```ini
[Unit]
Description=PlayStation Portal relay on Pi4 (100 Mbps profile)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=simple
User=root
WorkingDirectory=/opt/portal-relay-pi4
Environment=PYTHONUNBUFFERED=1
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
UMask=0077
RuntimeDirectory=portal-linux-native
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
StateDirectory=portal-linux-native
StateDirectoryMode=0700
ExecStartPre=/usr/sbin/ethtool -K eth0 gro off
ExecStart=/opt/portal-relay-pi4/.venv/bin/python -u /opt/portal-relay-pi4/linux_native.py active --profile 100 --continuous --config /etc/portal-relay-pi4/config.json --runtime /run/portal-linux-native --state-dir /var/lib/portal-linux-native
ExecStopPost=/usr/sbin/ethtool -K eth0 gro on
KillMode=process
TimeoutStopSec=30
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Install and start the unit:

```bash
sudo install -m 0644 -o root -g root /opt/portal-relay-pi4/portal-relay-pi4.service /etc/systemd/system/portal-relay-pi4.service
sudo systemctl daemon-reload
sudo systemctl enable --now portal-relay-pi4.service
```

---

## 8. Status, Stop Semantics (`systemctl stop` vs Direct `stop`), and Lock Safety

### Inspecting Status (`root` Required)

Always run `status` with `sudo`:

```bash
sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py status \
  --runtime /run/portal-linux-native \
  --state-dir /var/lib/portal-linux-native
```

### `systemctl stop` vs Direct `linux_native.py stop`

1. **Stopping the `systemd` service (`sudo systemctl stop portal-relay-pi4.service`):**
   - `systemd` sends `SIGTERM` to `linux_native.py`.
   - `linux_native.py` catches `SIGTERM`, exits the packet loop cleanly, runs guardian ARP/nft recovery, writes `"state": "stopped"`, removes `recovery-required` and `portal-linux-native.lock`, and `ExecStopPost` restores `ethtool -K eth0 gro on`.
   - It does **not** create `/run/portal-linux-native/disabled`, so `sudo systemctl start portal-relay-pi4.service` can start the service again directly.

2. **Direct CLI `stop` command (`linux_native.py stop --runtime /run/portal-linux-native`):**
   - `request_stop()` writes `/run/portal-linux-native/disabled`.
   - A running foreground or service relay detects `/run/portal-linux-native/disabled`, exits cleanly, and completes guardian recovery, **leaving `/run/portal-linux-native/disabled` on disk** (and because `RuntimeDirectoryPreserve=yes` is set in the unit, `/run/portal-linux-native/disabled` persists across service stop).
   - **Actual behavior on next start:** `linux_native.py` does **not** automatically clear `/run/portal-linux-native/disabled` when starting `baseline` or `active`; if `/run/portal-linux-native/disabled` is present, `linux_native.py` prints:
     `Relay is disabled; remove disabled marker before starting.`
     and exits with code `1`.
   - Before starting the next `baseline` or `active` run after using direct `stop`, run `sudo ... linux_native.py status` to verify `"state": "stopped"`, `"recovery_required": false`, and `"lock_present": false`, and then remove **only** the `disabled` marker:
     ```bash
     sudo rm -f /run/portal-linux-native/disabled
     ```

3. **Never delete recovery or lock files:**
   - Do **not** manually delete `/run/portal-linux-native/recovery-required`, `/run/portal-linux-native/portal-linux-native.lock`, or `/run/portal-linux-native/recovery.json`.
   - If `status` reports `"state": "recovery_failed"` or `"recovery_required": true`, inspect `recovery.json` and `sudo /usr/sbin/nft list table inet portal_native_nat` to diagnose the failure rather than deleting lock files.

---

## 9. Reboot Behavior

- `portal-relay-pi4.service` runs from the stable `/opt/portal-relay-pi4` folder and reads the persistent acceptance receipt in `/var/lib/portal-linux-native/baseline-accepted.json` (while volatile `/run/portal-linux-native` is recreated on `tmpfs`).
- As long as the code files in `/opt/portal-relay-pi4`, the interface (`eth0`), and the Pi/PS5/Portal IPv4 and MAC bindings match the receipt, `active` mode starts after reboot without repeating `baseline`. If any code file or IP/MAC changes, `active` mode refuses to start until a new `baseline` and `accept-baseline` are completed.
- After any Pi reboot, always perform **fresh physical gameplay verification** on PlayStation Portal.

---

## 10. Rollback Procedure

To completely stop the relay and return to direct PS5 <-> PlayStation Portal communication:

1. **Stop and disable the service (or stop a foreground run):**
   ```bash
   sudo systemctl disable --now portal-relay-pi4.service
   ```
   *(If running in the foreground instead of `systemd`, press `Ctrl+C` or run `sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py stop --runtime /run/portal-linux-native`.)*

2. **Wait for guardian recovery and confirm clean state (no `recovery_failed`):**
   ```bash
   sudo /opt/portal-relay-pi4/.venv/bin/python /opt/portal-relay-pi4/linux_native.py status \
     --runtime /run/portal-linux-native \
     --state-dir /var/lib/portal-linux-native
   ```
   Confirm `"state": "stopped"` (not `"recovery_failed"`), `"recovery_required": false`, and `"lock_present": false`. Confirm the scoped `nftables` table is absent:
   ```bash
   sudo /usr/sbin/nft list table inet portal_native_nat
   ```
   *(Expected: `Error: No such file or directory` / table does not exist.)*

3. **Restore original `eth0` GRO offload state:**
   ```bash
   sudo /usr/sbin/ethtool -K eth0 gro on
   ethtool -k eth0 | grep -E 'generic-receive-offload|large-receive-offload|rx-gro'
   ```
   *(Or restore the exact values recorded in `~/eth0-offloads-before.txt`.)*

4. **Reconnect PlayStation Portal normally:**
   Disconnect and reconnect the PlayStation Portal to the PS5 (toggle Portal Airplane Mode or restart the Portal session if needed) and verify normal direct streaming.
