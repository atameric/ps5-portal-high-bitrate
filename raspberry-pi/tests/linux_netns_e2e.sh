#!/usr/bin/env bash
# Coordinator-only isolated Linux network namespace E2E harness.
# Exercises real AF_PACKET + nftables (-450 prerouting drop) + guardian recovery
# across three isolated veth host namespaces connected to an isolated switch bridge
# namespace using RFC 5737 documentation IPs and RFC 7042 synthetic MACs.
#
# Safety invariants:
# - Never touches host eth0, default route, host nftables, or host sysctls.
# - Cleans only namespaces and temp files created by this invocation in trap,
#   and fails with a non-zero exit code if namespace or temp cleanup fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${ROOT_DIR}/.venv/bin/python}"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    PYTHON_BIN="$(command -v python3)"
fi

CREATED_NETNS=()
TMP_DIR="${TMP_DIR:-}"

wait_for_server_ready() {
    local ready_file="$1"
    local srv_pid="$2"
    local max_attempts="${3:-100}"
    local sleep_sec="${4:-0.05}"
    local attempt
    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        if [[ -f "${ready_file}" ]]; then
            return 0
        fi
        if ! kill -0 "${srv_pid}" 2>/dev/null; then
            echo "ERROR: Synthetic PS5 server (PID ${srv_pid}) exited before becoming ready." >&2
            return 1
        fi
        sleep "${sleep_sec}"
    done
    echo "ERROR: Timed out waiting for synthetic PS5 server readiness (${ready_file})." >&2
    return 1
}

wait_for_relay_running() {
    local status_file="$1"
    local relay_pid="$2"
    local max_attempts="${3:-120}"
    local sleep_sec="${4:-0.05}"
    local attempt
    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        if [[ -f "${status_file}" ]] && "${PYTHON_BIN}" - "${status_file}" <<'PY' 2>/dev/null
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
sys.exit(0 if data.get("state") == "running" else 1)
PY
        then
            return 0
        fi
        if ! kill -0 "${relay_pid}" 2>/dev/null; then
            echo "ERROR: Relay process (PID ${relay_pid}) exited before reaching running state." >&2
            return 1
        fi
        sleep "${sleep_sec}"
    done
    echo "ERROR: Timed out waiting for relay state=running in ${status_file}." >&2
    return 1
}

wait_for_portal_arp() {
    local portal_ns="$1"
    local ps5_ip="$2"
    local expected_mac="$3"
    local relay_pid="$4"
    local max_attempts="${5:-120}"
    local sleep_sec="${6:-0.05}"
    local attempt neigh_json
    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        neigh_json="$(ip -n "${portal_ns}" -j -4 neigh show "${ps5_ip}" dev eth0 2>/dev/null || true)"
        if [[ -n "${neigh_json}" ]] && "${PYTHON_BIN}" - "${neigh_json}" "${ps5_ip}" "${expected_mac}" <<'PY' 2>/dev/null
import json, sys
rows = json.loads(sys.argv[1])
target_ip = sys.argv[2]
expected = sys.argv[3].strip().lower()
for row in rows:
    if row.get("dst") == target_ip and str(row.get("lladdr") or "").strip().lower() == expected:
        sys.exit(0)
sys.exit(1)
PY
        then
            return 0
        fi
        if ! kill -0 "${relay_pid}" 2>/dev/null; then
            echo "ERROR: Relay process (PID ${relay_pid}) exited while waiting for Portal ARP redirection." >&2
            return 1
        fi
        sleep "${sleep_sec}"
    done
    echo "ERROR: Timed out waiting for Portal namespace ${portal_ns} ARP ${ps5_ip} -> ${expected_mac}." >&2
    return 1
}

stop_relay_controlled() {
    local pi_ns="$1"
    local runtime_dir="$2"
    local relay_pid="$3"
    local max_attempts="${4:-120}"
    local sleep_sec="${5:-0.05}"
    local attempt
    ip netns exec "${pi_ns}" "${PYTHON_BIN}" "${ROOT_DIR}/linux_native.py" stop \
        --runtime "${runtime_dir}" >/dev/null
    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        if ! kill -0 "${relay_pid}" 2>/dev/null; then
            wait "${relay_pid}"
            return $?
        fi
        sleep "${sleep_sec}"
    done
    echo "ERROR: Relay process (PID ${relay_pid}) did not terminate after controlled stop." >&2
    return 1
}

stop_netns_processes() {
    local ns="$1" max_attempts="${2:-100}" sleep_sec="${3:-0.05}"
    local pids remaining pid attempt still_alive
    if ! pids="$(ip netns pids "${ns}" 2>/dev/null)"; then
        echo "ERROR: Failed to discover processes in isolated netns ${ns}" >&2
        return 1
    fi
    for pid in ${pids}; do
        # Never pass an option or process-group identifier to kill.
        if [[ ! "${pid}" =~ ^[1-9][0-9]*$ ]]; then
            echo "ERROR: Invalid process ID in isolated netns ${ns}" >&2
            return 1
        fi
    done
    for pid in ${pids}; do
        if ! kill -9 "${pid}" 2>/dev/null; then
            echo "ERROR: Failed to kill PID ${pid} in ${ns}; verifying disappearance" >&2
        fi
    done
    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        still_alive=0
        # kill -0 failure alone cannot distinguish ESRCH from permission errors.
        # On Linux, require the enumerated processes' /proc entries to disappear.
        for pid in ${pids}; do
            if [[ -d "/proc/${pid}" ]]; then
                still_alive=1
            fi
        done
        if remaining="$(ip netns pids "${ns}" 2>/dev/null)" && \
            [[ -z "${remaining}" && "${still_alive}" == 0 ]]; then
            return 0
        fi
        if ((attempt < max_attempts)); then
            sleep "${sleep_sec}"
        fi
    done
    echo "ERROR: Could not confirm process disappearance in isolated netns ${ns}" >&2
    return 1
}

cleanup_created_resources() {
    local cleanup_failed=0
    local ns
    for ns in "${CREATED_NETNS[@]:-}"; do
        if [[ -n "${ns}" ]]; then
            if ! stop_netns_processes "${ns}" "${1:-100}" "${2:-0.05}"; then
                cleanup_failed=1
                # Preserve the owned name for a later cleanup attempt.
                continue
            fi
            if ! ip netns del "${ns}"; then
                echo "ERROR: Failed to delete isolated netns ${ns}" >&2
                cleanup_failed=1
            fi
        fi
    done
    if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR}" ]]; then
        if ! rm -rf "${TMP_DIR}"; then
            echo "ERROR: Failed to remove temporary directory ${TMP_DIR}" >&2
            cleanup_failed=1
        fi
    fi
    return "${cleanup_failed}"
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if ! cleanup_created_resources; then
        exit_code=1
    fi
    exit "${exit_code}"
}

if [[ "${LINUX_NETNS_LIB_ONLY:-0}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: linux_netns_e2e.sh requires a native Linux kernel." >&2
    exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: Run with sudo/root on Linux to create isolated netns objects." >&2
    exit 1
fi

RUN_ID="pnat_$$_$(date +%s)"
NS_SW="ns_sw_${RUN_ID}"
NS_PS5="ns_ps5_${RUN_ID}"
NS_PORTAL="ns_portal_${RUN_ID}"
NS_PI="ns_pi_${RUN_ID}"
TMP_DIR="$(mktemp -d "/tmp/portal-netns-e2e.${RUN_ID}.XXXXXX")"
chmod 700 "${TMP_DIR}"
trap cleanup EXIT INT TERM

create_ns() {
    local ns="$1"
    ip netns add "${ns}"
    CREATED_NETNS+=("${ns}")
    ip -n "${ns}" link set lo up
}

create_ns "${NS_SW}"
create_ns "${NS_PS5}"
create_ns "${NS_PORTAL}"
create_ns "${NS_PI}"

# Create bridge inside isolated switch namespace NS_SW
ip -n "${NS_SW}" link add br0 type bridge
ip -n "${NS_SW}" link set br0 up

connect_host_ns() {
    local host_ns="$1"
    local sw_port="$2"
    local mac="$3"
    local ip_cidr="$4"

    ip -n "${NS_SW}" link add "${sw_port}" type veth peer name eth0 netns "${host_ns}"
    ip -n "${NS_SW}" link set "${sw_port}" master br0
    ip -n "${NS_SW}" link set "${sw_port}" up

    ip -n "${host_ns}" link set eth0 address "${mac}"
    ip -n "${host_ns}" addr add "${ip_cidr}" dev eth0
    ip -n "${host_ns}" link set eth0 mtu 1500
    ip -n "${host_ns}" link set eth0 up

    # Disable GRO/LRO and checksum/segmentation offloads inside isolated netns
    ip netns exec "${host_ns}" ethtool -K eth0 gro off lro off gso off tso off tx off rx off >/dev/null 2>&1 || \
        ip netns exec "${host_ns}" ethtool -K eth0 gro off lro off >/dev/null
}

PS5_IP="192.0.2.10"
PORTAL_IP="192.0.2.20"
PI_IP="192.0.2.30"
PS5_MAC="02:00:5e:00:53:10"
PORTAL_MAC="02:00:5e:00:53:20"
PI_MAC="02:00:5e:00:53:30"

connect_host_ns "${NS_PS5}" "veth_ps5" "${PS5_MAC}" "${PS5_IP}/24"
connect_host_ns "${NS_PORTAL}" "veth_portal" "${PORTAL_MAC}" "${PORTAL_IP}/24"
connect_host_ns "${NS_PI}" "veth_pi" "${PI_MAC}" "${PI_IP}/24"

# Ensure forwarding is off inside isolated Pi namespace
ip netns exec "${NS_PI}" sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward && echo 0 > /proc/sys/net/ipv4/conf/eth0/forwarding'

# Seed initial neighbor entries via brief ping before relay starts
ip netns exec "${NS_PORTAL}" ping -c 1 -W 1 "${PS5_IP}" >/dev/null
ip netns exec "${NS_PI}" ping -c 1 -W 1 "${PS5_IP}" >/dev/null
ip netns exec "${NS_PI}" ping -c 1 -W 1 "${PORTAL_IP}" >/dev/null

CFG_PATH="${TMP_DIR}/auto-config.json"
RUNTIME_DIR="${TMP_DIR}/runtime"
STATE_DIR="${TMP_DIR}/state"
cat > "${CFG_PATH}" <<EOF
{
  "network": {
    "interface": "eth0",
    "ps5_ip": "${PS5_IP}",
    "portal_ip": "${PORTAL_IP}"
  },
  "profile": "100",
  "ps5_mac": "${PS5_MAC}",
  "portal_mac": "${PORTAL_MAC}"
}
EOF
chmod 600 "${CFG_PATH}"

echo "[1/5] Verifying production veth rejection and --allow-test-veth preflight inside ${NS_PI}..."
if ip netns exec "${NS_PI}" "${PYTHON_BIN}" "${ROOT_DIR}/linux_native.py" preflight \
    --config "${CFG_PATH}" --runtime "${RUNTIME_DIR}" --state-dir "${STATE_DIR}" >/dev/null 2>&1; then
    echo "ERROR: preflight accepted veth named eth0 without --allow-test-veth" >&2
    exit 1
fi
ip netns exec "${NS_PI}" "${PYTHON_BIN}" "${ROOT_DIR}/linux_native.py" preflight \
    --config "${CFG_PATH}" --runtime "${RUNTIME_DIR}" --state-dir "${STATE_DIR}" \
    --allow-test-veth > "${TMP_DIR}/preflight.json"

echo "[2/5] Starting synthetic PS5 TCP/UDP server inside ${NS_PS5}..."
PS5_RESULT="${TMP_DIR}/ps5_server.json"
PS5_READY="${TMP_DIR}/ps5_ready"
ip netns exec "${NS_PS5}" "${PYTHON_BIN}" - "${PS5_IP}" "${PS5_RESULT}" "${PS5_READY}" <<'PY' &
import json, pathlib, socket, sys
bind_ip, out_path, ready_path = sys.argv[1], sys.argv[2], sys.argv[3]
tcp_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_srv.bind((bind_ip, 9295))
tcp_srv.listen(1)
tcp_srv.settimeout(15)

udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_srv.bind((bind_ip, 9296))
udp_srv.settimeout(15)

pathlib.Path(ready_path).write_text("ready\n", encoding="utf-8")

conn, tcp_peer = tcp_srv.accept()
with conn:
    data = conn.recv(1024)
    conn.sendall(b"TCP_ACK:" + data)
tcp_srv.close()

udp_ports = []
for _ in range(2):
    msg, addr = udp_srv.recvfrom(2048)
    udp_ports.append({"peer_ip": addr[0], "peer_port": addr[1], "msg": msg.decode()})
    udp_srv.sendto(b"UDP_ACK:" + msg, addr)
udp_srv.close()

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"tcp_peer": list(tcp_peer), "udp_Datagrams": udp_ports}, f, indent=2)
PY
PS5_SRV_PID=$!
wait_for_server_ready "${PS5_READY}" "${PS5_SRV_PID}"

echo "[3/5] Starting Linux native baseline relay inside ${NS_PI}..."
ip netns exec "${NS_PI}" "${PYTHON_BIN}" "${ROOT_DIR}/linux_native.py" baseline \
    --config "${CFG_PATH}" --runtime "${RUNTIME_DIR}" --state-dir "${STATE_DIR}" \
    --allow-test-veth --seconds 30 > "${TMP_DIR}/relay_out.json" &
RELAY_PID=$!

wait_for_relay_running "${RUNTIME_DIR}/status.json" "${RELAY_PID}"

# Verify scoped nftables table is present inside NS_PI during run
ip netns exec "${NS_PI}" /usr/sbin/nft list table inet portal_native_nat > "${TMP_DIR}/nft_during.txt"

# Wait for Portal namespace neighbor cache to point PS5_IP at PI_MAC
wait_for_portal_arp "${NS_PORTAL}" "${PS5_IP}" "${PI_MAC}" "${RELAY_PID}"

echo "[4/5] Running synthetic Portal TCP + UDP INIT->BIG client inside ${NS_PORTAL}..."
ip netns exec "${NS_PORTAL}" "${PYTHON_BIN}" - "${PORTAL_IP}" "${PS5_IP}" <<'PY'
import socket, sys
portal_ip, ps5_ip = sys.argv[1], sys.argv[2]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ts:
    ts.settimeout(4)
    ts.bind((portal_ip, 51111))
    ts.connect((ps5_ip, 9295))
    ts.sendall(b"HELLO_PS5")
    reply = ts.recv(1024)
    assert reply == b"TCP_ACK:HELLO_PS5", f"Unexpected TCP reply: {reply!r}"

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as us:
    us.settimeout(4)
    us.bind((portal_ip, 52222))
    for label in (b"INIT_PKT", b"BIG_PKT"):
        us.sendto(label, (ps5_ip, 9296))
        data, src = us.recvfrom(2048)
        assert src == (ps5_ip, 9296), f"Unexpected UDP source: {src!r}"
        assert data == b"UDP_ACK:" + label, f"Unexpected UDP reply: {data!r}"
PY

wait "${PS5_SRV_PID}"
stop_relay_controlled "${NS_PI}" "${RUNTIME_DIR}" "${RELAY_PID}"

echo "[5/5] Verifying NAT port stability, nft cleanup, and baseline state..."
if ip netns exec "${NS_PI}" /usr/sbin/nft list table inet portal_native_nat >/dev/null 2>&1; then
    echo "ERROR: inet portal_native_nat was not removed after relay exit" >&2
    exit 1
fi

"${PYTHON_BIN}" - "${PS5_RESULT}" "${RUNTIME_DIR}" "${STATE_DIR}" "${PI_IP}" <<'PY'
import json, pathlib, sys
ps5_res = json.loads(pathlib.Path(sys.argv[1]).read_text())
runtime = pathlib.Path(sys.argv[2])
state_dir = pathlib.Path(sys.argv[3])
pi_ip = sys.argv[4]

assert ps5_res["tcp_peer"][0] == pi_ip
assert 58001 <= ps5_res["tcp_peer"][1] <= 58064
u0, u1 = ps5_res["udp_Datagrams"]
assert u0["peer_ip"] == pi_ip and u1["peer_ip"] == pi_ip
assert u0["peer_port"] == u1["peer_port"], "UDP NAT port changed between INIT and BIG!"
assert 58001 <= u0["peer_port"] <= 58064

status = json.loads((runtime / "status.json").read_text())
assert status["state"] == "stopped", status
assert status["counts"].get("forwarded_out", 0) >= 3, status
assert status["counts"].get("forwarded_in", 0) >= 3, status
assert status["counts"].get("modified_packets_including_retransmits", 0) == 0, status
assert not (runtime / "baseline-accepted.json").exists()
assert not (state_dir / "baseline-accepted.json").exists()
print("Isolated Linux netns E2E verification succeeded.")
PY
