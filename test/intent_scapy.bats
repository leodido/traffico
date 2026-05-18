#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

setup_file() {
    if ! command -v python3 &>/dev/null; then
        skip "python3 not found: scapy tests require python3"
    fi
    if ! python3 -c "import scapy" &>/dev/null; then
        skip "scapy not installed: install python-scapy (Arch) or python3-scapy (Ubuntu)"
    fi
}

setup() {
    load net
    NETNS="ns$((RANDOM % 10))"
    new_netns "${NETNS}"
    setup_net "${NETNS}"
    arp_prewarm "${NETNS}"
}

teardown() {
    killall traffico &>/dev/null || true
    [ -n "${SNIFFER_PID:-}" ] && kill "$SNIFFER_PID" &>/dev/null || true
    del_netdev
    del_netns "${NETNS}"
}

intent_tc_state_exists() {
    local qdisc
    local filter

    qdisc="$(ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact)"
    filter="$(ip netns exec "${NETNS}" tc filter show dev "${PEER}" egress)"

    [[ "${qdisc}" == *"clsact"* && "${filter}" != "" ]]
}

wait_for_intent_tc_state() {
    local i

    for i in {1..50}; do
        if intent_tc_state_exists; then
            return 0
        fi
        sleep 0.1
    done

    return 1
}

start_intent_primary() {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "dns/${VETH_ADDR}" \
        --allow "tcp/${VETH_ADDR}:8787" \
        --allow "udp/${VETH_ADDR}:123" >/dev/null 3>&- &
    wait_for_intent_tc_state
}

send_ipv4_l4_prefix() {
    local netns="$1"
    local ip_id="$2"
    local proto="$3"
    local total_length="$4"
    local src_port="$5"
    local dst_port="$6"

    ip netns exec "${netns}" python3 - "${PEER}" "${PEER_ADDR}" "${VETH_ADDR}" \
        "${ip_id}" "${proto}" "${total_length}" "${src_port}" "${dst_port}" <<'PY'
import socket
import struct
import sys
import time
import errno

from scapy.all import Ether, Raw, conf, sendp

conf.verb = 0

iface, src_ip, dst_ip = sys.argv[1:4]
ip_id = int(sys.argv[4])
proto = int(sys.argv[5])
total_length = int(sys.argv[6])
src_port = int(sys.argv[7])
dst_port = int(sys.argv[8])

ipv4 = struct.pack(
    "!BBHHHBBH4s4s",
    0x45,
    0,
    total_length,
    ip_id,
    0,
    64,
    proto,
    0,
    socket.inet_aton(src_ip),
    socket.inet_aton(dst_ip),
)
l4_prefix = struct.pack("!HH", src_port, dst_port)
pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0800) / Raw(ipv4 + l4_prefix)
for attempt in range(3):
    try:
        sendp(pkt, iface=iface, verbose=False)
        break
    except OSError as e:
        if e.errno == errno.ENOBUFS:
            if attempt < 2:
                time.sleep(0.2)
            continue
        raise
PY
}

send_truncated_arp() {
    local netns="$1"
    local ip_id="$2"

    ip netns exec "${netns}" python3 - "${PEER}" "${ip_id}" <<'PY'
import errno
import struct
import sys
import time

from scapy.all import Ether, Raw, conf, sendp

conf.verb = 0

iface = sys.argv[1]
ip_id = int(sys.argv[2])
arp_fixed_header = struct.pack(
    "!HHBBH",
    1,
    0x0800,
    6,
    4,
    ip_id & 0xFFFF,
)
pkt = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x0806) / Raw(arp_fixed_header)
for attempt in range(3):
    try:
        sendp(pkt, iface=iface, verbose=False)
        break
    except OSError as e:
        if e.errno == errno.ENOBUFS:
            if attempt < 2:
                time.sleep(0.2)
            continue
        raise
PY
}

start_truncated_arp_sniffer() {
    local iface="$1"
    local ip_id="$2"

    python3 - "${iface}" "${ip_id}" "${SCAPY_SNIFF_TIMEOUT}" <<'PY' &
import struct
import sys

from scapy.all import Ether, conf, sniff

conf.verb = 0

iface = sys.argv[1]
ip_id = int(sys.argv[2])
timeout = int(sys.argv[3])
arp_fixed_header = struct.pack("!HHBBH", 1, 0x0800, 6, 4, ip_id & 0xFFFF)

def matches(pkt):
    return pkt.haslayer(Ether) and pkt[Ether].type == 0x0806 and arp_fixed_header in bytes(pkt)

sys.exit(0 if sniff(iface=iface, timeout=timeout, count=1, lfilter=matches, store=True) else 1)
PY
    SNIFFER_PID=$!
    sleep 0.3
}

assert_l4_prefix_blocked() {
    local netns="$1"
    local ip_id="$2"
    local proto="$3"
    local total_length="$4"
    local src_port="$5"
    local dst_port="$6"
    local rc=0

    start_sniffer "$VETH" "$ip_id"
    send_ipv4_l4_prefix "${netns}" "${ip_id}" "${proto}" "${total_length}" "${src_port}" "${dst_port}"
    wait "$SNIFFER_PID" || rc=$?
    if [ $rc -eq 0 ]; then
        echo "# FAIL: expected L4-prefix packet (ip_id=$ip_id) to be blocked but it appeared on $VETH" >&3
        return 1
    fi
}

assert_truncated_arp_blocked() {
    local netns="$1"
    local ip_id="$2"
    local rc=0

    start_truncated_arp_sniffer "$VETH" "$ip_id"
    send_truncated_arp "${netns}" "${ip_id}"
    wait "$SNIFFER_PID" || rc=$?
    if [ $rc -eq 0 ]; then
        echo "# FAIL: expected truncated ARP packet (ip_id=$ip_id) to be blocked but it appeared on $VETH" >&3
        return 1
    fi
}

@test "Intent primary scenario allows correlated permits" {
    start_intent_primary

    assert_packet_seen "${NETNS}" 11001 \
        --type arp-request --src-ip "${PEER_ADDR}" --dst-ip "${VETH_ADDR}"

    assert_packet_seen "${NETNS}" 11002 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 8787

    assert_packet_seen "${NETNS}" 11003 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 123

    assert_packet_seen "${NETNS}" 11004 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 53

    assert_packet_seen "${NETNS}" 11005 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 53
}

@test "Intent primary scenario blocks rectangular leaks" {
    start_intent_primary

    assert_packet_blocked "${NETNS}" 12001 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 8787

    assert_packet_blocked "${NETNS}" 12002 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 123

    assert_packet_blocked "${NETNS}" 12003 \
        --type tcp --dst-ip "${PEER_ADDR}" --dst-port 8787

    assert_packet_blocked "${NETNS}" 12004 \
        --type udp --dst-ip "${PEER_ADDR}" --dst-port 53
}

@test "Intent backend fails closed on malformed and unenforceable packets" {
    start_intent_primary

    assert_packet_blocked "${NETNS}" 13001 \
        --type ethernet-truncated

    assert_packet_blocked "${NETNS}" 13002 \
        --type ipv4-invalid-ihl --dst-ip "${VETH_ADDR}"

    assert_packet_blocked "${NETNS}" 13003 \
        --type ipv4-truncated-l4 --dst-ip "${VETH_ADDR}"

    assert_packet_blocked "${NETNS}" 13004 \
        --type fragment-subsequent --dst-ip "${VETH_ADDR}" --frag-offset 10

    assert_packet_blocked "${NETNS}" 13005 \
        --type ipv6-tcp --dst-port 8787

    assert_packet_blocked "${NETNS}" 13006 \
        --type icmp --dst-ip "${VETH_ADDR}"
}

@test "Intent backend blocks declared-length L4 truncation with matching ports" {
    start_intent_primary

    assert_l4_prefix_blocked "${NETNS}" 13501 6 24 12345 8787
    assert_l4_prefix_blocked "${NETNS}" 13502 17 24 12345 123
    assert_l4_prefix_blocked "${NETNS}" 13503 6 22 12345 8787
}

@test "Intent backend fails closed on ARP and IPv4 fragmentation edge cases" {
    start_intent_primary

    assert_truncated_arp_blocked "${NETNS}" 13601

    assert_packet_blocked "${NETNS}" 13602 \
        --type fragment-first --dst-ip "${VETH_ADDR}" --dst-port 8787
}

@test "Intent behavior is independent of allow order" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow "udp/${VETH_ADDR}:123" \
        --allow "tcp/${VETH_ADDR}:8787" \
        --allow "dns/${VETH_ADDR}" \
        --allow arp >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 14001 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 8787

    assert_packet_seen "${NETNS}" 14002 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 123

    assert_packet_blocked "${NETNS}" 14003 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 123
}
