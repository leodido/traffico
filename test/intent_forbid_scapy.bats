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

@test "Intent forbid blocks a port inside a host-wide TCP permit" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --permit arp \
        --permit "tcp/${VETH_ADDR}" \
        --forbid "tcp/${VETH_ADDR}:22" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 22001 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 443
    assert_packet_seen "${NETNS}" 22002 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 8443
    assert_packet_blocked "${NETNS}" 22003 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 22
    assert_packet_blocked "${NETNS}" 22004 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 22
}

@test "Intent mixed permit forbid stays fail closed for VLAN IPv4 packets" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --permit arp \
        --permit "tcp/${VETH_ADDR}" \
        --forbid "tcp/${VETH_ADDR}:22" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_blocked "${NETNS}" 22005 \
        --type vlan-inner-ipv4 --dst-ip "${VETH_ADDR}" --dst-port 443
}

@test "Intent block alias has the same live semantics as forbid" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "udp/${VETH_ADDR}" \
        --block "udp/${VETH_ADDR}:123" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 22101 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 9999
    assert_packet_blocked "${NETNS}" 22102 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 123
}

@test "Intent forbid beats an exact permit" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --permit arp \
        --permit "tcp/${VETH_ADDR}:443" \
        --forbid "tcp/${VETH_ADDR}:443" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_blocked "${NETNS}" 22201 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 443
}

@test "Intent forbid ARP beats permit ARP" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --permit arp \
        --forbid arp >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_blocked "${NETNS}" 22301 \
        --type arp-request --src-ip "${PEER_ADDR}" --dst-ip "${VETH_ADDR}"
}

@test "Intent forbid DNS beats permit DNS" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --permit arp \
        --permit "dns/${VETH_ADDR}" \
        --forbid "dns/${VETH_ADDR}" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_blocked "${NETNS}" 22401 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 53
    assert_packet_blocked "${NETNS}" 22402 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 53
}

@test "Intent DNS forbid carves out host-wide TCP and UDP permits" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --permit arp \
        --permit "tcp/${VETH_ADDR}" \
        --permit "udp/${VETH_ADDR}" \
        --forbid "dns/${VETH_ADDR}" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_blocked "${NETNS}" 22501 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 53
    assert_packet_blocked "${NETNS}" 22502 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 53
    assert_packet_seen "${NETNS}" 22503 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 443
    assert_packet_seen "${NETNS}" 22504 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 123
}
