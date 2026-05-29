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
    RESOLVER_ADDR="198.51.100.53"
    SERVICE_ADDR="203.0.113.10"
    API_ADDR="203.0.113.20"
    TIME_ADDR="192.0.2.123"
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

@test "agent workload can use one resolver and one service while SSH is blocked" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "dns/${RESOLVER_ADDR}" \
        --allow "tcp/${SERVICE_ADDR}" \
        --forbid "tcp/${SERVICE_ADDR}:22" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 23001 \
        --type arp-request --src-ip "${PEER_ADDR}" --dst-ip "${VETH_ADDR}"
    assert_packet_seen "${NETNS}" 23002 \
        --type udp --dst-ip "${RESOLVER_ADDR}" --dst-port 53
    assert_packet_seen "${NETNS}" 23003 \
        --type tcp --dst-ip "${RESOLVER_ADDR}" --dst-port 53
    assert_packet_seen "${NETNS}" 23004 \
        --type tcp --dst-ip "${SERVICE_ADDR}" --dst-port 443
    assert_packet_blocked "${NETNS}" 23005 \
        --type tcp --dst-ip "${SERVICE_ADDR}" --dst-port 22
    assert_packet_blocked "${NETNS}" 23006 \
        --type udp --dst-ip "${SERVICE_ADDR}" --dst-port 22
    assert_packet_blocked "${NETNS}" 23007 \
        --type icmp --dst-ip "${SERVICE_ADDR}"
}

@test "service access can be broad while DNS is carved out" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "tcp/${SERVICE_ADDR}" \
        --allow "udp/${SERVICE_ADDR}" \
        --forbid "dns/${SERVICE_ADDR}" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_blocked "${NETNS}" 23101 \
        --type udp --dst-ip "${SERVICE_ADDR}" --dst-port 53
    assert_packet_blocked "${NETNS}" 23102 \
        --type tcp --dst-ip "${SERVICE_ADDR}" --dst-port 53
    assert_packet_seen "${NETNS}" 23103 \
        --type tcp --dst-ip "${SERVICE_ADDR}" --dst-port 443
    assert_packet_seen "${NETNS}" 23104 \
        --type udp --dst-ip "${SERVICE_ADDR}" --dst-port 123
    assert_packet_blocked "${NETNS}" 23105 \
        --type vlan-inner-ipv4 --dst-ip "${SERVICE_ADDR}" --dst-port 443
}

@test "block is the human-facing alias for forbid in examples" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "udp/${SERVICE_ADDR}" \
        --block "udp/${SERVICE_ADDR}:123" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 23201 \
        --type udp --dst-ip "${SERVICE_ADDR}" --dst-port 9999
    assert_packet_blocked "${NETNS}" 23202 \
        --type udp --dst-ip "${SERVICE_ADDR}" --dst-port 123
}

@test "ai agent egress quarantine allows resolver api and time source only" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "dns/${RESOLVER_ADDR}" \
        --allow "tcp/${API_ADDR}:443" \
        --allow "udp/${TIME_ADDR}:123" \
        --block "tcp/${API_ADDR}:22" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 23301 \
        --type arp-request --src-ip "${PEER_ADDR}" --dst-ip "${VETH_ADDR}"
    assert_packet_seen "${NETNS}" 23302 \
        --type udp --dst-ip "${RESOLVER_ADDR}" --dst-port 53
    assert_packet_seen "${NETNS}" 23303 \
        --type tcp --dst-ip "${RESOLVER_ADDR}" --dst-port 53
    assert_packet_seen "${NETNS}" 23304 \
        --type tcp --dst-ip "${API_ADDR}" --dst-port 443
    assert_packet_seen "${NETNS}" 23305 \
        --type udp --dst-ip "${TIME_ADDR}" --dst-port 123
    assert_packet_blocked "${NETNS}" 23306 \
        --type tcp --dst-ip "${API_ADDR}" --dst-port 22
    assert_packet_blocked "${NETNS}" 23307 \
        --type udp --dst-ip "${API_ADDR}" --dst-port 443
    assert_packet_blocked "${NETNS}" 23308 \
        --type tcp --dst-ip "${SERVICE_ADDR}" --dst-port 443
    assert_packet_blocked "${NETNS}" 23309 \
        --type icmp --dst-ip "${API_ADDR}"
}
