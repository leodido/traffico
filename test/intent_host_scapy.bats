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

@test "Intent host-wide TCP permit allows multiple destination ports" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "tcp/${VETH_ADDR}" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 21001 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 443
    assert_packet_seen "${NETNS}" 21002 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 8443
    assert_packet_blocked "${NETNS}" 21003 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 443
    assert_packet_blocked "${NETNS}" 21004 \
        --type tcp --dst-ip "${PEER_ADDR}" --dst-port 443
}

@test "Intent host-wide UDP permit allows multiple destination ports" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "udp/${VETH_ADDR}" >/dev/null 3>&- &
    wait_for_intent_tc_state

    assert_packet_seen "${NETNS}" 22001 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 123
    assert_packet_seen "${NETNS}" 22002 \
        --type udp --dst-ip "${VETH_ADDR}" --dst-port 9999
    assert_packet_blocked "${NETNS}" 22003 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 123
    assert_packet_blocked "${NETNS}" 22004 \
        --type udp --dst-ip "${PEER_ADDR}" --dst-port 123
}
