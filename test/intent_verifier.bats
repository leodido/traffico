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

@test "Intent BPF verifier accepts the maximum v0.6 rule envelope" {
    local args=(-i "${PEER}" --at egress)
    local i

    # Keep all 64 action rows while permitting ARP for L3 Scapy sends.
    args+=(--allow arp)
    for i in {1..31}; do
        args+=(--allow "tcp/${VETH_ADDR}:$((10000 + i))")
    done
    for i in {1..32}; do
        args+=(--forbid "tcp/${VETH_ADDR}:$((20000 + i))")
    done

    ip netns exec "${NETNS}" traffico "${args[@]}" >/dev/null 3>&- &
    wait_for_intent_tc_state
    arp_prewarm "${NETNS}"

    assert_packet_blocked "${NETNS}" 23001 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 20001
    assert_packet_blocked "${NETNS}" 23002 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 20032
    assert_packet_seen "${NETNS}" 23003 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 10001
    assert_packet_seen "${NETNS}" 23004 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 10031
    assert_packet_blocked "${NETNS}" 23005 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 443
}

@test "Intent rejects the 33rd forbid before attach and leaves TC untouched" {
    local args=(-i "${PEER}" --at egress --dry-run)
    local i

    for i in {1..32}; do
        args+=(--allow "tcp/10.0.0.${i}")
    done
    for i in {1..33}; do
        args+=(--forbid "tcp/10.0.1.${i}:22")
    done

    run ip netns exec "${NETNS}" traffico "${args[@]}"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: too many forbids: 'tcp/10.0.1.33:22'" ]
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$output" = "" ]
}
