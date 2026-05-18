#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

setup() {
    load net
    NETNS="ns$((RANDOM % 10))"
    new_netns "${NETNS}"
    setup_net "${NETNS}"
}

teardown() {
    killall traffico &>/dev/null || true
    del_netdev
    del_netns "${NETNS}"
}

@test "Intent live attach is rejected until backend is implemented" {
    run traffico -i lo --at egress --allow arp
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: intent attach backend is not implemented; use --dry-run" ]
}

@test "--dry-run validates Intent without attaching" {
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "tcp/${VETH_ADDR}:443" \
        --dry-run
    [ $status -eq 0 ]
    [[ "$output" == *"intent dry-run: compiler ok"* ]]
    [[ "$output" == *"intent backend: not implemented"* ]]

    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$output" = "" ]
}

@test "--dry-run --explain prints deterministic intent" {
    run traffico -i lo --at egress \
        --allow udp/10.0.0.20:123 \
        --allow arp \
        --allow tcp/10.0.0.10:443 \
        --dry-run --explain
    [ $status -eq 0 ]
    [ "${lines[0]}" == "traffico intent" ]
    [ "${lines[1]}" == "interface: lo" ]
    [ "${lines[2]}" == "direction: egress" ]
    [ "${lines[3]}" == "default: drop" ]
    [[ "$output" == *"  1. ARP"* ]]
    [[ "$output" == *"  2. TCP to 10.0.0.10 destination port 443"* ]]
    [[ "$output" == *"  3. UDP to 10.0.0.20 destination port 123"* ]]
}
