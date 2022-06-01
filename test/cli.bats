#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

setup() {
    echo "# setup:" >&3

    load net

    NETNS="ns$((RANDOM % 10))"

    new_netns "${NETNS}"
    setup_net "${NETNS}"
}

teardown() {
    echo "# teardown:" >&3

    killall traffico &>/dev/null || true
    del_netdev
    del_netns "${NETNS}"
}

@test "install nop program at egress" {
    run ip netns exec "${NETNS}" traffico -i "${PEER}" nop >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
}

@test "install nop program at ingress" {
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at ingress nop >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
}

@test "--no-cleanup works" {
    echo "# traffico up at interface ${PEER}" >&3
    run ip netns exec "${NETNS}" traffico --no-cleanup -i "${PEER}" --at ingress nop >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    killall traffico
    echo "# traffico down" >&3
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# tc qdisc still there" >&3
    run bpftool prog show name nop
    OUT=${lines[0]##*: } >&3
    [ "${OUT%%  *}" == "sched_cls" ]
    echo "# BPF program still there" >&3
    run ip netns exec "${NETNS}" tc qdisc del dev "${PEER}" clsact
}

@test "block_private_ipv4 blocks ICMP packets" {
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 10.22.1.2
    [ $status -eq 0 ]
    run ip netns exec "${NETNS}" traffico -i lo --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev lo clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 10.22.1.2
    [ $status -eq 1 ]
}