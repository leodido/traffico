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
    del_server
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
    run bpftool prog show --json name nop
    [[ "$output" == *'"type":"sched_cls"'* ]]
    echo "# BPF program still there" >&3
    run ip netns exec "${NETNS}" tc qdisc del dev "${PEER}" clsact
}

@test "block_ipv4 blocks specific IP" {
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 0 ]
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_ipv4 "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 1 ]
}

@test "block_port blocks specific port" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_port "${SERVER_PORT}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ ! $status -eq 0 ]
    echo "# cannot reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
}

@test "block_port does not block other ports" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_port 9999 >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:${SERVER_PORT} (blocked port 9999, not ${SERVER_PORT})" >&3
}

@test "allow_ip allows specific IP" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ip "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:${SERVER_PORT} (allowed IP)" >&3
}

@test "allow_ip blocks other IPs" {
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ip "${PEER_ADDR}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 1 ]
    echo "# cannot reach ${VETH_ADDR} (only ${PEER_ADDR} allowed)" >&3
}

@test "allow_ip does not block localhost" {
    run ip netns exec "${NETNS}" traffico -i lo --at egress allow_ip "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev lo clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 127.0.0.1
    [ $status -eq 0 ]
    echo "# localhost still reachable (exempt from allow_ip)" >&3
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