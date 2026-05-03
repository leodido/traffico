#!/usr/bin/env bats

load helpers
fixtures cni
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

setup() {
    echo "# setup:" >&3

    load net

    NETNS="ns$((RANDOM % 10))"

    new_netns "${NETNS}"
    setup_net "${NETNS}"
    new_server
}

teardown() {
    echo "# teardown:" >&3

    del_netdev
    del_netns "${NETNS}"
    del_server
}

@test "allow_ipv4 via CNI" {
    run curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT}" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    echo "# installing allow_ipv4 in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat '$FIXTURE_ROOT/attach_allow_ipv4_in.json' | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:${SERVER_PORT} (allowed IP)" >&3
}

@test "block_ipv4 via CNI" {
    run curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT}" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    echo "# installing block_ipv4 in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat '$FIXTURE_ROOT/attach_block_ipv4_in.json' | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ ! $status -eq 0 ]
    echo "# cannot reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
}

@test "block_port via CNI" {
    run curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT}" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    echo "# installing block_port in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat '$FIXTURE_ROOT/attach_block_port_in.json' | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ ! $status -eq 0 ]
    echo "# cannot reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
}

@test "block_private_ipv4" {
    run curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT}" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    echo "# installing block_private_ipv4 in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat "$FIXTURE_ROOT/attach_in.json" | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    OUT=$(cat "$FIXTURE_ROOT/attach_out.json")
    run diff -u <(echo "$OUT") <(echo "$output")
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ ! $status -eq 0 ]
    echo "# cannot reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
}