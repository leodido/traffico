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

@test "allow_ip via CNI" {
    run curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT}" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    echo "# installing allow_ip in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat '$FIXTURE_ROOT/attach_allow_ip_in.json' | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:${SERVER_PORT} (allowed IP)" >&3
}

@test "block_ip via CNI" {
    run curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT}" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    echo "# installing block_ip in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat '$FIXTURE_ROOT/attach_block_ip_in.json' | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ ! $status -eq 0 ]
    echo "# cannot reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
}

@test "allow_dns via CNI" {
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('${VETH_ADDR}', 53))
s.listen(1)
s.settimeout(5)
try:
    c, _ = s.accept()
    c.send(b'ok')
    c.close()
except: pass
s.close()
" &
    DNS_PID=$!
    sleep 0.5
    run ip netns exec "${NETNS}" curl --max-time 2 --silent "telnet://${VETH_ADDR}:53"
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:53 from the namespace" >&3
    # Restart listener for the post-attach test
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('${VETH_ADDR}', 53))
s.listen(1)
s.settimeout(5)
try:
    c, _ = s.accept()
    c.send(b'ok')
    c.close()
except: pass
s.close()
" &
    DNS_PID=$!
    sleep 0.5
    echo "# installing allow_dns in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat '$FIXTURE_ROOT/attach_allow_dns_in.json' | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 2 --silent "telnet://${VETH_ADDR}:53"
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:53 (approved resolver)" >&3
    kill $DNS_PID 2>/dev/null || true
}

@test "allow_port via CNI" {
    run curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT}" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    echo "# installing allow_port in the namespace" >&3
    run ip netns exec "${NETNS}" bash -c "cat '$FIXTURE_ROOT/attach_allow_port_in.json' | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    echo "# attach ok" >&3
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    echo "# qdisc ok" >&3
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:${SERVER_PORT} (allowed port)" >&3
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