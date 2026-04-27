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

@test "block_ip blocks specific IP" {
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 0 ]
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_ip "${VETH_ADDR}" >/dev/null 3>&- &
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

@test "allow_dns permits DNS to approved resolver" {
    # Start a TCP listener on port 53 (simulating a DNS resolver)
    python3 -c "
import socket, threading
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
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_dns "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 2 --silent "telnet://${VETH_ADDR}:53"
    [ $status -eq 0 ]
    echo "# DNS to approved resolver ${VETH_ADDR}:53 allowed" >&3
    kill $DNS_PID 2>/dev/null || true
}

@test "allow_dns blocks DNS to other resolvers" {
    # Start a TCP listener on port 53 (simulating an unauthorized resolver)
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
    # Allow DNS only to PEER_ADDR (not VETH_ADDR where the server is)
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_dns "${PEER_ADDR}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 2 --silent "telnet://${VETH_ADDR}:53"
    [ ! $status -eq 0 ]
    echo "# DNS to ${VETH_ADDR}:53 blocked (only ${PEER_ADDR} allowed)" >&3
    kill $DNS_PID 2>/dev/null || true
}

@test "allow_dns does not block non-DNS traffic" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    # Allow DNS only to PEER_ADDR — but non-DNS traffic should still pass
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_dns "${PEER_ADDR}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# non-DNS traffic to ${VETH_ADDR}:${SERVER_PORT} still works" >&3
}

@test "allow_port allows specific port" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_port "${SERVER_PORT}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:${SERVER_PORT} (allowed port)" >&3
}

@test "allow_port blocks other ports" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_port 9999 >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ ! $status -eq 0 ]
    echo "# cannot reach ${VETH_ADDR}:${SERVER_PORT} (only port 9999 allowed)" >&3
}

@test "allow_port does not block ICMP" {
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 0 ]
    echo "# can ping ${VETH_ADDR} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_port 9999 >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 0 ]
    echo "# can still ping ${VETH_ADDR} (ICMP not blocked by allow_port)" >&3
}

@test "chain allow_ip+allow_port allows matching traffic" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress --chain "allow_ip:${VETH_ADDR},allow_port:${SERVER_PORT}" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can still reach ${VETH_ADDR}:${SERVER_PORT} (chain allows it)" >&3
}

@test "chain allow_ip+allow_port blocks non-matching IP" {
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 0 ]
    echo "# can ping ${VETH_ADDR} from the namespace" >&3
    # Allow only PEER_ADDR (not VETH_ADDR) on any port
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress --chain "allow_ip:${PEER_ADDR},allow_port:8787" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" ping -W1 -4 -c1 "${VETH_ADDR}"
    [ $status -eq 1 ]
    echo "# cannot ping ${VETH_ADDR} (chain blocks wrong IP)" >&3
}

@test "chain allow_ip+allow_port blocks non-matching port" {
    new_server
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ $status -eq 0 ]
    echo "# can reach ${VETH_ADDR}:${SERVER_PORT} from the namespace" >&3
    # Allow VETH_ADDR but only port 9999 (not SERVER_PORT)
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress --chain "allow_ip:${VETH_ADDR},allow_port:9999" >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
    run ip netns exec "${NETNS}" curl --max-time 1 --silent "${VETH_ADDR}:${SERVER_PORT}" >/dev/null
    [ ! $status -eq 0 ]
    echo "# cannot reach ${VETH_ADDR}:${SERVER_PORT} (chain blocks wrong port)" >&3
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