#!/usr/bin/env bats

setup_file() {
    load helpers

    export BATS_TEST_NAME_PREFIX=$(setsuite)
}

setup() {
    echo "# setup" >&3

    load ns

    NETNS="ns$((RANDOM % 10))"

    new_netns "${NETNS}"
    setup_net "${NETNS}"
}

teardown() {
    echo "# teardown" >&3

    killall traffico || true
    del_netdev
    del_netns "${NETNS}"
}

@test "install nop program at egress" {
    run ip netns exec "${NETNS}" traffico -i peer0 nop >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
}

@test "install nop program at ingress" {
    run ip netns exec "${NETNS}" traffico -i peer0 --at ingress nop >/dev/null 3>&- &
    sleep 1
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
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