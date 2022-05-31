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