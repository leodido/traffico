#!/usr/bin/env bats

load helpers
fixtures cni
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

setup() {
    echo "# setup" >&3

    load ns

    NETNS="ns$((RANDOM % 10))"

    new_netns "${NETNS}"
    setup_net "${NETNS}"
}

teardown() {
    echo "# teardown" >&3

    del_netdev
    del_netns "${NETNS}"
}

@test "attach" {
    run ip netns exec "${NETNS}" bash -c "cat "$FIXTURE_ROOT/attach_in.json" | CNI_COMMAND=ADD traffico-cni"
    [ $status -eq 0 ]
    OUT=$(cat "$FIXTURE_ROOT/attach_out.json")
    run diff -u <(echo "$OUT") <(echo "$output")
    [ $status -eq 0 ]
    run ip netns exec "${NETNS}" tc qdisc show dev peer0 clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]
}