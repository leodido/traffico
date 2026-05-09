#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

RAW_HELPER="$BATS_TEST_DIRNAME/raw_packets.py"
RAW_SNIFF_TIMEOUT="${RAW_SNIFF_TIMEOUT:-2}"

setup() {
    echo "# setup:" >&3

    load net

    NETNS="ns$((RANDOM % 10))"

    new_netns "${NETNS}"
    setup_net "${NETNS}"
    arp_prewarm "${NETNS}"
}

teardown() {
    echo "# teardown:" >&3

    killall traffico &>/dev/null || true
    [ -n "${SNIFFER_PID:-}" ] && kill "$SNIFFER_PID" &>/dev/null || true
    del_netdev
    del_netns "${NETNS}"
}

start_raw_sniffer() {
    local ip_id="$1"

    python3 "$RAW_HELPER" sniff \
        --iface "$VETH" \
        --ip-id "$ip_id" \
        --src-ip "$PEER_ADDR" \
        --dst-ip "$VETH_ADDR" \
        --timeout "$RAW_SNIFF_TIMEOUT" &
    SNIFFER_PID=$!
    sleep 0.3
}

send_truncated_ihl() {
    local ip_id="$1"

    ip netns exec "$NETNS" python3 "$RAW_HELPER" send-truncated-ihl \
        --iface "$PEER" \
        --src-ip "$PEER_ADDR" \
        --dst-ip "$VETH_ADDR" \
        --ip-id "$ip_id" \
        --proto 6
}

assert_truncated_ihl_blocked() {
    local ip_id="$1"
    local rc=0

    start_raw_sniffer "$ip_id"
    send_truncated_ihl "$ip_id"
    wait "$SNIFFER_PID" || rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "# FAIL: malformed IPv4 packet (ip_id=$ip_id) appeared on $VETH" >&3
        return 1
    fi
}

@test "allow_proto drops IPv4 packet whose IHL extends past packet data" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_proto tcp >/dev/null 3>&- &
    sleep 1

    assert_truncated_ihl_blocked 4001
    echo "# blocked malformed IPv4 packet with oversized IHL" >&3
}
