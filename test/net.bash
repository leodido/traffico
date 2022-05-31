#!/usr/bin/env bash

del_netns() {
    echo "# remove namespace $1 (if it exists)" >&3
    ip netns delete "$1" &>/dev/null || true
}

new_netns() {
    del_netns "$1"
    echo "# create namespace $1" >&3
    ip netns add "$1" &>/dev/null
}

setup_net() {
    export VETH="veth0"
    export PEER="peer0"
    export VETH_ADDR="10.22.1.1"
    export PEER_ADDR="10.22.1.2"

    echo "# create veth link $VETH <-> $PEER" >&3
    ip link add "$VETH" type veth peer name "$PEER" &>/dev/null

    echo "# assign device $PEER to namespace $1" >&3
    ip link set "$PEER" netns "$1" &>/dev/null

    echo "# setup address of $VETH" >&3
    ip addr add "$VETH_ADDR/24" dev "$VETH" &>/dev/null
    ip link set "$VETH" up &>/dev/null

    echo "# setup address of $PEER" >&3
    ip netns exec "$1" ip addr add "$PEER_ADDR"/24 dev "$PEER" &>/dev/null
    ip netns exec "$1" ip link set "$PEER" up &>/dev/null
    ip netns exec "$1" ip link set lo up &>/dev/null
    ip netns exec "$1" ip route add default via "$VETH_ADDR" &>/dev/null
}

del_netdev() {
    echo "# delete device $VETH" >&3
    ip link delete "$VETH" &>/dev/null
}

new_server() {
    export SERVER_PORT=8787
    echo "# serving $BATS_TMPDIR at $SERVER_PORT" >&3
    mini_httpd -d "$BATS_TMPDIR" -p "$SERVER_PORT" -i "$BATS_RUN_TMPDIR/mini_httpd.pid" &>/dev/null
}

del_server() {
    echo "# shutdown server" >&3
    pkill -F "$BATS_RUN_TMPDIR/mini_httpd.pid" &>/dev/null
}
