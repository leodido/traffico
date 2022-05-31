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
    local VETH="veth0"
    local PEER="peer0"
    local VETH_ADDR="10.22.1.1"
    local PEER_ADDR="10.22.1.2"

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
    local VETH="veth0"
    echo "# delete device $VETH" >&3
    ip link delete "$VETH" &>/dev/null
}

