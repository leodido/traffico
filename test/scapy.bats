#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

# Preflight: skip all tests if scapy is not available
setup_file() {
    if ! command -v python3 &>/dev/null; then
        skip "python3 not found: scapy tests require python3"
    fi
    if ! python3 -c "import scapy" &>/dev/null; then
        skip "scapy not installed: install python-scapy (Arch) or python3-scapy (Ubuntu)"
    fi
}

setup() {
    echo "# setup:" >&3

    load net

    NETNS="ns$((RANDOM % 10))"

    new_netns "${NETNS}"
    setup_net "${NETNS}"

    # Prewarm ARP so crafted packets aren't lost to ARP resolution
    arp_prewarm "${NETNS}"
}

teardown() {
    echo "# teardown:" >&3

    killall traffico &>/dev/null || true
    # Clean up any leftover sniffer
    [ -n "${SNIFFER_PID:-}" ] && kill "$SNIFFER_PID" &>/dev/null || true
    del_netdev
    del_netns "${NETNS}"
}

# --------------------------------------------------------------------------
# block_ipv4
# --------------------------------------------------------------------------

@test "block_ipv4: drops packet with IP options (IHL > 5)" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_ipv4 "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 1001 \
        --type tcp --dst-ip "${VETH_ADDR}" --ip-options
    echo "# blocked IPv4 packet with IP options to ${VETH_ADDR}" >&3
}

@test "block_ipv4: drops fragmented packet to blocked IP" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_ipv4 "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    # First fragment
    assert_packet_blocked "${NETNS}" 1002 \
        --type fragment-first --dst-ip "${VETH_ADDR}"
    echo "# blocked first fragment to ${VETH_ADDR}" >&3

    # Subsequent fragment
    assert_packet_blocked "${NETNS}" 1003 \
        --type fragment-subsequent --dst-ip "${VETH_ADDR}" --frag-offset 10
    echo "# blocked subsequent fragment to ${VETH_ADDR}" >&3
}

# --------------------------------------------------------------------------
# block_port
# --------------------------------------------------------------------------

@test "block_port: drops TCP with IP options when port matches" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 2001 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 8787 --ip-options
    echo "# blocked TCP to port 8787 with IP options" >&3
}

@test "block_port: allows TCP with IP options when port does not match" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 2002 \
        --type tcp --dst-ip "${VETH_ADDR}" --dst-port 9999 --ip-options
    echo "# allowed TCP to port 9999 with IP options (blocked port is 8787)" >&3
}

@test "block_port: drops first fragment with blocked port" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 2003 \
        --type fragment-first --dst-ip "${VETH_ADDR}" --dst-port 8787
    echo "# blocked first fragment to port 8787" >&3
}

@test "block_port: allows subsequent fragment (fail-open)" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 2004 \
        --type fragment-subsequent --dst-ip "${VETH_ADDR}" --frag-offset 10
    echo "# allowed subsequent fragment (fail-open for block_*)" >&3
}

# --------------------------------------------------------------------------
# block_private_ipv4
# --------------------------------------------------------------------------

@test "block_private_ipv4: allows ICMP to non-private destination" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 3001 \
        --type icmp --dst-ip 8.8.8.8
    echo "# allowed ICMP to 8.8.8.8 (non-private)" >&3
}

@test "block_private_ipv4: drops ICMP to private destination" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 3002 \
        --type icmp --dst-ip 10.0.0.1
    echo "# blocked ICMP to 10.0.0.1 (private)" >&3
}

@test "block_private_ipv4: allows TCP source port 22 to private (SSH exemption)" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 3003 \
        --type tcp --dst-ip 10.0.0.1 --src-port 22
    echo "# allowed TCP src port 22 to 10.0.0.1 (SSH exemption)" >&3
}

@test "block_private_ipv4: allows TCP source port 22 with IP options (SSH + IHL > 5)" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 3004 \
        --type tcp --dst-ip 10.0.0.1 --src-port 22 --ip-options
    echo "# allowed TCP src port 22 with IP options to 10.0.0.1" >&3
}

@test "block_private_ipv4: drops UDP source port 22 to private" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 3005 \
        --type udp --dst-ip 10.0.0.1 --src-port 22
    echo "# blocked UDP src port 22 to 10.0.0.1 (SSH exemption is TCP-only)" >&3
}

@test "block_private_ipv4: drops GRE to private destination" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 3006 \
        --type gre --dst-ip 10.0.0.1
    echo "# blocked GRE to 10.0.0.1 (non-TCP/UDP to private)" >&3
}

@test "block_private_ipv4: drops first fragment to private, allows subsequent" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress block_private_ipv4 >/dev/null 3>&- &
    sleep 1

    # First fragment to private subnet
    assert_packet_blocked "${NETNS}" 3007 \
        --type fragment-first --dst-ip 10.0.0.1 --dst-port 80
    echo "# blocked first fragment to 10.0.0.1" >&3

    # Subsequent fragment: fail-open for block_* programs
    assert_packet_seen "${NETNS}" 3008 \
        --type fragment-subsequent --dst-ip 10.0.0.1 --frag-offset 10
    echo "# allowed subsequent fragment to 10.0.0.1 (fail-open)" >&3
}
