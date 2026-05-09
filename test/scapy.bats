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
# allow_ipv4
# --------------------------------------------------------------------------

@test "allow_ipv4: drops packet with invalid IHL" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ipv4 "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 4001 \
        --type ipv4-invalid-ihl --dst-ip "${VETH_ADDR}"
    echo "# blocked IPv4 packet with IHL < 5 to ${VETH_ADDR}" >&3
}

@test "allow_ipv4: drops packet with truncated IPv4 header" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ipv4 "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 4002 \
        --type ipv4-truncated-ihl --dst-ip "${VETH_ADDR}"
    echo "# blocked IPv4 packet whose IHL extends beyond packet data" >&3
}

@test "allow_ipv4: allows non-IPv4 EtherType" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ipv4 "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 4003 \
        --type ipv6-tcp --dst-port 8787
    echo "# allowed IPv6 TCP packet through IPv4-only allowlist" >&3
}

# --------------------------------------------------------------------------
# allow_port
# --------------------------------------------------------------------------

@test "allow_port: drops non-IPv4 EtherType" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 5001 \
        --type non-ipv4-tcp --dst-ip "${VETH_ADDR}" --dst-port 8787
    echo "# blocked non-IPv4 EtherType carrying TCP-like payload to allowed port" >&3
}

@test "allow_port: drops IPv6 TCP to allowed port" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 5002 \
        --type ipv6-tcp --dst-port 8787
    echo "# blocked IPv6 TCP to allowed IPv4 TCP/UDP port" >&3
}

@test "allow_port: allows fragmented non-TCP/UDP IPv4" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 5003 \
        --type fragment-subsequent --dst-ip "${VETH_ADDR}" --frag-offset 10 --proto-override 1
    echo "# allowed subsequent non-TCP/UDP IPv4 fragment" >&3
}

@test "allow_port: drops packet with truncated L4 header" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_port 8787 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 5004 \
        --type ipv4-truncated-l4 --dst-ip "${VETH_ADDR}"
    echo "# blocked IPv4 TCP packet with fewer than four L4 bytes" >&3
}

# --------------------------------------------------------------------------
# allow_dns
# --------------------------------------------------------------------------

@test "allow_dns: allows non-IPv4 EtherType" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_dns "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 6001 \
        --type non-ipv4-tcp --dst-ip "${VETH_ADDR}" --dst-port 53
    echo "# allowed non-IPv4 EtherType carrying DNS-like payload" >&3
}

@test "allow_dns: drops packet with truncated L4 header" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_dns "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 6002 \
        --type ipv4-truncated-l4 --dst-ip "${VETH_ADDR}"
    echo "# blocked IPv4 DNS candidate with fewer than four L4 bytes" >&3
}

@test "allow_dns: allows non-TCP/UDP protocol with DNS-shaped payload" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_dns "${VETH_ADDR}" >/dev/null 3>&- &
    sleep 1

    assert_packet_seen "${NETNS}" 6003 \
        --type ipv4-non-l4-dns-port --dst-ip "${VETH_ADDR}"
    echo "# allowed non-TCP/UDP IPv4 packet with DNS port-shaped payload" >&3
}

# --------------------------------------------------------------------------
# allow_ethertype
# --------------------------------------------------------------------------

@test "allow_ethertype: drops truncated Ethernet frame" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ethertype ipv4 >/dev/null 3>&- &
    sleep 1

    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$(echo $output | xargs)" == "qdisc clsact ffff: parent ffff:fff1" ]

    assert_packet_blocked "${NETNS}" 7001 \
        --type ethernet-truncated
    echo "# blocked frame shorter than Ethernet header" >&3
}

@test "allow_ethertype: drops QinQ when only inner EtherType is allowed" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ethertype ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 7003 \
        --type qinq-inner-ipv4 --dst-ip "${VETH_ADDR}"
    echo "# blocked QinQ frame when only the inner IPv4 EtherType matches" >&3
}

@test "allow_ethertype: drops disallowed EtherType" {
    ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress allow_ethertype ipv4 >/dev/null 3>&- &
    sleep 1

    assert_packet_blocked "${NETNS}" 7004 \
        --type non-ipv4-tcp --dst-ip "${VETH_ADDR}" --dst-port 8787
    echo "# blocked frame whose EtherType is not in the allowed set" >&3
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
