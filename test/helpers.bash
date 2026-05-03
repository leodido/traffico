#!/usr/bin/env bash

SCAPY_HELPER="$BATS_TEST_DIRNAME/scapy_packets.py"
SCAPY_SNIFF_TIMEOUT="${SCAPY_SNIFF_TIMEOUT:-2}"

fixtures() {
  FIXTURE_ROOT="$BATS_TEST_DIRNAME/fixtures/$1"
  # shellcheck disable=SC2034
  RELATIVE_FIXTURE_ROOT="${FIXTURE_ROOT#"$BATS_CWD"/}"
}

setsuite() {
  local PREFIX
  PREFIX="$(basename "$BATS_TEST_FILENAME" .bats)"
  echo "${PREFIX%%.*}: "
}

# Start a background sniffer on IFACE matching packets with IP_ID.
# Usage: start_sniffer IFACE IP_ID [SRC_IP] [DST_IP]
start_sniffer() {
  local iface="$1" ip_id="$2" src_ip="${3:-}" dst_ip="${4:-}"
  local sniff_args=(--iface "$iface" --ip-id "$ip_id" --timeout "$SCAPY_SNIFF_TIMEOUT")
  [ -n "$src_ip" ] && sniff_args+=(--src-ip "$src_ip")
  [ -n "$dst_ip" ] && sniff_args+=(--dst-ip "$dst_ip")

  python3 "$SCAPY_HELPER" sniff "${sniff_args[@]}" &
  SNIFFER_PID=$!
  SNIFFER_STATUS_FILE="$BATS_TEST_TMPDIR/sniffer_status"
  # Brief settle time for the sniffer to attach
  sleep 0.3
}

# Wait for the background sniffer and capture its exit code.
# Returns: 0 if packet was seen, 1 if timeout (not seen).
wait_sniffer() {
  local rc=0
  wait "$SNIFFER_PID" || rc=$?
  echo "$rc" > "$SNIFFER_STATUS_FILE"
  return $rc
}

# Send a crafted packet from inside a namespace.
# Usage: scapy_send NETNS IFACE [args...]
# All args after IFACE are passed to scapy_packets.py send.
scapy_send() {
  local netns="$1" iface="$2"
  shift 2
  ip netns exec "$netns" python3 "$SCAPY_HELPER" send --iface "$iface" "$@"
}

# Populate ARP caches so Scapy probes don't get lost waiting for ARP.
arp_prewarm() {
  local netns="$1"
  ip netns exec "$netns" ping -W1 -4 -c1 "$VETH_ADDR" &>/dev/null || true
  sleep 0.1
}

# Assert a packet is seen on the wire (allowed by BPF).
# Usage: assert_packet_seen NETNS IP_ID [send_args...]
# Starts sniffer on VETH, sends from PEER inside NETNS, asserts sniffer sees it.
assert_packet_seen() {
  local netns="$1" ip_id="$2"
  shift 2

  start_sniffer "$VETH" "$ip_id"
  scapy_send "$netns" "$PEER" --ip-id "$ip_id" "$@"
  wait_sniffer
  local rc=$?
  [ $rc -eq 0 ] || {
    echo "# FAIL: expected packet (ip_id=$ip_id) to be seen on $VETH but it was not" >&3
    return 1
  }
}

# Assert a packet is NOT seen on the wire (blocked by BPF).
# Usage: assert_packet_blocked NETNS IP_ID [send_args...]
assert_packet_blocked() {
  local netns="$1" ip_id="$2"
  shift 2

  start_sniffer "$VETH" "$ip_id"
  scapy_send "$netns" "$PEER" --ip-id "$ip_id" "$@"
  local rc=0
  wait "$SNIFFER_PID" || rc=$?
  if [ $rc -eq 0 ]; then
    echo "# FAIL: expected packet (ip_id=$ip_id) to be blocked but it appeared on $VETH" >&3
    return 1
  fi
}