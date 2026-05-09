#!/usr/bin/env python3
"""Raw packet helper for tests that should not depend on Scapy."""

import argparse
import errno
import socket
import struct
import sys
import time


ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800


def checksum(data):
    """Compute the IPv4 header checksum for a byte string."""
    if len(data) % 2:
        data += b"\0"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def build_truncated_ihl_packet(args):
    """Build IPv4 whose IHL claims options that are not present."""
    src = socket.inet_aton(args.src_ip)
    dst = socket.inet_aton(args.dst_ip)
    version_ihl = (4 << 4) | 15
    total_length = 20

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,                  # DSCP/ECN
        total_length,
        args.ip_id,
        0,                  # flags/fragment offset
        64,                 # TTL
        args.proto,
        0,                  # checksum placeholder
        src,
        dst,
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def parse_mac(value):
    return bytes(int(part, 16) for part in value.split(":"))


def iface_mac(iface):
    with open(f"/sys/class/net/{iface}/address", "r", encoding="ascii") as f:
        return parse_mac(f.read().strip())


def cmd_send_truncated_ihl(args):
    ip_pkt = build_truncated_ihl_packet(args)
    src_mac = iface_mac(args.iface)
    dst_mac = parse_mac(args.dst_mac)
    frame = dst_mac + src_mac + struct.pack("!H", ETH_P_IP) + ip_pkt

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((args.iface, 0))
        sock.send(frame)
    except OSError as err:
        if err.errno not in (errno.ENOBUFS, errno.ENETUNREACH):
            raise
    finally:
        sock.close()


def packet_matches(pkt, args):
    if len(pkt) < 34:
        return False
    if pkt[12:14] != struct.pack("!H", ETH_P_IP):
        return False

    ip_offset = 14
    ip_id = int.from_bytes(pkt[ip_offset + 4:ip_offset + 6], "big")
    if ip_id != args.ip_id:
        return False

    if args.src_ip and pkt[ip_offset + 12:ip_offset + 16] != socket.inet_aton(args.src_ip):
        return False
    if args.dst_ip and pkt[ip_offset + 16:ip_offset + 20] != socket.inet_aton(args.dst_ip):
        return False

    return True


def cmd_sniff(args):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((args.iface, 0))
    sock.settimeout(0.1)

    deadline = time.monotonic() + args.timeout
    try:
        while time.monotonic() < deadline:
            try:
                pkt = sock.recv(65535)
            except socket.timeout:
                continue
            if packet_matches(pkt, args):
                sys.exit(0)
    finally:
        sock.close()

    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Raw packet helper for BPF tests")
    sub = parser.add_subparsers(dest="command", required=True)

    p_send = sub.add_parser("send-truncated-ihl")
    p_send.add_argument("--iface", required=True)
    p_send.add_argument("--src-ip", default="10.22.1.2")
    p_send.add_argument("--dst-ip", default="10.22.1.1")
    p_send.add_argument("--dst-mac", default="ff:ff:ff:ff:ff:ff")
    p_send.add_argument("--ip-id", type=int, required=True)
    p_send.add_argument("--proto", type=int, default=6)

    p_sniff = sub.add_parser("sniff")
    p_sniff.add_argument("--iface", required=True)
    p_sniff.add_argument("--timeout", type=float, default=2.0)
    p_sniff.add_argument("--ip-id", type=int, required=True)
    p_sniff.add_argument("--src-ip", default=None)
    p_sniff.add_argument("--dst-ip", default=None)

    args = parser.parse_args()
    if args.command == "send-truncated-ihl":
        cmd_send_truncated_ihl(args)
    elif args.command == "sniff":
        cmd_sniff(args)


if __name__ == "__main__":
    main()
