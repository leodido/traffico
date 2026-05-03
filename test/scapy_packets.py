#!/usr/bin/env python3
"""Scapy helper for Bats tests. Provides send and sniff subcommands."""

import argparse
import sys

from scapy.all import (
    IP,
    TCP,
    UDP,
    ICMP,
    GRE,
    Ether,
    Raw,
    IPOption,
    send as scapy_send,
    sniff,
    conf,
)

# Suppress Scapy warnings
conf.verb = 0


def build_ip_layer(args):
    """Build an IP layer with optional IP options (NOP padding to force IHL > 5)."""
    ip = IP(src=args.src_ip, dst=args.dst_ip, id=args.ip_id)

    if args.ip_options:
        # Add NOP options to push IHL to 8 (32 bytes total header)
        ip.options = [IPOption(b"\x01")] * 12

    if args.frag_offset is not None:
        ip.frag = args.frag_offset
        if args.frag_offset == 0 and args.more_fragments:
            ip.flags = "MF"

    if args.proto_override:
        ip.proto = int(args.proto_override)

    return ip


def cmd_send(args):
    """Craft and send a packet."""
    ip = build_ip_layer(args)

    if args.type == "tcp":
        pkt = ip / TCP(sport=args.src_port, dport=args.dst_port) / Raw(b"X" * 20)
    elif args.type == "udp":
        pkt = ip / UDP(sport=args.src_port, dport=args.dst_port) / Raw(b"X" * 20)
    elif args.type == "icmp":
        pkt = ip / ICMP(type=8, id=args.ip_id) / Raw(b"X" * 20)
    elif args.type == "gre":
        pkt = ip / GRE() / Raw(b"X" * 20)
    elif args.type == "fragment-first":
        # First fragment: MF=1, offset=0, carries L4 header
        ip.flags = "MF"
        ip.frag = 0
        pkt = ip / TCP(sport=args.src_port, dport=args.dst_port) / Raw(b"X" * 20)
    elif args.type == "fragment-subsequent":
        # Subsequent fragment: offset > 0, no L4 header
        ip.frag = args.frag_offset if args.frag_offset else 10
        pkt = ip / Raw(b"X" * 20)
    else:
        print(f"unknown packet type: {args.type}", file=sys.stderr)
        sys.exit(2)

    # Use L3 send: the kernel adds the Ethernet header and routes
    # through the default gateway. The packet hits TC egress on its
    # way out, which is where the BPF program is attached.
    try:
        scapy_send(pkt, verbose=False)
    except OSError:
        # ENOBUFFS / ENETUNREACH is expected when the BPF program
        # drops the packet at TC egress. The sniffer judges the result.
        pass


def cmd_sniff(args):
    """Sniff for a matching packet. Exit 0 if seen, 1 if timeout."""
    timeout = args.timeout
    ip_id = args.ip_id

    def match_filter(pkt):
        if not pkt.haslayer(IP):
            return False
        ip = pkt[IP]
        if ip.id != ip_id:
            return False
        if args.src_ip and ip.src != args.src_ip:
            return False
        if args.dst_ip and ip.dst != args.dst_ip:
            return False
        return True

    result = sniff(
        iface=args.iface,
        timeout=timeout,
        count=1,
        lfilter=match_filter,
        store=True,
    )

    if len(result) > 0:
        sys.exit(0)  # packet seen
    else:
        sys.exit(1)  # timeout, packet not seen


def main():
    parser = argparse.ArgumentParser(description="Scapy packet helper for Bats tests")
    sub = parser.add_subparsers(dest="command", required=True)

    # send subcommand
    p_send = sub.add_parser("send", help="Craft and send a packet")
    p_send.add_argument("--iface", required=True)
    p_send.add_argument("--type", required=True,
                        choices=["tcp", "udp", "icmp", "gre",
                                 "fragment-first", "fragment-subsequent"])
    p_send.add_argument("--src-ip", default="10.22.1.2")
    p_send.add_argument("--dst-ip", default="10.22.1.1")
    p_send.add_argument("--src-port", type=int, default=12345)
    p_send.add_argument("--dst-port", type=int, default=80)
    p_send.add_argument("--ip-id", type=int, default=1)
    p_send.add_argument("--ip-options", action="store_true",
                        help="Add NOP IP options to force IHL > 5")
    p_send.add_argument("--frag-offset", type=int, default=None)
    p_send.add_argument("--more-fragments", action="store_true")
    p_send.add_argument("--proto-override", default=None,
                        help="Override IP protocol number")

    # sniff subcommand
    p_sniff = sub.add_parser("sniff", help="Sniff for a matching packet")
    p_sniff.add_argument("--iface", required=True)
    p_sniff.add_argument("--timeout", type=float, default=2.0)
    p_sniff.add_argument("--ip-id", type=int, required=True)
    p_sniff.add_argument("--src-ip", default=None)
    p_sniff.add_argument("--dst-ip", default=None)

    args = parser.parse_args()

    if args.command == "send":
        cmd_send(args)
    elif args.command == "sniff":
        cmd_sniff(args)


if __name__ == "__main__":
    main()
