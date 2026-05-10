                  _   _
                 | | | | o
 _|_  ,_    __,  | | | |     __   __
  |  /  |  /  |  |/  |/  |  /    /  \_
  |_/   |_/\_/|_/|__/|__/|_/\___/\__/
                 |\  |\
                 |/  |/

README

    traffico is a collection of tools to shape traffic on a network using traffic control tc(8).
    It can be used via a CLI tool (traffico) or as a CNI plugin (traffico-cni).
    For a list of the available programs and what they do see the BUILT-IN PROGRAMS section.

    The BUILT-IN PROGRAMS are very opinionated and made for the needs of the authors but the framework
    is flexible enough to be used for other purposes. You can add programs to the bpf/ directory
    to extend it to other use cases.

CONTACT

    If you have problems, question, ideas or suggestions, please contact us by
    posting to https://github.com/leodido/traffico/issues.

DOWNLOAD

    To download the very latest source do this:

    git clone https://github.com/leodido/traffico.git

AUTHORS

    Leonardo Di Donato
    Lorenzo Fontana

USAGE

    Traffico can be either used standalone or as a CNI plugin.

    traffico
        traffico is a CLI tool that can be used to load and unload the programs.
        You can choose an interface and choose whether the program will be loaded in
        "INGRESS" or "EGRESS".

        Example usage:
            traffico --ifname=eth0 --at=INGRESS block_private_ipv4

        Programs that accept runtime input (marked [input] in --help) take it
        as a second positional argument:
            traffico --ifname=eth0 block_ipv4 10.0.0.1
            traffico --ifname=eth0 block_port 443

    traffico-cni
        traffico-cni is a meta CNI plugin that allows the traffico programs to be used in CNI.

        Meta means that traffic-cni does not create any interface for you,
        it is intended to be used as a chained CNI plugin.

        The plugin block to use traffico-cni is very similar to how traffico is
        used as a CLI tool.

        {
            "type": "traffico-cni",
            "program": "block_private_ipv4",
            "attachPoint": "ingress"
        }

        Programs that accept runtime input use the "input" field:

        {
            "type": "traffico-cni",
            "program": "block_ipv4",
            "input": "10.0.0.1",
            "attachPoint": "egress"
        }

        Here's an example CNI config file featuring traffico-cni.

        {
            "name": "mynetwork",
            "cniVersion": "0.4.0",
            "plugins": [
                {
                    "type": "ptp",
                    "ipMasq": true,
                    "ipam": {
                        "type": "host-local",
                        "subnet": "10.10.10.0/24",
                        "resolvConf": "/etc/resolv.conf",
                        "routes": [
                            { "dst": "0.0.0.0/0" }
                        ]
                    },
                    "dns": {
                        "nameservers": ["1.1.1.1", "1.0.0.1"]
                    }
                },
                {
                    "type": "firewall"
                },
                {
                    "type": "traffico-cni",
                    "program": "block_private_ipv4",
                    "attachPoint": "ingress"
                },
                {
                    "type": "tc-redirect-tap"
                }
            ]
        }

DESIGN PRINCIPLES

    +-----------------------+------------------------------------------------+
    | Principle             | Description                                    |
    +-----------------------+------------------------------------------------+
    | Standalone vs chained | Standalone programs are the only filter on     |
    |                       | the interface and handle all traffic types     |
    |                       | themselves. Chained programs pass traffic      |
    |                       | they do not handle to the next program,        |
    |                       | trusting that an upstream filter (typically    |
    |                       | allow_ethertype) already constrained it.       |
    +-----------------------+------------------------------------------------+
    | Boundary failures     | block_* programs fail open (TC_ACT_OK) on      |
    |                       | truncated headers, unsupported protocols,      |
    |                       | and subsequent fragments because they target   |
    |                       | specific traffic. allow_* programs fail closed |
    |                       | (TC_ACT_SHOT) on the same failures because     |
    |                       | they define permitted traffic.                 |
    +-----------------------+------------------------------------------------+
    | L2 -> L3 -> L4       | Chains run cheapest and broadest checks         |
    | ordering              | first: allow_ethertype (L2), then allow_proto  |
    |                       | (L3), then allow_port or allow_dns (L4).       |
    |                       | allow_ipv4 fits after L2 and alongside or      |
    |                       | after L3 protocol filtering.                   |
    +-----------------------+------------------------------------------------+
    | Non-IPv4 passthrough  | In chains, L3 and L4 programs pass non-IPv4    |
    | in chains             | traffic to the next program via                |
    |                       | tail_call_next(). L2 filtering is              |
    |                       | allow_ethertype's job; ARP, IPv6, and other    |
    |                       | non-IPv4 traffic allowed by L2 must not be     |
    |                       | silently dropped downstream.                   |
    +-----------------------+------------------------------------------------+

BUILT-IN PROGRAMS

    allow_dns
        allow_dns allows IPv4 DNS traffic (UDP/TCP port 53) to the input
        resolver address, drops the rest. Other traffic passes through.
        Non-IPv4 traffic passes through unchanged in this program; put
        allow_ethertype first in a chain when L2 filtering is required.

    allow_ethertype
        allow_ethertype is an L2 gatekeeper that drops Ethernet frames
        whose EtherType is not in the allowed set. Multiple EtherTypes
        can be specified by joining them with +. Symbolic names (ipv4,
        ipv6, arp, vlan, qinq) and hex values (0x0800) are both
        supported.
        Example: allow_ethertype ipv4+arp

        In a chain, allow_ethertype must be the first program. L3+
        programs (allow_ipv4, allow_port, etc.) pass through traffic
        outside their domain (e.g., non-IPv4 frames), which bypasses
        any downstream allow_ethertype filter.

        Standalone allow_ethertype compares the outer Ethernet header
        EtherType only; it does not unwrap VLAN tags or match the inner
        payload EtherType.

        Symbolic names vlan (0x8100) and qinq (0x88A8) are available.
        VLAN TPIDs are only supported in standalone mode. In chains,
        they are rejected because VLAN-aware parsing is not uniform
        across downstream programs.

    allow_proto
        allow_proto is an L3 gatekeeper that drops IPv4 packets whose IP
        protocol is not in the allowed set. Non-IPv4 traffic passes
        through (L2 filtering is allow_ethertype's job). Multiple
        protocols can be specified by joining them with +. Symbolic
        names (tcp, udp, icmp, sctp) and decimal numbers (6, 17) are
        both supported.
        Example: allow_proto tcp+udp

        In a chain, allow_proto should be placed after allow_ethertype
        and before allow_port (L2 -> L3 -> L4 ordering).
        VLAN/QinQ-tagged IPv4 is unwrapped before checking the IP
        protocol; truncated VLAN headers and unsupported additional
        VLAN nesting fail closed.

    allow_ipv4
        allow_ipv4 allows IPv4 traffic to the input address, drops the
        rest. Non-IPv4 traffic passes through and should be constrained
        by L2 or chain policy when needed. Localhost (127.0.0.0/8)
        traffic is always allowed.

    allow_port
        allow_port allows IPv4 TCP/UDP traffic to the input destination
        port, drops the rest. Other IPv4 protocols (ICMP, GRE, etc.)
        pass through. Non-IPv4 traffic and TCP/UDP subsequent fragments
        are blocked.

    block_private_ipv4
        block_private_ipv4 is a program that can be used to block
        private IPv4 addresses subnets allowing only SSH access on port 22.

    block_ipv4
        block_ipv4 is a program that drops packets with destination equal to the
        input IPv4 address.

    block_port
        block_port is a program that drops packets with the destination port
        equal to the input port number.

    nop
        nop is a simple program that does nothing.

BUILD

    To compile traffico from source you either provide your `vmlinux.h` in the
    `vmlinux/` directory (default option) or you configure the project to
    generate one from your current Linux kernel:

    xmake f --generate-vmlinux=y

    Now you will be able to build traffico from source by running:

    xmake

    In case you only want to compile the BPF programs you can do this:

    xmake -b bpf

    In case you want to compile in debug mode:

    xmake f -m debug

    You will be able to read from the trace_pipe the logs of the BPF programs
    and you will obtain the logs of libbpf into the stderr only if you compile
    in debug mode.

TEST

    To run the test suite you can do this:

    xmake -b test
    xmake run test
