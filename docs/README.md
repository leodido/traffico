# traffico

traffico is a collection of tools to shape traffic on a network using traffic control `tc(8)`.
It can be used via a CLI tool (`traffico`) or as a CNI plugin (`traffico-cni`).
For a list of the available programs and what they do see the [Built-in programs](#built-in-programs) section.

The built-in programs are very opinionated and made for the needs of the authors but the framework
is flexible enough to be used for other purposes. You can add programs to the `bpf/` directory
to extend it to other use cases.

## Contact

If you have problems, questions, ideas or suggestions, please contact us by
posting to https://github.com/leodido/traffico/issues.

## Download

To download the very latest source do this:

```bash
git clone https://github.com/leodido/traffico.git
```

## Authors

- Leonardo Di Donato
- Lorenzo Fontana

## Usage

Traffico can be either used standalone or as a CNI plugin.

### traffico

`traffico` is a CLI tool that can be used to load and unload the programs.
You can choose an interface and choose whether the program will be loaded in
`INGRESS` or `EGRESS`.

Example usage:

```bash
traffico --ifname=eth0 --at=INGRESS block_private_ipv4
```

Programs that accept runtime input (marked `[input]` in `--help`) take it as a second positional argument:

```bash
traffico --ifname=eth0 block_ipv4 10.0.0.1
traffico --ifname=eth0 block_port 443
```

### traffico-cni

`traffico-cni` is a meta CNI plugin that allows the traffico programs to be used in CNI.

Meta means that `traffico-cni` does not create any interface for you,
it is intended to be used as a chained CNI plugin.

The plugin block to use `traffico-cni` is very similar to how `traffico` is
used as a CLI tool.

```json
{
    "type": "traffico-cni",
    "program": "block_private_ipv4",
    "attachPoint": "ingress"
}
```

Programs that accept runtime input use the `"input"` field:

```json
{
    "type": "traffico-cni",
    "program": "block_ipv4",
    "input": "10.0.0.1",
    "attachPoint": "egress"
}
```

Here's an example CNI config file featuring `traffico-cni`.

```json
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
```

## Design principles

| Principle | Description |
|---|---|
| Standalone vs chained | Standalone programs are the only filter on the interface and handle all traffic types themselves. Chained programs pass traffic they do not handle to the next program, trusting that an upstream filter (typically `allow_ethertype`) already constrained it. |
| Boundary failures | `block_*` programs fail open (`TC_ACT_OK`) on truncated headers, unsupported protocols, and subsequent fragments because they target specific traffic. `allow_*` programs fail closed (`TC_ACT_SHOT`) on the same failures because they define permitted traffic. |
| L2 → L3 → L4 ordering | Chains run cheapest and broadest checks first: `allow_ethertype` (L2), then `allow_proto` (L3), then `allow_port` or `allow_dns` (L4). `allow_ipv4` fits after L2 and alongside or after L3 protocol filtering. |
| Non-IPv4 passthrough in chains | In chains, L3 and L4 programs pass non-IPv4 traffic to the next program via `tail_call_next()`. L2 filtering is `allow_ethertype`'s job; ARP, IPv6, and other non-IPv4 traffic allowed by L2 must not be silently dropped downstream. |

## Built-in programs

| Program | Description |
|---|---|
| `allow_dns` | Allows IPv4 DNS traffic (TCP/UDP port 53) to the input resolver. Other IPv4 traffic passes through. Standalone mode blocks non-IPv4; chain mode passes non-IPv4 to the next stage. |
| `allow_ethertype` | L2 gatekeeper: drops frames whose outer EtherType is not in the allowed set (e.g., `ipv4+arp`). Required first when a chain contains L3/L4 programs. |
| `allow_ipv4` | Allows IPv4 traffic to the input address, drops other IPv4 destinations except localhost (127.0.0.0/8). Standalone mode blocks non-IPv4; chain mode passes non-IPv4 to the next stage. |
| `allow_port` | Allows IPv4 TCP/UDP traffic to the input port. Other IPv4 protocols pass through. Standalone mode blocks non-IPv4; chain mode passes non-IPv4 to the next stage. TCP/UDP subsequent fragments are blocked. |
| `allow_proto` | L3 gatekeeper: drops IPv4 packets whose IP protocol is not in the allowed set (e.g., `tcp+udp`). It unwraps supported VLAN/QinQ tags before the IPv4 protocol check. Standalone mode blocks non-IPv4 after VLAN unwrap; chain mode passes it to the next stage. |
| `block_private_ipv4` | Blocks private IPv4 addresses subnets allowing only SSH access on port 22 |
| `block_ipv4` | Drops packets with destination equal to the input IPv4 address |
| `block_port` | Drops packets with the destination port equal to the input port number |
| `nop` | A simple program that does nothing |

### Notes on `allow_ethertype`

**Chain ordering:** If a chain contains any L3/L4 program, slot 0 must be `allow_ethertype`. Chain order must be non-decreasing by layer: `L2 -> L3 -> L4`. Same-layer programs are allowed, and chains may skip L3 after the L2 gate, such as `--chain "allow_ethertype:ipv4+arp,allow_port:443"`.

**VLAN-tagged networks:** Standalone `allow_ethertype` compares the EtherType in the outer Ethernet header only; it does not unwrap VLAN tags or match the inner payload EtherType. Symbolic names `vlan` (0x8100) and `qinq` (0x88A8) are available for standalone filters. In multi-program chains, VLAN TPIDs are rejected because VLAN-aware parsing is not uniform across downstream programs. Example (standalone): `allow_ethertype ipv4+arp+vlan`.

### Notes on `allow_proto`

**Chain ordering:** In a chain, `allow_proto` should be placed after `allow_ethertype` and before `allow_port`/`allow_dns`. This gives `L2 -> L3 -> L4` ordering with cheapest checks first. Example: `--chain "allow_ethertype:ipv4+arp,allow_proto:tcp+udp,allow_port:8080"`.

**VLAN-tagged IPv4:** `allow_proto` unwraps supported 802.1Q and QinQ tags before reading the IPv4 protocol. Truncated VLAN headers and unsupported additional VLAN nesting fail closed.

**Non-IPv4 behavior:** In standalone mode, non-IPv4 traffic is blocked after VLAN unwrap because the program is the complete policy. In chain mode, non-IPv4 traffic is passed to the next stage because L2 policy belongs to `allow_ethertype`.

## Build

To compile traffico from source you either provide your `vmlinux.h` in the
`vmlinux/` directory (default option) or you configure the project to
generate one from your current Linux kernel:

```bash
xmake f --generate-vmlinux=y
```

Now you will be able to build traffico from source by running:

```bash
xmake
```

In case you only want to compile the BPF programs you can do this:

```bash
xmake -b bpf
```

## Test

To run the test suite you can do this:

```bash
xmake -b test
xmake run test
```

The full test suite includes Scapy-backed advanced packet tests that exercise IP options, fragmentation, and protocol-specific behavior. These require the `python-scapy` (Arch) or `python3-scapy` (Ubuntu) package. If Scapy is not installed, the advanced tests are skipped automatically.
