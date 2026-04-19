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
traffico --ifname=eth0 block_ip 10.0.0.1
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
    "program": "block_ip",
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

## Built-in programs

| Program | Description |
|---|---|
| `block_private_ipv4` | Blocks private IPv4 addresses subnets allowing only SSH access on port 22 |
| `block_ip` | Drops packets with destination equal to the input IPv4 address |
| `block_port` | Drops packets with the destination port equal to the input port number |
| `nop` | A simple program that does nothing |

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
