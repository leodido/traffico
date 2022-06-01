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

BUILT-IN PROGRAMS

    block_private_ipv4
        block_private_ipv4 is a program that can be used to block
        private IPv4 addresses subnets allowing only SSH access on port 22.

    block_ip
        block_ip is a program that drops packets with destination equal to the
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

TEST

    To run the test suite you can do this:

    xmake -b test
    xmake run test
