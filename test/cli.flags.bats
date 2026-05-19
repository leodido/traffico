#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "help" {
    run traffico --help
    [ $status -eq 0 ]
    [ "${lines[0]}" == 'Usage: traffico [OPTION...] [PROGRAM [INPUT]]' ]
}

@test "usage" {
    run traffico --usage
    [ $status -eq 0 ]
    [ "${lines[0]%% *}" == 'Usage:' ]
}

@test "--allow accepts first Intent values in dry-run mode" {
    run traffico -i lo --at egress \
        --allow arp \
        --allow dns/10.0.0.53 \
        --allow tcp/10.0.0.10:443 \
        --allow udp/10.0.0.20:123 \
        --dry-run
    [ $status -eq 0 ]
    [[ "$output" == *"intent dry-run: compiler ok"* ]]
    [[ "$output" == *"intent backend: bpf admissible"* ]]
}

@test "--permit is an alias for --allow" {
    run traffico -i lo --at egress --permit tcp/10.0.0.10:443 --dry-run
    [ $status -eq 0 ]
    [[ "$output" == *"intent dry-run: compiler ok"* ]]
    [[ "$output" == *"intent backend: bpf admissible"* ]]
}

@test "--allow and --chain are mutually exclusive" {
    run traffico -i lo --allow arp --chain "allow_ethertype:arp" --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --allow/--permit and --chain are mutually exclusive" ]
}

@test "--allow and positional program are mutually exclusive" {
    run traffico -i lo --allow arp nop --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --allow/--permit and positional PROGRAM arguments are mutually exclusive" ]
}

@test "--dry-run requires Intent mode" {
    run traffico -i lo --dry-run nop
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --dry-run currently requires --allow or --permit" ]
}

@test "--explain requires Intent mode" {
    run traffico -i lo --explain nop
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --explain currently requires --allow or --permit" ]
}

@test "--explain=dag is reserved for future Intent debug output" {
    run traffico -i lo --allow arp --dry-run --explain=dag
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: unsupported --explain mode: 'dag'" ]
}

@test "--explain=intent is the explicit Intent explain mode" {
    run traffico -i lo --allow arp --dry-run --explain=intent
    [ $status -eq 0 ]
    [[ "$output" == *"traffico intent"* ]]
    [[ "$output" == *"permitted traffic:"* ]]
}

@test "Intent mode rejects ingress until designed" {
    run traffico -i lo --at ingress --allow arp --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: intent dry-run: Intent BPF backend supports egress only" ]
}

@test "--allow rejects malformed values" {
    run traffico -i lo --allow tcp/10.0.0.10 --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid permit: 'tcp/10.0.0.10'" ]
}

@test "--allow rejects unsupported Intent value" {
    run traffico -i lo --allow icmp/10.0.0.10 --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: unsupported permit: 'icmp/10.0.0.10'" ]
}

@test "--allow rejects duplicate permits" {
    run traffico -i lo --allow arp --allow arp --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate permit: 'arp'" ]
}

@test "--allow rejects too many permits" {
    args=(-i lo --dry-run)
    for port in {10000..10032}; do
        args+=(--allow "tcp/10.0.0.10:${port}")
    done

    run traffico "${args[@]}"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: too many permits: 'tcp/10.0.0.10:10032'" ]
}

@test "invalid option" {
    run traffico -x
    [ ! $status -eq 0 ]
    [ $status -eq 1 ]
    [ "${lines[0]##*: }" == "invalid option -- 'x'" ]
}

@test "unrecognized option" {
    run traffico --xxxx
    [ ! $status -eq 0 ]
    [ $status -eq 1 ]
    [ "${lines[0]##*: }" == "unrecognized option '--xxxx'" ]
}

@test "missing program" {
    run traffico
    [ ! $status -eq 0 ]
    [ $status -eq 1 ]
    [ "${lines[0]}" == 'traffico: program name is mandatory' ]
}

@test "unavailable program" {
    run traffico xxx
    [ ! $status -eq 0 ]
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: argument 'xxx' is not a traffico program" ]
}

@test "unavailable network interface" {
    run traffico -i ciao
    [ ! $status -eq 0 ]
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: option '--ifname' requires an existing interface: got 'ciao'" ]
}

@test "unavailable network interface (long)" {
    run traffico --ifname ciao
    [ ! $status -eq 0 ]
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: option '--ifname' requires an existing interface: got 'ciao'" ]
}

@test "unsupported attach point" {
    run traffico --at wrong
    [ ! $status -eq 0 ]
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: option '--at' requires one of the following values: INGRESS|EGRESS" ]
}

@test "missing input for allow_dns" {
    run traffico -i lo allow_dns
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'allow_dns' requires an input argument" ]
}

@test "invalid IP for allow_dns" {
    run traffico -i lo allow_dns not.an.ip
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid IP address: 'not.an.ip'" ]
}

@test "missing input for allow_ipv4" {
    run traffico -i lo allow_ipv4
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'allow_ipv4' requires an input argument" ]
}

@test "invalid IP for allow_ipv4" {
    run traffico -i lo allow_ipv4 not.an.ip
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid IP address: 'not.an.ip'" ]
}

@test "missing input for block_ipv4" {
    run traffico -i lo block_ipv4
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'block_ipv4' requires an input argument" ]
}

@test "invalid IP for block_ipv4" {
    run traffico -i lo block_ipv4 not.an.ip
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid IP address: 'not.an.ip'" ]
}

@test "missing input for allow_port" {
    run traffico -i lo allow_port
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'allow_port' requires an input argument" ]
}

@test "invalid port for allow_port" {
    run traffico -i lo allow_port abc
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid port number: 'abc'" ]
}

@test "missing input for block_port" {
    run traffico -i lo block_port
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'block_port' requires an input argument" ]
}

@test "invalid port for block_port" {
    run traffico -i lo block_port abc
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid port number: 'abc'" ]
}

@test "port out of range" {
    run traffico -i lo block_port 99999
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid port number: '99999'" ]
}

@test "input for program that doesn't need it" {
    run traffico -i lo nop 1.2.3.4
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program does not accept input: '1.2.3.4'" ]
}

@test "too many arguments" {
    run traffico -i lo block_ipv4 1.2.3.4 extra
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: too many arguments" ]
}

@test "--chain with unknown program" {
    run traffico -i lo --chain "xxx:1.2.3.4"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: unknown program in chain: 'xxx'" ]
}

@test "--chain with missing input for program that requires it" {
    run traffico -i lo --chain "allow_ipv4"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'allow_ipv4' in chain requires an input value (use name:value)" ]
}

@test "--chain with invalid input" {
    run traffico -i lo --chain "allow_ipv4:not.an.ip"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid IP address: 'not.an.ip'" ]
}

@test "--chain with too many entries" {
    run traffico -i lo --chain "allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4,allow_ipv4:1.2.3.4"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: chain exceeds maximum of 8 programs" ]
}

@test "--chain with unsupported program" {
    run traffico -i lo --chain "nop"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'nop' does not support chaining" ]
}

@test "--chain rejects block programs as non-chainable" {
    run traffico -i lo --chain "block_ipv4:127.0.0.1"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'block_ipv4' does not support chaining" ]

    run traffico -i lo --chain "block_port:80"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'block_port' does not support chaining" ]

    run traffico -i lo --chain "block_private_ipv4"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'block_private_ipv4' does not support chaining" ]
}

@test "--chain rejects allow_ethertype after L3/L4" {
    run timeout 2 traffico -i lo --chain "allow_ipv4:127.0.0.1,allow_ethertype:ipv4+arp"
    [ $status -eq 1 ]
    [[ "$output" == *"L3/L4 chains must start with allow_ethertype"* ]]
}

@test "--chain rejects L3/L4 chain without allow_ethertype gate" {
    run timeout 2 traffico -i lo --chain "allow_port:443"
    [ $status -eq 1 ]
    [[ "$output" == *"L3/L4 chains must start with allow_ethertype"* ]]

    run timeout 2 traffico -i lo --chain "allow_ipv4:127.0.0.1,allow_port:443"
    [ $status -eq 1 ]
    [[ "$output" == *"L3/L4 chains must start with allow_ethertype"* ]]
}

@test "--chain rejects layer regression" {
    run timeout 2 traffico -i lo --chain "allow_ethertype:ipv4+arp,allow_port:443,allow_ipv4:127.0.0.1"
    [ $status -eq 1 ]
    [[ "$output" == *"chain order must be L2 -> L3 -> L4"* ]]
}

@test "--chain rejects VLAN TPIDs in multi-program chain" {
    run timeout 2 traffico -i lo --chain "allow_ethertype:ipv4+0x8100,allow_ipv4:127.0.0.1"
    [ $status -ne 0 ]
    [[ "$output" == *"VLAN EtherTypes"* ]]
}

@test "--chain mutually exclusive with positional args" {
    run traffico -i lo --chain "nop" nop
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --chain and positional PROGRAM arguments are mutually exclusive" ]
}

@test "--chain with empty string" {
    run traffico -i lo --chain ""
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --chain requires at least one program" ]
}

@test "missing input for allow_ethertype" {
    run traffico -i lo allow_ethertype
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'allow_ethertype' requires an input argument" ]
}

@test "unknown ethertype name" {
    run traffico -i lo allow_ethertype xxx
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: unknown EtherType name: 'xxx'" ]
}

@test "invalid ethertype hex value" {
    run traffico -i lo allow_ethertype 0xZZZZ
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid EtherType hex value: '0xZZZZ'" ]
}

@test "duplicate ethertype values" {
    run traffico -i lo allow_ethertype ipv4+ipv4
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate EtherType value: 'ipv4+ipv4'" ]
}

@test "duplicate ethertype values across representations" {
    run traffico -i lo allow_ethertype ipv4+0x0800
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate EtherType value: 'ipv4+0x0800'" ]
}

@test "trailing + in ethertype input" {
    run traffico -i lo allow_ethertype "ipv4+"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: input must not end with '+': 'ipv4+'" ]
}

@test "leading + in ethertype input" {
    run traffico -i lo allow_ethertype "+ipv4"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: input must not start with '+': '+ipv4'" ]
}

@test "consecutive ++ in ethertype input" {
    run traffico -i lo allow_ethertype "ipv4++arp"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: input contains empty value between '+' delimiters: 'ipv4++arp'" ]
}

@test "too many ethertype values" {
    run traffico -i lo allow_ethertype "ipv4+ipv6+arp+0x8100+0x88A8+0x8847+0x8848+0x88CC+0x0842"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: too many EtherType values: 'ipv4+ipv6+arp+0x8100+0x88A8+0x8847+0x8848+0x88CC+0x0842'" ]
}

@test "zero ethertype hex value" {
    run traffico -i lo allow_ethertype 0x0000
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: invalid EtherType hex value: '0x0000'" ]
}

@test "vlan symbolic name resolves to 0x8100" {
    run traffico -i lo allow_ethertype "vlan+0x8100"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate EtherType value: 'vlan+0x8100'" ]
}

@test "qinq symbolic name resolves to 0x88A8" {
    run traffico -i lo allow_ethertype "qinq+0x88A8"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate EtherType value: 'qinq+0x88A8'" ]
}

@test "missing input for allow_proto" {
    run traffico -i lo allow_proto
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: program 'allow_proto' requires an input argument" ]
}

@test "unknown protocol name" {
    run traffico -i lo allow_proto xxx
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: unknown protocol name (use a number 0-255): 'xxx'" ]
}

@test "invalid protocol decimal" {
    run traffico -i lo allow_proto abc
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: unknown protocol name (use a number 0-255): 'abc'" ]
}

@test "protocol number out of range" {
    run traffico -i lo allow_proto 256
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: protocol number out of range (0-255): '256'" ]
}

@test "duplicate protocol values" {
    run traffico -i lo allow_proto tcp+tcp
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate protocol value: 'tcp+tcp'" ]
}

@test "duplicate protocol values across representations" {
    run traffico -i lo allow_proto tcp+6
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate protocol value: 'tcp+6'" ]
}

@test "trailing + in proto input" {
    run traffico -i lo allow_proto "tcp+"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: input must not end with '+': 'tcp+'" ]
}

@test "leading + in proto input" {
    run traffico -i lo allow_proto "+tcp"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: input must not start with '+': '+tcp'" ]
}

@test "consecutive ++ in proto input" {
    run traffico -i lo allow_proto "tcp++udp"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: input contains empty value between '+' delimiters: 'tcp++udp'" ]
}

@test "too many protocol values" {
    run traffico -i lo allow_proto "1+2+3+4+5+6+7+8+9"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: too many protocol values: '1+2+3+4+5+6+7+8+9'" ]
}

@test "sctp symbolic name resolves to 132" {
    run traffico -i lo allow_proto "sctp+132"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: duplicate protocol value: 'sctp+132'" ]
}

@test "protocol 0 is accepted" {
    # Verify the parser does not reject protocol 0.
    # With a valid interface, traffico proceeds past parsing to BPF load:
    #   - unprivileged: BPF load fails immediately (exit 1)
    #   - privileged: attaches and runs until signalled (exit 124)
    # Either way, output must not contain a parser rejection message.
    # Use SIGINT so traffico cleans up BPF programs on lo before exiting.
    run timeout --signal=INT 1 traffico -i lo allow_proto 0
    [[ "$output" != *"invalid"* ]]
    [[ "$output" != *"out of range"* ]]
    [[ "$output" != *"unknown"* ]]
}

@test "--chain rejects leading separator" {
    run timeout 2 traffico -i lo --chain ",allow_ipv4:127.0.0.1"
    [ $status -eq 1 ]
    [[ "${output}" == *"empty chain entry"* ]]
}

@test "--chain rejects trailing separator" {
    run timeout 2 traffico -i lo --chain "allow_ipv4:127.0.0.1,"
    [ $status -eq 1 ]
    [[ "${output}" == *"empty chain entry"* ]]
}

@test "--chain rejects consecutive separators" {
    run timeout 2 traffico -i lo --chain "allow_ipv4:127.0.0.1,,allow_port:80"
    [ $status -eq 1 ]
    [[ "${output}" == *"empty chain entry"* ]]
}
