#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "help" {
    run traffico --help
    [ $status -eq 0 ]
    [ "${lines[0]}" == 'Usage: traffico [OPTION...] PROGRAM [INPUT]' ]
}

@test "usage" {
    run traffico --usage
    [ $status -eq 0 ]
    [ "${lines[0]%% *}" == 'Usage:' ]
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
    run traffico -i lo --chain "nop,nop,nop,nop,nop,nop,nop,nop,nop"
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: chain exceeds maximum of 8 programs" ]
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
    run traffico -i lo allow_proto 0
    # Exit 1 from BPF load (no root), not from parsing.
    # If parsing rejected 0, the error message would mention "invalid" or "out of range".
    [[ "${lines[0]}" != *"invalid"* ]]
    [[ "${lines[0]}" != *"out of range"* ]]
    [[ "${lines[0]}" != *"unknown"* ]]
}
