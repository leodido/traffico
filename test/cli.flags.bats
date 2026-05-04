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