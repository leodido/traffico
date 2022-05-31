#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "help" {
    run traffico --help
    [ $status -eq 0 ]
    [ "${lines[0]}" == 'Usage: traffico [OPTION...] PROGRAM' ]
}

@test "usage" {
    run traffico --usage
    [ $status -eq 0 ]
    [ "${lines[0]%% *}" == 'Usage:' ]
}

@test "invalid option" {
    run traffico -x
    [ ! $status -eq 0 ]
    [ $status -eq 64 ]
    [ "${lines[0]##*: }" == "invalid option -- 'x'" ]
}

@test "unrecognized option" {
    run traffico --xxxx
    [ ! $status -eq 0 ]
    [ $status -eq 64 ]
    [ "${lines[0]##*: }" == "unrecognized option '--xxxx'" ]
}

@test "missing program" {
    run traffico
    [ ! $status -eq 0 ]
    [ $status -eq 64 ]
    [ "${lines[0]}" == 'traffico: program name is mandatory' ]
}

@test "unavailable program" {
    run traffico xxx
    [ ! $status -eq 0 ]
    [ $status -eq 64 ]
    [ "${lines[0]}" == "traffico: argument 'xxx' is not a traffico program" ]
}

@test "unavailable network interface" {
    run traffico -i ciao
    [ ! $status -eq 0 ]
    [ $status -eq 64 ]
    [ "${lines[0]}" == "traffico: option '--ifname' requires an existing interface: got 'ciao'" ]
}

@test "unavailable network interface (long)" {
    run traffico --ifname ciao
    [ ! $status -eq 0 ]
    [ $status -eq 64 ]
    [ "${lines[0]}" == "traffico: option '--ifname' requires an existing interface: got 'ciao'" ]
}

@test "unsupported attach point" {
    run traffico --at wrong
    [ ! $status -eq 0 ]
    [ $status -eq 64 ]
    [ "${lines[0]}" == "traffico: option '--at' requires one of the following values: INGRESS|EGRESS" ]
}