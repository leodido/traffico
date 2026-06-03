#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

output_contains() {
    case "$output" in
        *"$1"*) return 0 ;;
        *) return 1 ;;
    esac
}

@test "--forbid selects Intent mode and is BPF admissible" {
    run traffico -i lo --at egress \
        --permit tcp/10.0.0.10 \
        --forbid tcp/10.0.0.10:22 \
        --dry-run
    [ $status -eq 0 ]
    output_contains "intent dry-run: compiler ok"
    output_contains "intent backend: bpf admissible"
}

@test "--block is an alias for --forbid" {
    run traffico -i lo --at egress \
        --allow tcp/10.0.0.10 \
        --block tcp/10.0.0.10:22 \
        --dry-run
    [ $status -eq 0 ]
    output_contains "intent dry-run: compiler ok"
    output_contains "intent backend: bpf admissible"
}

@test "--dry-run --explain prints permits and forbids" {
    run traffico -i lo --at egress \
        --permit tcp/10.0.0.10 \
        --forbid tcp/10.0.0.10:22 \
        --dry-run --explain
    [ $status -eq 0 ]
    output_contains "permitted traffic:"
    output_contains "  1. TCP to 10.0.0.10 any destination port"
    output_contains "forbidden traffic:"
    output_contains "  1. TCP to 10.0.0.10 destination port 22"
}

@test "--forbid without a permit is rejected before compilation" {
    run traffico -i lo --at egress \
        --forbid tcp/10.0.0.10:22 \
        --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --forbid/--block requires at least one --allow/--permit" ]
    ! output_contains "at least one permit is required"
}

@test "--block without a permit is rejected before compilation" {
    run traffico -i lo --at egress \
        --block tcp/10.0.0.10:22 \
        --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: --forbid/--block requires at least one --allow/--permit" ]
    ! output_contains "at least one permit is required"
}

@test "host-wide TCP and UDP forbids explain the v0.6 boundary" {
    run traffico -i lo --at egress \
        --permit arp \
        --forbid tcp/10.0.0.10 \
        --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: host-wide TCP/UDP forbids are not supported; use tcp/IP:PORT or udp/IP:PORT: 'tcp/10.0.0.10'" ]

    run traffico -i lo --at egress \
        --permit arp \
        --forbid udp/10.0.0.20 \
        --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: host-wide TCP/UDP forbids are not supported; use tcp/IP:PORT or udp/IP:PORT: 'udp/10.0.0.20'" ]
}
