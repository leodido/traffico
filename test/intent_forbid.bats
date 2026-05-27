#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "--forbid selects Intent mode and is parsed before backend support" {
    run traffico -i lo --at egress \
        --allow tcp/10.0.0.10 \
        --forbid tcp/10.0.0.10:22 \
        --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: intent dry-run: forbids are not supported yet" ]
}

@test "--block is an alias for --forbid" {
    run traffico -i lo --at egress \
        --allow tcp/10.0.0.10 \
        --block tcp/10.0.0.10:22 \
        --dry-run
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: intent dry-run: forbids are not supported yet" ]
}

@test "--dry-run --explain prints permits and forbids" {
    run traffico -i lo --at egress \
        --allow tcp/10.0.0.10 \
        --forbid tcp/10.0.0.10:22 \
        --dry-run --explain
    [ $status -eq 1 ]
    [[ "$output" == *"permitted traffic:"* ]]
    [[ "$output" == *"  1. TCP to 10.0.0.10 any destination port"* ]]
    [[ "$output" == *"forbidden traffic:"* ]]
    [[ "$output" == *"  1. TCP to 10.0.0.10 destination port 22"* ]]
}
