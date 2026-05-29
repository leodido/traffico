#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "lima traffico runner unit tests" {
    run python3 test/lima_traffico_runner_test.py
    [ $status -eq 0 ]
    [[ "$output" == *"OK"* ]]
}
