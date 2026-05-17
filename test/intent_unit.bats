#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "intent header unit tests" {
    run intent-ir-unit
    [ $status -eq 0 ]
    [ "${lines[0]}" == "intent unit tests: ok" ]
}
