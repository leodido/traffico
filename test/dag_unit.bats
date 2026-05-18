#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "DAG header unit tests" {
    run dag-unit
    [ $status -eq 0 ]
    [ "${lines[0]}" == "dag unit tests: ok" ]
}
