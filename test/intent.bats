#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "Intent live attach is rejected until backend is implemented" {
    run traffico -i lo --at egress --allow arp
    [ $status -eq 1 ]
    [ "${lines[0]}" == "traffico: intent attach backend is not implemented; use --dry-run" ]
}
