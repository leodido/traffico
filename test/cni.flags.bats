#!/usr/bin/env bats

load helpers
fixtures cni
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "rejects input for program that doesn't need it" {
    run bash -c 'echo '"'"'{"cniVersion":"0.4.0","name":"dummy","type":"traffico-cni","program":"nop","input":"1.2.3.4","prevResult":{"cniVersion":"1.0.0","interfaces":[{"name":"lo"}],"ips":[],"routes":[],"dns":{}}}'"'"' | CNI_COMMAND=ADD traffico-cni'
    [ ! $status -eq 0 ]
    [[ "$output" == *'"msg":	"program does not accept input"'* ]]
}
