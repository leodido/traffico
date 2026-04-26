#!/usr/bin/env bats

load helpers
fixtures cni
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

# Run traffico-cni ADD with a minimal CNI config for the given program.
# Optional second argument adds an "input" field.
cni_add() {
    local program="$1"
    local input_field=""
    if [ -n "${2:-}" ]; then
        input_field="\"input\":\"$2\","
    fi
    run bash -c "echo '{\"cniVersion\":\"0.4.0\",\"name\":\"dummy\",\"type\":\"traffico-cni\",\"program\":\"${program}\",${input_field}\"prevResult\":{\"cniVersion\":\"1.0.0\",\"interfaces\":[{\"name\":\"lo\"}],\"ips\":[],\"routes\":[],\"dns\":{}}}' | CNI_COMMAND=ADD traffico-cni"
}

@test "rejects input for program that doesn't need it" {
    cni_add "nop" "1.2.3.4"
    [ ! $status -eq 0 ]
    [[ "$output" == *'"msg":	"program does not accept input"'* ]]
}

@test "rejects missing input for allow_dns" {
    cni_add "allow_dns"
    [ ! $status -eq 0 ]
    [[ "$output" == *"program requires an"*"input"*"field"* ]]
}

@test "rejects missing input for allow_ip" {
    cni_add "allow_ip"
    [ ! $status -eq 0 ]
    [[ "$output" == *"program requires an"*"input"*"field"* ]]
}

@test "rejects missing input for allow_port" {
    cni_add "allow_port"
    [ ! $status -eq 0 ]
    [[ "$output" == *"program requires an"*"input"*"field"* ]]
}

@test "rejects missing input for block_ip" {
    cni_add "block_ip"
    [ ! $status -eq 0 ]
    [[ "$output" == *"program requires an"*"input"*"field"* ]]
}

@test "rejects missing input for block_port" {
    cni_add "block_port"
    [ ! $status -eq 0 ]
    [[ "$output" == *"program requires an"*"input"*"field"* ]]
}
