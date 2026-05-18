#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

setup() {
    load net
    NETNS="ns$((RANDOM % 10))"
    new_netns "${NETNS}"
    setup_net "${NETNS}"
}

teardown() {
    killall traffico &>/dev/null || true
    del_netdev
    del_netns "${NETNS}"
}

intent_tc_state_exists() {
    local qdisc
    local filter

    qdisc="$(ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact)"
    filter="$(ip netns exec "${NETNS}" tc filter show dev "${PEER}" egress)"

    [[ "${qdisc}" == *"clsact"* && "${filter}" != "" ]]
}

wait_for_intent_tc_state() {
    local i

    for i in {1..50}; do
        if intent_tc_state_exists; then
            return 0
        fi
        sleep 0.1
    done

    return 1
}

start_intent_attach() {
    TRAFFICO_OUTPUT="$1"
    shift

    ip netns exec "${NETNS}" traffico "$@" >"${TRAFFICO_OUTPUT}" 2>&1 &
    TRAFFICO_PID=$!
}

stop_intent_attach() {
    kill -INT "${TRAFFICO_PID}"
    wait "${TRAFFICO_PID}"
}

assert_intent_tc_cleanup() {
    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$output" = "" ]

    run ip netns exec "${NETNS}" tc filter show dev "${PEER}" egress
    [ "$output" = "" ]
}

@test "Intent live attach creates and cleans TC state" {
    start_intent_attach "${BATS_TEST_TMPDIR}/intent-live.out" \
        -i "${PEER}" --at egress --allow arp

    wait_for_intent_tc_state
    stop_intent_attach

    assert_intent_tc_cleanup
}

@test "--dry-run validates Intent without attaching" {
    run ip netns exec "${NETNS}" traffico -i "${PEER}" --at egress \
        --allow arp \
        --allow "tcp/${VETH_ADDR}:443" \
        --dry-run
    [ $status -eq 0 ]
    [[ "$output" == *"intent dry-run: compiler ok"* ]]
    [[ "$output" == *"intent backend: bpf admissible"* ]]

    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$output" = "" ]
}

@test "--dry-run does not require an attach interface" {
    run ip netns exec "${NETNS}" ip route del default
    [ $status -eq 0 ]

    run ip netns exec "${NETNS}" traffico --at egress \
        --allow arp \
        --dry-run --explain
    [ $status -eq 0 ]
    [ "${lines[1]}" == "interface: not attached" ]
    [[ "$output" == *"intent dry-run: compiler ok"* ]]

    run ip netns exec "${NETNS}" tc qdisc show dev "${PEER}" clsact
    [ "$output" = "" ]
}

@test "--dry-run --explain prints deterministic intent" {
    run traffico -i lo --at egress \
        --allow udp/10.0.0.20:123 \
        --allow arp \
        --allow tcp/10.0.0.10:443 \
        --allow dns/10.0.0.53 \
        --dry-run --explain
    [ $status -eq 0 ]
    [ "${lines[0]}" == "traffico intent" ]
    [ "${lines[1]}" == "interface: lo" ]
    [ "${lines[2]}" == "direction: egress" ]
    [ "${lines[3]}" == "default: drop" ]
    [[ "$output" == *"  1. ARP"* ]]
    [[ "$output" == *"  2. TCP to 10.0.0.10 destination port 443"* ]]
    [[ "$output" == *"  3. UDP to 10.0.0.20 destination port 123"* ]]
    [[ "$output" == *"  4. DNS to 10.0.0.53 over TCP or UDP destination port 53"* ]]
    [[ "$output" == *"TCP/UDP fragments whose destination port cannot be checked"* ]]
}

@test "--explain prints deterministic intent before live attach" {
    local output_file="${BATS_TEST_TMPDIR}/intent-explain-live.out"
    local intent_output
    local intent_lines

    start_intent_attach "${output_file}" \
        -i "${PEER}" --at egress --allow arp --explain

    wait_for_intent_tc_state
    stop_intent_attach

    intent_output="$(<"${output_file}")"
    mapfile -t intent_lines <"${output_file}"

    [ "${intent_lines[0]}" == "traffico intent" ]
    [[ "${intent_output}" == *"permitted traffic:"* ]]
    [[ "${intent_output}" == *"  1. ARP"* ]]
    [[ "${intent_output}" != *"TCP/UDP fragments whose destination port cannot be checked"* ]]

    assert_intent_tc_cleanup
}
