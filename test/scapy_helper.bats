#!/usr/bin/env bats

load helpers
export BATS_TEST_NAME_PREFIX=$(setsuite)
bats_require_minimum_version 1.7.0

@test "Scapy sniffer reports readiness before timeout" {
    ready_file="$BATS_TEST_TMPDIR/sniffer.ready"

    run python3 "$SCAPY_HELPER" sniff \
        --iface lo \
        --ip-id 65000 \
        --timeout 0.1 \
        --ready-file "$ready_file"

    [ "$status" -eq 1 ]
    [ -f "$ready_file" ]
}
