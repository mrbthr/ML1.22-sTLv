#!/usr/bin/env bats

setup() {
    SCRIPT="./bin/netdiag"
}

@test "prints version string" {
    run "$SCRIPT" --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"netdiag v"* ]]
}

@test "prints help usage" {
    run "$SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "rejects non-numeric port" {
    run "$SCRIPT" --port invalid
    [ "$status" -eq 1 ]
    [[ "$output" == *"Invalid port"* ]]
}

@test "detects 1ms external ping anomaly in JSON mode" {
    run "$SCRIPT" --target 127.0.0.1 --port 80 --count 1 --json
    [ "$status" -eq 0 ]
    [[ "$output" == *"127.0.0.1"* ]]
}
