#!/usr/bin/env bash

fixtures() {
  FIXTURE_ROOT="$BATS_TEST_DIRNAME/fixtures/$1"
  # shellcheck disable=SC2034
  RELATIVE_FIXTURE_ROOT="${FIXTURE_ROOT#"$BATS_CWD"/}"
}

setsuite() {
  local PREFIX
  PREFIX="$(basename "$BATS_TEST_FILENAME" .bats)"
  echo "${PREFIX%%.*}: "
}