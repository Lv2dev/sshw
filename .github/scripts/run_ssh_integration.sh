#!/usr/bin/env bash
set -euo pipefail

image_tag="sshw-password-sshd:integration-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
fixture_dir="tests/fixtures/password-sshd"
build_timeout_seconds="${SSHW_DOCKER_BUILD_TIMEOUT_SECONDS:-150}"
build_attempts="${SSHW_DOCKER_BUILD_ATTEMPTS:-2}"

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "$name must be a positive integer, got: $value" >&2
    exit 2
  fi
}

cleanup() {
  docker image rm --force "$image_tag" >/dev/null 2>&1 || true
}

require_positive_integer "SSHW_DOCKER_BUILD_TIMEOUT_SECONDS" "$build_timeout_seconds"
require_positive_integer "SSHW_DOCKER_BUILD_ATTEMPTS" "$build_attempts"
trap cleanup EXIT

build_fixture() {
  local attempt
  local status=1

  for ((attempt = 1; attempt <= build_attempts; attempt++)); do
    echo "::group::Build password SSH fixture (attempt $attempt/$build_attempts)"
    if timeout --signal=TERM --kill-after=10s "${build_timeout_seconds}s" \
      docker build --progress=plain --tag "$image_tag" "$fixture_dir"; then
      echo "::endgroup::"
      return 0
    else
      status=$?
    fi
    echo "::endgroup::"
    echo "password SSH fixture build attempt $attempt/$build_attempts failed with status $status" >&2

    if ((attempt < build_attempts)); then
      sleep 5
    fi
  done

  echo "password SSH fixture build failed after $build_attempts attempts" >&2
  return "$status"
}

build_fixture
SSHW_DOCKER_PASSWORD_IMAGE="$image_tag" \
  cargo test --test integration_ssh --locked -- --ignored --test-threads=1
