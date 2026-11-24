#!/usr/bin/env bash
# Runs cargo inside the libpq build image against a read-only checkout.
# Registry and target live in Docker volumes, never in the host target dir.
#   worker/e2e/cargo.sh build --features sqlite,postgresql,s3
#   worker/e2e/cargo.sh test --features postgresql,s3
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
docker build -q -t kyvault-e2e-rust:local -f "$repo/worker/e2e/Dockerfile.rust" "$repo/worker/e2e" >/dev/null
exec docker run --rm --name "kyvault-e2e-cargo-$$" \
  --memory 10g --memory-swap 10g \
  -e CARGO_TARGET_DIR=/target -e RUSTUP_TOOLCHAIN=1.99.1 -e CARGO_BUILD_JOBS=10 \
  -v kyvault-e2e-registry:/usr/local/cargo/registry \
  -v kyvault-e2e-target:/target \
  -v "$repo":/src:ro -w /src \
  kyvault-e2e-rust:local cargo "$1" --locked "${@:2}"
