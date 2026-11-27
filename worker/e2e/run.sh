#!/usr/bin/env bash
# Live end-to-end suite: builds the vault (sqlite+postgresql+s3) in Docker, then runs the
# Go test that starts PostgreSQL 18, RustFS, two multi-tenant replicas, one single-tenant
# SQLite replica, the worker and a TLS KyIdentity fake. Needs Docker and Go.
# Containers carry the label kyvault-e2e=1 and are always removed. The cargo cache volumes
# (kyvault-e2e-registry, kyvault-e2e-target) are kept for speed; --clean removes them.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

cleanup() {
  ids=$(docker ps -aq --filter label=kyvault-e2e=1)
  if [ -n "$ids" ]; then docker rm -fv $ids >/dev/null; fi
  if [ "${1:-}" = "--clean" ]; then
    docker volume rm -f kyvault-e2e-registry kyvault-e2e-target >/dev/null
    docker image rm -f kyvault-e2e-rust:local >/dev/null 2>&1 || true
  fi
}
trap 'cleanup "${1:-}"' EXIT

"$here/cargo.sh" build --features sqlite,postgresql,s3
docker pull -q postgres:18-alpine >/dev/null
docker pull -q rustfs/rustfs:1.0.3 >/dev/null
cd "$here/.."
KYVAULT_E2E_PG=1 GOWORK=off go test -count=1 -v -timeout 15m ./e2e/
