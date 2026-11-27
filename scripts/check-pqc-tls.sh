#!/usr/bin/env bash
# Keep Go's hybrid TLS defaults; worker code must not disable ML-KEM.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
if matches=$(grep -RnE --include='*.go' 'CurvePreferences|tlsmlkem' "$repo/worker"); then
  printf '%s\n' "$matches" >&2
  echo 'ERROR: worker Go code must not override Go hybrid TLS defaults.' >&2
  exit 1
else
  status=$?
  if [[ $status -ne 1 ]]; then
    exit "$status"
  fi
fi
echo 'PQ TLS override check passed.'
