#!/usr/bin/env bash
# Fails if a public image could be built with the private `hosted` or test-only `kye2e` feature.
# Public images get their Cargo features only from Cargo.toml defaults, the Dockerfiles,
# docker-bake.hcl and the workflows that publish them.
set -euo pipefail
cd "${1:-.}"

python3 - <<'PY'
import sys, tomllib
feats = tomllib.load(open("Cargo.toml", "rb")).get("features", {})
bad = [f"{k} -> {v}" for k, vs in feats.items() for v in vs if v in ("hosted", "kye2e")]
if bad:
    sys.exit("ERROR: no Cargo feature (default included) may enable hosted or kye2e: " + ", ".join(bad))
PY

mapfile -t files < <(
  find -L Dockerfile docker -type f ! -name '*.md'
  grep -lE 'docker/(login|bake|build-push)-action|docker push|push-to-registry' .github/workflows/*.y*ml || true
)
if grep -nHE '(^|[^-[:alnum:]_])(hosted|kye2e)($|[^-[:alnum:]_])' "${files[@]}"; then
  echo "ERROR: hosted and kye2e must never be built into a public image" >&2
  exit 1
fi
echo "public image features OK (${#files[@]} files checked)"
