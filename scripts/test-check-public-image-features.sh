#!/usr/bin/env bash
# Proves check-public-image-features.sh passes on the repo and fails on each way a flag can slip in.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
check="$repo/scripts/check-public-image-features.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fresh() {
  rm -rf "$work/r" && mkdir -p "$work/r/.github"
  cp -L "$repo/Cargo.toml" "$repo/Dockerfile" "$work/r/"
  cp -r "$repo/docker" "$work/r/"
  cp -r "$repo/.github/workflows" "$work/r/.github/"
}

fresh
"$check" "$work/r" >/dev/null || { echo "FAIL: check rejects the clean repo" >&2; exit 1; }

cases=(
  "Cargo.toml|s/^default = \[/default = [\"hosted\",/"
  "Cargo.toml|s/^s3 = \[/s3 = [\"kye2e\",/"
  "Dockerfile|s/^ARG DB=sqlite,mysql,postgresql\$/ARG DB=sqlite,mysql,postgresql,hosted/"
  "docker/Dockerfile.alpine|s/^ARG DB=sqlite,mysql,postgresql,enable_mimalloc\$/ARG DB=postgresql,s3,kye2e/"
  "docker/Dockerfile.j2|s/^ARG DB=sqlite,mysql,postgresql\$/ARG DB=postgresql,hosted/"
  "docker/docker-bake.hcl|/^variable \"DB\"/,/default/s/default = null/default = \"postgresql,s3,hosted\"/"
  ".github/workflows/release.yml|s/^ *SOURCE_COMMIT: \"\\\${{ env.SOURCE_COMMIT }}\"/&\n          DB: \"postgresql,s3,hosted\"/"
)
for c in "${cases[@]}"; do
  file="${c%%|*}" expr="${c#*|}"
  fresh
  cp "$work/r/$file" "$work/before"
  sed -i "$expr" "$work/r/$file"
  cmp -s "$work/before" "$work/r/$file" && { echo "FAIL: mutation did not apply: $c" >&2; exit 1; }
  if "$check" "$work/r" >"$work/out" 2>&1 || ! grep -q "^ERROR: " "$work/out"; then
    echo "FAIL: check accepted: $c" >&2
    exit 1
  fi
done
echo "check-public-image-features: clean repo passes, ${#cases[@]} injected flags fail"
