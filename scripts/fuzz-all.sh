#!/usr/bin/env bash
# fuzz-all.sh — auto-discovers and runs all Go native fuzz targets in the listed
# packages, then uploads any crash corpora as workflow artifacts.
#
# Usage:
#   ./scripts/fuzz-all.sh [fuzztime]
#
# fuzztime defaults to 30s. Any new Fuzz* target added to a listed package is
# picked up automatically — no edits to this script or the CI workflow are needed.

set -euo pipefail

FUZZTIME="${1:-30s}"

PACKAGES=(
  "pkg/config"
  "features/controller/transport"
  "pkg/entitygraph/types"
  "pkg/cert"
  "features/controller/fleet/storage"
  "features/steward/dna"
)

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

overall_exit=0

for pkg in "${PACKAGES[@]}"; do
  echo "=== Discovering fuzz targets in ./${pkg} ==="
  targets=$(go test -list '^Fuzz' "./${pkg}" 2>/dev/null || true)
  if [ -z "$targets" ]; then
    echo "  No fuzz targets found in ./${pkg}, skipping."
    continue
  fi

  while IFS= read -r target; do
    [ -z "$target" ] && continue
    echo "--- Running ${target} in ./${pkg} for ${FUZZTIME} ---"
    if ! go test -run='^$' -fuzz="^${target}$" -fuzztime="${FUZZTIME}" "./${pkg}"; then
      echo "FAIL: ${target} in ./${pkg}"
      overall_exit=1
    fi

    # Collect any crash corpus entries produced during this run.
    corpus_dir="${pkg}/testdata/fuzz/${target}"
    if [ -d "${corpus_dir}" ] && [ "$(ls -A "${corpus_dir}")" ]; then
      echo "  Crash corpus found in ${corpus_dir} — will be uploaded as artifact."
    fi
  done <<< "$targets"
done

exit $overall_exit
