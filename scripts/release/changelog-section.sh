#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Print the body of the CHANGELOG.md section for a release tag: the lines after
# the matching "## [X.Y.Z]" heading up to, not including, the next "## [".
# Usage: changelog-section.sh vX.Y.Z [CHANGELOG.md]

set -euo pipefail

TAG="${1:?usage: changelog-section.sh vX.Y.Z [CHANGELOG.md]}"
FILE="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/CHANGELOG.md}"
VERSION="${TAG#v}"

if ! TARGET="## [${VERSION}]" awk '
    index($0, "## [") == 1 {
        if (found) exit
        if (index($0, ENVIRON["TARGET"]) == 1) { found = 1; next }
    }
    found { print }
    END { if (!found) exit 3 }
' "$FILE"; then
    echo "Error: no CHANGELOG section for $TAG" >&2
    exit 1
fi
