#!/bin/bash
# Check that all source files have proper SPDX license headers
# Exit code 0 = all files have headers, 1 = missing headers found

set -e

MISSING_HEADERS=0
ERRORS=""

# Check Go files
echo "🔍 Checking Go files for SPDX license headers..."
while IFS= read -r file; do
    # Skip vendor, .git, and .cache directories
    if [[ "$file" == *"/vendor/"* ]] || [[ "$file" == *"/.git/"* ]] || [[ "$file" == *"/.cache/"* ]]; then
        continue
    fi

    # Check if file has SPDX header
    if ! grep -q "SPDX-License-Identifier:" "$file" 2>/dev/null; then
        ERRORS="${ERRORS}\n  ❌ Missing header: $file"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done < <(find . -name "*.go" -type f)

# Check proto files
echo "🔍 Checking .proto files for SPDX license headers..."
while IFS= read -r file; do
    # Skip vendor, .git, and .cache directories
    if [[ "$file" == *"/vendor/"* ]] || [[ "$file" == *"/.git/"* ]] || [[ "$file" == *"/.cache/"* ]]; then
        continue
    fi

    # Check if file has SPDX header
    if ! grep -q "SPDX-License-Identifier:" "$file" 2>/dev/null; then
        ERRORS="${ERRORS}\n  ❌ Missing header: $file"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done < <(find . -name "*.proto" -type f)

# Report results
if [ $MISSING_HEADERS -eq 0 ]; then
    echo "✅ All source files have proper SPDX license headers"
    exit 0
else
    echo ""
    echo "❌ LICENSE HEADER CHECK FAILED"
    echo ""
    echo "Found $MISSING_HEADERS file(s) without SPDX license headers:"
    echo -e "$ERRORS"
    echo ""
    echo "To add license headers, run:"
    echo "  make add-license-headers"
    echo ""
    exit 1
fi
