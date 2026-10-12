#!/usr/bin/env bash
# Install gosec and staticcheck built against a golang.org/x/tools new enough to
# read the compiler export data written by the active Go toolchain.
#
# Both tools load packages through x/tools' gcimporter. gosec v2.29.0 vendors
# x/tools v0.49.0 and staticcheck 2026.2.1 vendors a v0.44.1 pseudo-version;
# neither can decode the export data Go 1.27.2 writes ("export data version 5 is
# greater than maximum supported version 4"). `go install pkg@version` ignores
# any override, so this builds both from a throwaway module that raises x/tools.
#
# Pins (keep in sync with the install hints in the Makefile and docs):
#   gosec       v2.29.0   (2026-08-25)
#   staticcheck 2026.2.1  (honnef.co/go/tools v0.8.1, 2026-08-21)
#   x/tools     v0.50.0   (2026-09-08)
#
# Usage: scripts/install-go-analyzers.sh   (installs to $GOBIN or $(go env GOPATH)/bin)
set -euo pipefail

GOSEC_VERSION="v2.29.0"
STATICCHECK_VERSION="2026.2.1"
XTOOLS_VERSION="v0.50.0"

work="$(mktemp -d)"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

cd "$work"
printf 'module analyzers\n\ngo 1.27\n' > go.mod
cat > tools.go <<'GO'
package analyzers

import (
	_ "github.com/securego/gosec/v2/cmd/gosec"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
GO

go get "github.com/securego/gosec/v2@${GOSEC_VERSION}" \
	"honnef.co/go/tools@${STATICCHECK_VERSION}" \
	"golang.org/x/tools@${XTOOLS_VERSION}"
go mod tidy
go install github.com/securego/gosec/v2/cmd/gosec honnef.co/go/tools/cmd/staticcheck
