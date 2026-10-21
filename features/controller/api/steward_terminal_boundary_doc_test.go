// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	codeDeliveryBegin = "<!-- code-delivery-permissions:begin -->"
	codeDeliveryEnd   = "<!-- code-delivery-permissions:end -->"
)

var (
	docTableRow = regexp.MustCompile("^\\|\\s*`([^`]+)`\\s*\\|(.*)\\|\\s*$")
	docRouteRef = regexp.MustCompile("`(routes[a-z_]*\\.go)`")
)

// The remote-terminal switch's documented code-delivery permissions must exist
// in knownPermissions and be enforced by the named route file (Issue #5262).
func TestStewardOperatingModel_CodeDeliveryPermissionsMatchCode(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "architecture", "steward-operating-model.md"))
	require.NoError(t, err)
	text := string(doc)

	begin := strings.Index(text, codeDeliveryBegin)
	end := strings.Index(text, codeDeliveryEnd)
	require.True(t, begin >= 0 && end > begin, "doc must contain the code-delivery table between its marker comments")

	required := []string{
		"config:push", "steward:write-config", "steward:execute-scripts", "script:admin",
		"module:approve", "terminal:create", "installer:upload", "installer:delete",
		"installer:publish:steward", "installer:dispatch:steward", "steward:delete-config", "jobs:write",
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(text[begin+len(codeDeliveryBegin):end], "\n") {
		m := docTableRow.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || m[1] == "Permission ID" {
			continue
		}
		perm := m[1]
		seen[perm] = true
		assert.True(t, knownPermissions[perm], "documented permission %q is not in knownPermissions", perm)

		files := docRouteRef.FindAllStringSubmatch(m[2], -1)
		require.NotEmpty(t, files, "permission %q names no route file", perm)
		resource, action, ok := strings.Cut(perm, ":")
		require.True(t, ok, perm)
		call := fmt.Sprintf("requirePermission(%q, %q)", resource, action)
		for _, f := range files {
			src, rerr := os.ReadFile(f[1])
			require.NoError(t, rerr, "route file %s for %q", f[1], perm)
			assert.Contains(t, string(src), call, "%s does not enforce %q", f[1], perm)
		}
	}
	for _, perm := range required {
		assert.True(t, seen[perm], "doc table is missing required permission %q", perm)
	}
}
