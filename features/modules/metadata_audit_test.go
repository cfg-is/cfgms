// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package modules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModuleMetadata_ParsesAuditOperations verifies security.audit_operations
// is parsed from module.yaml and survives Clone (Issue #5564).
func TestModuleMetadata_ParsesAuditOperations(t *testing.T) {
	const manifest = `
name: dirmod
publisher: acme-corp
version: 1.0.0
description: test
executors: [steward]
security:
  audit_operations:
    - create_user
    - add_group_member
`
	md, err := ParseModuleMetadata(strings.NewReader(manifest))
	require.NoError(t, err)
	require.NotNil(t, md.Security)
	assert.Equal(t, []string{"create_user", "add_group_member"}, md.Security.AuditOperations)

	clone := md.Clone()
	assert.Equal(t, md.Security.AuditOperations, clone.Security.AuditOperations)
	clone.Security.AuditOperations[0] = "changed"
	assert.Equal(t, "create_user", md.Security.AuditOperations[0], "Clone must not alias the list")
}
