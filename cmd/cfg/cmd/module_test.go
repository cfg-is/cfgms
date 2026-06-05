// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleRefRE_ValidRefs(t *testing.T) {
	valid := []string{
		"cfgms/hyperv@0.2.1",
		"acme-corp/custom-module@1.3.0",
		"publisher/name@version",
		"a/b@c",
		"vendor_a/tool.v2@1.0.0-rc1",
	}
	for _, ref := range valid {
		assert.True(t, moduleRefRE.MatchString(ref), "expected valid ref: %q", ref)
	}
}

func TestModuleRefRE_InvalidRefs(t *testing.T) {
	invalid := []string{
		"no-at-sign",
		"publisher/name",
		"@version",
		"/name@version",
		"publisher//name@version",
		"publisher/name@",
		"publisher name@version",
		"../evil/name@version",
	}
	for _, ref := range invalid {
		assert.False(t, moduleRefRE.MatchString(ref), "expected invalid ref: %q", ref)
	}
}

// TestModuleListCmd_StatusValidation verifies the status flag rejects illegal values.
// Only the validation path is tested here; valid statuses proceed to network I/O
// which is out of scope for unit tests.
func TestModuleListCmd_StatusValidation(t *testing.T) {
	invalidStatuses := []string{"invalid", "PENDING", "Approved", "queued", "ALL"}
	for _, s := range invalidStatuses {
		t.Run("invalid_"+s, func(t *testing.T) {
			origStatus := moduleListStatus
			moduleListStatus = s
			defer func() { moduleListStatus = origStatus }()

			err := runModuleList(moduleListCmd, nil)
			assert.ErrorContains(t, err, "invalid --status", "status %q must be rejected", s)
		})
	}
}

func TestModuleApproveCmd_ParsesRef(t *testing.T) {
	// Verify that a well-formed ref passes moduleRefRE validation.
	ref := "cfgms/hyperv@0.2.1"
	require.True(t, moduleRefRE.MatchString(ref))

	// Verify that runModuleApprove rejects an invalid ref without calling the API.
	err := runModuleApprove(moduleApproveCmd, []string{"invalid-ref-no-at"})
	assert.ErrorContains(t, err, "invalid module reference")
}

func TestShortHash(t *testing.T) {
	assert.Equal(t, "abc123def456...", shortHash("abc123def456xyz"))
	assert.Equal(t, "abc123", shortHash("abc123"))
	assert.Equal(t, "abc123456789", shortHash("abc123456789"))
}
