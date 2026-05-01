// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package keysafe_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/providers/internal/keysafe"
)

func TestValidateLeafField_RejectsTraversalInputs(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"path traversal relative", "../etc/passwd"},
		{"path traversal embedded", "foo/../bar"},
		{"null byte", "with\x00null"},
		{"absolute path", "/abs"},
		{"backslash traversal", `..\\windows`},
		{"windows drive letter", "C:foo"},
		{"single dot", "."},
		{"trailing dot", "foo."},
		{"trailing space", "foo "},
		{"leading space", " foo"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := keysafe.ValidateLeafField("test_field", tc.value)
			assert.Error(t, err, "expected rejection of %q", tc.value)
		})
	}
}

func TestValidateLeafField_AcceptsValidInputs(t *testing.T) {
	valid := []string{
		"",
		"config",
		"my-config",
		"my_config",
		"config123",
		"UPPER",
		"mixedCase",
	}
	for _, v := range valid {
		t.Run(v, func(t *testing.T) {
			err := keysafe.ValidateLeafField("test_field", v)
			assert.NoError(t, err, "expected acceptance of %q", v)
		})
	}
}

func TestValidateLeafField_EmptyAllowed(t *testing.T) {
	require.NoError(t, keysafe.ValidateLeafField("scope", ""))
}

func TestValidateTenantID_RejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"double slash", "root//msp-a"},
		{"leading slash", "/root"},
		{"trailing slash", "root/"},
		{"dotdot segment", "root/.."},
		{"dot segment", "root/."},
		{"backslash", `root\msp-a`},
		{"null byte", "root/\x00tenant"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := keysafe.ValidateTenantID(tc.value)
			assert.Error(t, err, "expected rejection of %q", tc.value)
		})
	}
}

func TestValidateTenantID_AcceptsHierarchicalID(t *testing.T) {
	valid := []string{
		"root",
		"root/msp-a",
		"root/msp-a/client-1",
		"root/msp-a/client-1/sub-tenant",
		"single-tenant",
	}
	for _, v := range valid {
		t.Run(v, func(t *testing.T) {
			err := keysafe.ValidateTenantID(v)
			assert.NoError(t, err, "expected acceptance of %q", v)
		})
	}
}

func TestValidateTenantID_ErrorContainsFieldInfo(t *testing.T) {
	err := keysafe.ValidateTenantID("root/../escaped")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID")
}

func TestValidateLeafField_ErrorContainsFieldName(t *testing.T) {
	err := keysafe.ValidateLeafField("namespace", "../etc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace")
}

func TestValidateLeafField_SanitizesControlCharsInError(t *testing.T) {
	err := keysafe.ValidateLeafField("name", "abc\x00def")
	require.Error(t, err)
	// The raw null byte must not appear verbatim in the error string.
	assert.NotContains(t, err.Error(), "\x00")
}
