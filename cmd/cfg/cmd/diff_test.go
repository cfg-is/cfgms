// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiffCmdBaseRefFlagRemoved asserts that the dead --base-ref flag is not
// registered on diffCmd. The flag was never read by runDiff or runThreeWayDiff;
// args[0] is used directly as the base reference.
func TestDiffCmdBaseRefFlagRemoved(t *testing.T) {
	flag := diffCmd.Flags().Lookup("base-ref")
	assert.Nil(t, flag, "--base-ref must not be registered on diffCmd")
}

// TestDiffCmdThreeWayFlagPresent confirms the --three-way flag is still
// registered, so removing --base-ref did not accidentally drop it.
func TestDiffCmdThreeWayFlagPresent(t *testing.T) {
	flag := diffCmd.Flags().Lookup("three-way")
	require.NotNil(t, flag, "--three-way flag must still be registered on diffCmd")
	assert.Equal(t, "bool", flag.Value.Type())
}

// TestDiffCmdArgsValidationThreeWay verifies that the cobra Args validator on
// diffCmd accepts exactly three positional arguments (the three-way path).
func TestDiffCmdArgsValidationThreeWay(t *testing.T) {
	err := diffCmd.Args(diffCmd, []string{"base.yaml", "left.yaml", "right.yaml"})
	assert.NoError(t, err, "three positional args must satisfy diffCmd.Args validator")
}

// TestDiffCmdArgsValidationTwoWay verifies two positional args are still accepted.
func TestDiffCmdArgsValidationTwoWay(t *testing.T) {
	err := diffCmd.Args(diffCmd, []string{"old.yaml", "new.yaml"})
	assert.NoError(t, err, "two positional args must satisfy diffCmd.Args validator")
}

// TestDiffCmdArgsValidationRejectsOne ensures fewer than two args are rejected.
func TestDiffCmdArgsValidationRejectsOne(t *testing.T) {
	err := diffCmd.Args(diffCmd, []string{"only.yaml"})
	assert.Error(t, err, "one positional arg must be rejected by diffCmd.Args validator")
}
