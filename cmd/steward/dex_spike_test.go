// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDexSpikeCommand_Metadata verifies the diagnostic subcommand is wired as a
// hidden, no-args command named dex-spike with the expected flags — it must stay
// a hidden diagnostic (never a documented/production surface), per #2540's scope
// guardrail.
func TestDexSpikeCommand_Metadata(t *testing.T) {
	cmd := buildDexSpikeCommand()
	assert.Equal(t, "dex-spike", cmd.Name())
	assert.True(t, cmd.Hidden, "dex-spike must be a HIDDEN diagnostic subcommand")

	for _, f := range []string{"overhead-window-sec", "max-events-per-class", "json"} {
		assert.NotNilf(t, cmd.Flags().Lookup(f), "flag --%s must exist", f)
	}
}

// TestDexSpikeCommand_RegisteredOnRoot verifies the subcommand is attached to the
// steward root command so `cfgms-steward dex-spike` resolves.
func TestDexSpikeCommand_RegisteredOnRoot(t *testing.T) {
	root := buildRootCommand()
	found, _, err := root.Find([]string{"dex-spike"})
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "dex-spike", found.Name())
}
