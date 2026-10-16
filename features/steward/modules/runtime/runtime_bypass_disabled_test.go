//go:build !cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package runtime_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
)

// TestBypassModeRefusedInReleaseBuild: a build without cfgms_dev_bypass refuses
// to start any bundle under module_trust.mode: bypass, and never execs it.
func TestBypassModeRefusedInReleaseBuild(t *testing.T) {
	dir := shortBaseDir(t)
	rt := runtime.NewModuleRuntime(dir)
	b := makeUnsignedBundle(t, echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unavailable in a release build")
	assert.Nil(t, handle)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a refused Start must not create a socket directory entry")
}
