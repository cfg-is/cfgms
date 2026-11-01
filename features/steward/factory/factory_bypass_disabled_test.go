//go:build !cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/config"
	moduleruntime "github.com/cfgis/cfgms/features/steward/modules/runtime"
)

// TestLoadModule_BypassMode_RefusedInReleaseBuild: a build without
// cfgms_dev_bypass refuses to load any bundle under module_trust.mode: bypass,
// and no module process is tracked.
func TestLoadModule_BypassMode_RefusedInReleaseBuild(t *testing.T) {
	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "cfgms", nil) // unsigned
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	f := newTestFactory()
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)
	t.Cleanup(func() { f.UnloadAllModules() })

	instance, err := f.LoadModule("widget")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unavailable in a release build")
	assert.Nil(t, instance)

	f.mu.RLock()
	_, tracked := f.bundleHandles["widget"]
	f.mu.RUnlock()
	assert.False(t, tracked, "no module process may be started under bypass in a release build")
}
