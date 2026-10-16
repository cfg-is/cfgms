//go:build cfgms_dev_bypass

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package factory

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	moduleruntime "github.com/cfgis/cfgms/features/steward/modules/runtime"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Bypass mode loads a bundle only in a cfgms_dev_bypass build; the release-build
// refusal is covered by factory_bypass_disabled_test.go.

// TestLoadModule_BypassMode_LoadsUnsignedBundleAndWarnsNamingMode is the
// [REQUIRED TEST] for bypass mode: a bundle with an absent signature loads
// under module_trust.mode: bypass, and the steward emits a warning naming the
// mode at load time — a mode that disables a trust check must be visible in
// the log, not silent.
func TestLoadModule_BypassMode_LoadsUnsignedBundleAndWarnsNamingMode(t *testing.T) {
	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "cfgms", nil) // unsigned
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	capturingLogger := logging.NewCapturingLogger()
	f := NewWithStewardID(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{}, "test-steward", capturingLogger)
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)
	t.Cleanup(func() { f.UnloadAllModules() })

	instance, err := f.LoadModule("widget")
	require.NoError(t, err, "bypass mode must load a bundle with an absent signature")
	assert.NotNil(t, instance)

	entry, found := capturingLogger.FindWarn("loading module bundle with module_trust.mode=bypass: signature verification disabled")
	require.True(t, found, "bypass mode must emit a warning naming the mode at load time; got messages: %v", capturingLogger.WarnMessages)
	assert.Equal(t, "widget", entry["module"])
	assert.Equal(t, "bypass", entry["mode"])
}

// TestLoadModule_BypassMode_LoadsInvalidSignatureBundle is the other half of
// the same AC: a bundle whose signature would fail strict verification (signed
// by a publisher neither baked-in nor configured) still loads under bypass
// mode, since bypass never verifies the signature at all.
func TestLoadModule_BypassMode_LoadsInvalidSignatureBundle(t *testing.T) {
	_, untrustedPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "untrusted-vendor", untrustedPriv)
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	capturingLogger := logging.NewCapturingLogger()
	f := NewWithStewardID(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{}, "test-steward", capturingLogger)
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)
	t.Cleanup(func() { f.UnloadAllModules() })

	instance, err := f.LoadModule("widget")
	require.NoError(t, err, "bypass mode must load a bundle even when its signature would fail strict verification")
	assert.NotNil(t, instance)
	assert.GreaterOrEqual(t, capturingLogger.WarnCount(), 1, "bypass mode must emit a warning at load time")
}
