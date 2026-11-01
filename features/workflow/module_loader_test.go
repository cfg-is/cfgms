// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"errors"
	"os"
	goruntime "runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/workflow/runtime"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// newControllerBundle builds a signed controller-executor (workflow) payload
// bundle through the production assemble/sign path for the running platform. The
// binary is the file at binaryPath (a stand-in payload when it does not exist).
// When sign is non-nil it replaces the publisher signature with the signatures
// it returns for the bundle's content hash, so a test can present any signature
// set to a cache that stores signatures verbatim.
func newControllerBundle(t *testing.T, name, publisher, version, binaryPath string, sign func(contentHash string) []bundle.BundleSignature) *bundle.Bundle {
	t.Helper()
	osArch := goruntime.GOOS + "-" + goruntime.GOARCH
	data, err := os.ReadFile(binaryPath) // #nosec G304 -- test-controlled path to a binary the test built
	if err != nil {
		data = []byte("stand-in binary for " + name)
	}
	b := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher:     publisher,
		Name:          name,
		Version:       version,
		Executors:     []string{"controller"},
		Platforms:     []string{osArch},
		BinaryContent: map[string][]byte{osArch: data},
	}).Bundle
	if sign != nil {
		b.Signatures = sign(b.ContentHash)
	}
	return b
}

// TestWorkflowModuleFactory_NilCache verifies that a factory built without
// a cache rejects every CreateModuleInstance call with a clear message —
// rather than panicking or returning a generic error. REST-only controllers
// that don't resolve modules through the engine intentionally pass nil; if
// such a deployment somehow tries to instantiate a module the error must
// be self-explanatory.
func TestWorkflowModuleFactory_NilCache(t *testing.T) {
	loader := NewWorkflowModuleFactory(nil, nil)
	module, err := loader.CreateModuleInstance("any-module")
	require.Error(t, err)
	assert.Nil(t, module)
	assert.Contains(t, err.Error(), "no cache backing")
}

// TestWorkflowModuleFactory_ModuleNotCached verifies that a name that does
// not match any cached bundle returns the ErrModuleNotCached sentinel
// wrapped with the requested name — the caller-facing path operators
// expect when surfacing "no bundle available" to an operator.
func TestWorkflowModuleFactory_ModuleNotCached(t *testing.T) {
	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	require.NoError(t, err)

	loader := NewWorkflowModuleFactory(c, nil)
	module, err := loader.CreateModuleInstance("nonexistent-module")

	require.Error(t, err)
	assert.Nil(t, module)
	assert.True(t, errors.Is(err, ErrModuleNotCached),
		"missing bundle must surface as ErrModuleNotCached, got: %v", err)
	assert.Contains(t, err.Error(), "nonexistent-module")
}

// TestWorkflowModuleFactory_NilRuntime verifies that a factory with a cache
// but no runtime returns a descriptive error when a matching approved bundle
// is found — rather than a confusing nil-pointer panic.
func TestWorkflowModuleFactory_NilRuntime(t *testing.T) {
	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	require.NoError(t, err)

	// Put an approved controller-kind bundle in the cache.
	b := newControllerBundle(t, "my-module", "test", "1.0.0", "/nonexistent/bin", nil)
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	loader := NewWorkflowModuleFactory(c, nil)
	module, err := loader.CreateModuleInstance("my-module")

	require.Error(t, err)
	assert.Nil(t, module)
	assert.Contains(t, err.Error(), "no workflow module runtime is configured",
		"error must clearly explain that the runtime is missing")
}

// TestWorkflowModuleFactory_IntegrationWithEchoModule is the end-to-end
// integration test that verifies the complete path from cache lookup to
// gRPC call:
//
//   - A controller-kind bundle is published and approved in a real ModuleCache.
//   - WorkflowModuleFactory.CreateModuleInstance resolves the bundle, starts the
//     echo_module subprocess via the workflow ModuleRuntime, and returns a
//     modules.Module backed by the live gRPC connection.
//   - Get("my-resource") via the modules.Module interface returns "echo:my-resource".
//
// The echo_module binary is compiled once per test run by TestMain.
func TestWorkflowModuleFactory_IntegrationWithEchoModule(t *testing.T) {
	if integrationEchoModuleBin == "" {
		t.Skip("echo_module binary not available — integration test skipped")
	}

	// Set up a real module cache with an approved echo bundle.
	cacheDir := t.TempDir()
	c, err := cache.New(cacheDir)
	require.NoError(t, err)

	b := newControllerBundle(t, "echo", "test", "0.1.0", integrationEchoModuleBin, nil)
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	// Use /tmp explicitly so the socket path fits within macOS's 103-byte sun_path limit.
	// t.TempDir() on macOS generates paths under /var/folders/... that are too long.
	runtimeDir, err := os.MkdirTemp("/tmp", "cfgms-wf-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	rt := runtime.NewModuleRuntime(runtimeDir)
	factory := NewWorkflowModuleFactory(c, rt)

	// CreateModuleInstance must resolve the cached bundle, fork/exec the binary,
	// and return a live gRPC-backed module.
	mod, err := factory.CreateModuleInstance("echo")
	require.NoError(t, err, "CreateModuleInstance must not return ErrWorkflowRuntimeNotAvailable")
	require.NotNil(t, mod)

	// Retrieve the handle for lifecycle cleanup.
	handle, ok := mod.(*runtime.ModuleHandle)
	require.True(t, ok, "CreateModuleInstance must return *runtime.ModuleHandle")
	t.Cleanup(func() { _ = rt.Stop(handle) })

	// Call Get via the modules.Module interface and verify the echo response.
	ctx := context.Background()
	state, err := mod.Get(ctx, "my-resource")
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, "echo:my-resource", state.AsMap()["config_data"],
		"module Get must return the echo response via the gRPC client")
}
