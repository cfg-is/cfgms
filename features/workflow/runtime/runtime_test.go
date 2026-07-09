// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package runtime_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/workflow/runtime"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// echoModuleBin is the path to the compiled echo_module binary. It is set by
// TestMain before any tests run.
var echoModuleBin string

// binaryDir holds the temp dir for the compiled echo_module binary; cleaned up
// after all tests complete.
var binaryDir string

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	var err error
	binaryDir, err = os.MkdirTemp("", "echo-workflow-module-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime_test: failed to create temp dir: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(binaryDir) }()

	echoModuleBin = filepath.Join(binaryDir, "echo_module")
	cmd := exec.Command("go", "build", "-o", echoModuleBin, "./testdata/echo_module")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "runtime_test: failed to build echo_module: %s: %v\n", out, err)
		return 1
	}

	return m.Run()
}

// shortBaseDir creates a temp dir under /tmp with a predictably short path so
// that socket paths constructed from it fit within the macOS sun_path limit
// (103 bytes).
func shortBaseDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "cfgms-wf-rt-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

// makeWorkflowBundle creates a minimal workflow-kind bundle using the echo_module binary.
func makeWorkflowBundle(binPath string) *bundle.Bundle {
	return &bundle.Bundle{
		Manifest: &featuremodules.ModuleMetadata{
			Name:      "echo",
			Version:   "0.1.0",
			Executors: []string{"controller"},
			Kind:      "workflow",
			Publisher: "test",
		},
		ContentHash: "sha256-echo-workflow-test-hash",
		Binaries:    map[string]string{goruntime.GOOS + "-" + goruntime.GOARCH: binPath},
	}
}

// TestEchoModuleLifecycle verifies the full lifecycle:
//   - Start() fork/execs echo_module and connects via gRPC
//   - Get() returns "echo:<resource_id>"
//   - Stop() sends Shutdown RPC and the process exits within 10 s
func TestEchoModuleLifecycle(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeWorkflowBundle(echoModuleBin)

	handle, err := rt.Start(b)
	require.NoError(t, err)
	require.NotNil(t, handle)
	assert.Equal(t, runtime.StateRunning, handle.GetState())

	// Call Get via gRPC; expect echo response.
	ctx := context.Background()
	resp, err := handle.Client.Get(ctx, &proto.GetRequest{ResourceId: "my-resource"})
	require.NoError(t, err)
	assert.Equal(t, "echo:my-resource", resp.ConfigData)

	// Stop and verify clean shutdown.
	require.NoError(t, rt.Stop(handle))
	assert.Equal(t, runtime.StateStopped, handle.GetState())
}

// TestEchoModuleLifecycle_ModuleInterface verifies that ModuleHandle implements
// features/modules.Module and that Get/Set delegate to the gRPC client correctly.
func TestEchoModuleLifecycle_ModuleInterface(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeWorkflowBundle(echoModuleBin)

	handle, err := rt.Start(b)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Compile-time check: ModuleHandle must satisfy the modules.Module interface.
	var _ featuremodules.Module = handle

	ctx := context.Background()

	// Get via modules.Module interface; verify ConfigState carries the echo response.
	state, err := handle.Get(ctx, "test-resource")
	require.NoError(t, err)
	require.NotNil(t, state, "Get must return a non-nil ConfigState")
	assert.Equal(t, "echo:test-resource", state.AsMap()["config_data"])

	// Verify ConfigState ToYAML/AsMap round-trip for the returned state.
	yamlBytes, err := state.ToYAML()
	require.NoError(t, err)
	assert.Contains(t, string(yamlBytes), "echo:test-resource",
		"ToYAML must serialise the echo response")
	assert.Equal(t, []string{"config_data"}, state.GetManagedFields())
	assert.NoError(t, state.Validate())

	// Set via modules.Module interface; verify the call succeeds (echo_module
	// responds with Applied = true and no error).
	setErr := handle.Set(ctx, "test-resource", state)
	require.NoError(t, setErr, "Set via modules.Module interface must succeed")

	require.NoError(t, rt.Stop(handle))
}

// TestStartReturnsErrWrongModuleKindForNonWorkflowBundle verifies that Start()
// returns ErrWrongModuleKind before any fork/exec for bundles whose kind is not "workflow".
func TestStartReturnsErrWrongModuleKindForNonWorkflowBundle(t *testing.T) {
	rt := runtime.NewModuleRuntime(t.TempDir())

	cases := []struct {
		name string
		kind string
	}{
		{"steward kind", "steward"},
		{"outpost kind", "outpost"},
		{"empty kind", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &bundle.Bundle{
				Manifest: &featuremodules.ModuleMetadata{
					Name:      "wrong-kind",
					Version:   "1.0.0",
					Kind:      tc.kind,
					Publisher: "test",
				},
				Binaries: map[string]string{goruntime.GOOS + "-" + goruntime.GOARCH: "/nonexistent"},
			}

			_, err := rt.Start(b)
			require.Error(t, err)
			assert.ErrorIs(t, err, runtime.ErrWrongModuleKind)
		})
	}
}

// TestStartReturnsErrWrongModuleKindForNilManifest verifies that a nil Manifest
// returns ErrWrongModuleKind.
func TestStartReturnsErrWrongModuleKindForNilManifest(t *testing.T) {
	rt := runtime.NewModuleRuntime(t.TempDir())
	b := &bundle.Bundle{
		Manifest: nil,
		Binaries: map[string]string{goruntime.GOOS + "-" + goruntime.GOARCH: "/nonexistent"},
	}
	_, err := rt.Start(b)
	require.Error(t, err)
	assert.ErrorIs(t, err, runtime.ErrWrongModuleKind)
}

// TestStopIsIdempotent verifies that calling Stop multiple times on the same
// handle does not error or panic.
func TestStopIsIdempotent(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeWorkflowBundle(echoModuleBin)

	handle, err := rt.Start(b)
	require.NoError(t, err)

	require.NoError(t, rt.Stop(handle))
	require.NoError(t, rt.Stop(handle))
}
