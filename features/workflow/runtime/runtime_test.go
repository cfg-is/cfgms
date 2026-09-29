// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package runtime_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"
	"time"

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

// exitModuleBin is the path to the compiled exit_module binary — a module that
// exits immediately without listening. Set by TestMain before any tests run.
var exitModuleBin string

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

	echoModuleBin = filepath.Join(binaryDir, "echo_module"+exeSuffix())
	cmd := exec.Command("go", "build", "-o", echoModuleBin, "./testdata/echo_module")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "runtime_test: failed to build echo_module: %s: %v\n", out, err)
		return 1
	}

	exitModuleBin = filepath.Join(binaryDir, "exit_module"+exeSuffix())
	cmd = exec.Command("go", "build", "-o", exitModuleBin, "./testdata/exit_module")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "runtime_test: failed to build exit_module: %s: %v\n", out, err)
		return 1
	}

	return m.Run()
}

// exeSuffix returns the platform executable suffix (".exe" on Windows, empty
// elsewhere) so exec.Command can resolve a binary built with "go build -o":
// on Windows, exec.LookPath requires a PATHEXT-recognized extension.
func exeSuffix() string {
	if goruntime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// shortBaseDir returns a runtimeDir for the module runtime. On Unix it is a
// temp dir under /tmp with a predictably short path so socket paths
// constructed from it fit within the macOS sun_path limit (103 bytes). On
// Windows runtimeDir is unused by makeSocketPath (named pipes are identified
// by name, not filesystem path — see socket_windows.go), so t.TempDir() is
// fine there.
func shortBaseDir(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return t.TempDir()
	}
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

// TestStartFailsFastWhenModuleExitsBeforeListening asserts Start reports a
// module that died during startup — promptly, rather than waiting out the 30 s
// listen deadline.
//
// The runtime reaps the child from the moment it is forked, so a module that
// fails closed at startup is reported as an early exit. That case is not
// hypothetical: contract.Listen fails closed when the address it was given is
// already held by another local process (on Windows, a named pipe another user
// created first). Before, cmd.Wait() was not consulted until after the
// handshake, so the runtime kept polling the address and would have accepted,
// handshaked with and trusted whatever other server answered there.
func TestStartFailsFastWhenModuleExitsBeforeListening(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeWorkflowBundle(exitModuleBin)

	start := time.Now()
	handle, err := rt.Start(b)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, handle)
	assert.Contains(t, err.Error(), "exited before it was ready",
		"error must identify the module's exit rather than a generic listen timeout; got %v", err)
	assert.Less(t, elapsed, 10*time.Second,
		"Start must report the dead child promptly, not wait out the 30 s listen deadline (took %s)", elapsed)
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
