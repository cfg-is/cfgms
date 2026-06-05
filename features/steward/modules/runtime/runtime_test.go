// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package runtime_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
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
	binaryDir, err = os.MkdirTemp("", "echo-module-test-*")
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

// makeBypassBundle creates a minimal steward-kind bundle using the echo_module
// binary. Trust mode bypass is used by tests that focus on lifecycle, not trust.
func makeBypassBundle(binPath string) *bundle.Bundle {
	return &bundle.Bundle{
		Manifest: &featuremodules.ModuleMetadata{
			Name:      "echo",
			Version:   "0.1.0",
			Executors: []string{"steward"},
			Kind:      "steward",
			Publisher: "test",
		},
		ContentHash: "sha256-echo-test-hash",
		Binaries:    map[string]string{goruntime.GOOS + "-" + goruntime.GOARCH: binPath},
	}
}

// TestEchoModuleLifecycle verifies the full lifecycle:
//   - Start() fork/execs echo_module and connects via gRPC
//   - Get() returns "echo:<resource_id>"
//   - Stop() sends Shutdown RPC and the process exits within 10 s
func TestEchoModuleLifecycle(t *testing.T) {
	rt := runtime.NewModuleRuntime(t.TempDir())
	b := makeBypassBundle(echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
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

// TestEchoModuleLifecycleWithOverlongRuntimeDir is the regression test for the
// macOS CI failures (PR #1897 review): on macOS, t.TempDir() returns paths
// under /var/folders/... that, joined with the socket filename, exceed the
// 104-byte sun_path limit. The runtime must fall back to a short hashed path
// under /tmp so net.Listen("unix", ...) succeeds. This test forces the fallback
// path on all platforms by passing a deliberately long runtimeDir.
func TestEchoModuleLifecycleWithOverlongRuntimeDir(t *testing.T) {
	// Build a runtime dir long enough that the natural socket path overflows
	// 103 bytes — exercising the fallback even on Linux where t.TempDir() is
	// normally short.
	base := t.TempDir()
	deep := filepath.Join(base,
		"deeply", "nested", "directory", "tree",
		"with", "enough", "path", "components",
		"to", "blow", "past", "the", "macos", "sun_path", "limit",
	)
	require.NoError(t, os.MkdirAll(deep, 0o755))

	rt := runtime.NewModuleRuntime(deep)
	b := makeBypassBundle(echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)
	require.NotNil(t, handle)

	ctx := context.Background()
	resp, err := handle.Client.Get(ctx, &proto.GetRequest{ResourceId: "long-path"})
	require.NoError(t, err)
	assert.Equal(t, "echo:long-path", resp.ConfigData)

	require.NoError(t, rt.Stop(handle))
}

// TestStartReturnsErrWrongModuleKindForNonStewardBundle verifies that Start()
// returns ErrWrongModuleKind immediately, before any fork/exec, for bundles
// whose kind is not "steward".
func TestStartReturnsErrWrongModuleKindForNonStewardBundle(t *testing.T) {
	rt := runtime.NewModuleRuntime(t.TempDir())

	cases := []struct {
		name string
		kind string
	}{
		{"outpost kind", "outpost"},
		{"workflow kind", "workflow"},
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

			_, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
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
	_, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, runtime.ErrWrongModuleKind)
}

// TestStrictModeRejectsControllerApprovedUnknownPublisher is the key threat-model
// test: a compromised controller cannot push arbitrary modules to strict-mode
// stewards. Even if the controller approved the bundle, if the steward's local
// trust store does not contain the publisher's key, Start() must return
// ErrPublisherNotTrusted before any fork/exec occurs.
func TestStrictModeRejectsControllerApprovedUnknownPublisher(t *testing.T) {
	// Generate an "unknown" publisher key pair — not in the steward's trust set.
	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Sign a bundle with the unknown key.
	b := &bundle.Bundle{
		Manifest: &featuremodules.ModuleMetadata{
			Name:      "malicious-module",
			Version:   "1.0.0",
			Executors: []string{"steward"},
			Kind:      "steward",
			Publisher: "unknown-vendor",
		},
		ContentHash: "sha256-controller-approved-hash",
		Binaries:    map[string]string{goruntime.GOOS + "-" + goruntime.GOARCH: "/nonexistent/path"},
	}
	sig := ed25519.Sign(unknownPriv, []byte(b.ContentHash))
	b.Signatures = []bundle.BundleSignature{
		{Publisher: "unknown-vendor", Algorithm: "ed25519", Signature: sig},
	}

	rt := runtime.NewModuleRuntime(t.TempDir())

	// Start in strict mode with no additional publishers.
	_, err = rt.Start(b, stewardtypes.ModuleTrustModeStrict, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, pkgtrust.ErrPublisherNotTrusted,
		"strict-mode steward must reject bundles from untrusted publishers before fork/exec")
}

// TestControllerModePassesUnsignedBundle verifies that controller mode skips
// signature verification.
func TestControllerModePassesUnsignedBundle(t *testing.T) {
	rt := runtime.NewModuleRuntime(t.TempDir())
	b := makeBypassBundle(echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(handle))
}

// TestBypassModePassesUnsignedBundle verifies that bypass mode skips
// signature verification.
func TestBypassModePassesUnsignedBundle(t *testing.T) {
	rt := runtime.NewModuleRuntime(t.TempDir())
	b := makeBypassBundle(echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(handle))
}

// TestStopIsIdempotent verifies that calling Stop multiple times on the same
// handle does not error or panic.
func TestStopIsIdempotent(t *testing.T) {
	rt := runtime.NewModuleRuntime(t.TempDir())
	b := makeBypassBundle(echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeBypass, nil)
	require.NoError(t, err)

	require.NoError(t, rt.Stop(handle))
	require.NoError(t, rt.Stop(handle)) // second call must not error
}

// testEnforcerRuntimeWithKey returns a ModuleRuntime whose trust enforcer uses
// the given public key as the CFGMS identity (for strict-mode tests that need to
// sign with a known key).
func testEnforcerRuntimeWithKey(t *testing.T, cfgmsPub ed25519.PublicKey) *runtime.ModuleRuntime {
	t.Helper()
	rt := runtime.NewModuleRuntimeWithEnforcer(
		t.TempDir(),
		stewardtrust.NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{
				Name:      "cfgms",
				PublicKey: []byte(cfgmsPub),
				Algorithm: "ed25519",
			}
		}),
	)
	return rt
}

// TestStrictModeAcceptsCFGMSSignedBundle verifies that strict mode accepts a
// bundle signed with the configured CFGMS publisher identity.
func TestStrictModeAcceptsCFGMSSignedBundle(t *testing.T) {
	cfgmsPub, cfgmsPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	b := makeBypassBundle(echoModuleBin)
	sig := ed25519.Sign(cfgmsPriv, []byte(b.ContentHash))
	b.Signatures = []bundle.BundleSignature{
		{Publisher: "cfgms", Algorithm: "ed25519", Signature: sig},
	}

	rt := testEnforcerRuntimeWithKey(t, cfgmsPub)
	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeStrict, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(handle))
}
