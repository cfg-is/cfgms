// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proto "github.com/cfgis/cfgms/api/proto/modules"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/modules/install"
	"github.com/cfgis/cfgms/features/steward/modules/runtime"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// echoModuleBin is the path to the compiled echo_module binary. It is set by
// TestMain before any tests run.
var echoModuleBin string

// exitModuleBin is the path to the compiled exit_module binary — a module that
// exits immediately without listening. Set by TestMain before any tests run.
var exitModuleBin string

// shortBaseDir returns a runtimeDir for the module runtime. On Unix it is a
// temp dir under /tmp with a predictably short path so socket paths
// constructed from it fit within the macOS sun_path limit (103 bytes) —
// t.TempDir() on macOS returns /var/folders/... paths that are already 80+
// bytes, causing makeSocketPath to error before any gRPC is tried. On Windows
// runtimeDir is unused by makeSocketPath (named pipes are identified by name,
// not filesystem path — see socket_windows.go), so t.TempDir() is fine there.
func shortBaseDir(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return t.TempDir()
	}
	base, err := os.MkdirTemp("/tmp", "cfgms-rt-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

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

// installOpts configures installTestBundle.
type installOpts struct {
	name      string
	publisher string
	key       ed25519.PrivateKey
}

// installTestBundle installs the module binary at binPath as a real, signed
// installation root (built and written through the production bundle code, on a
// protected parent directory) and returns the bundle read back from it plus the
// root. The bundle therefore carries InstallRoot and a real content hash.
func installTestBundle(t *testing.T, binPath string, o installOpts) (*bundle.Bundle, string) {
	t.Helper()
	content, err := os.ReadFile(binPath)
	require.NoError(t, err)
	if o.name == "" {
		o.name = "echo"
	}
	if o.publisher == "" {
		o.publisher = "test"
	}
	platform := goruntime.GOOS + "-" + goruntime.GOARCH
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Name:          o.name,
		Publisher:     o.publisher,
		Key:           o.key,
		BinaryContent: map[string][]byte{platform: content},
	})
	parent := t.TempDir()
	require.NoError(t, install.EnsureProtectedDir(parent))
	root := filepath.Join(parent, o.name)
	sb.WriteRoot(t, root, bundle.WriteOptions{})
	b, err := bundle.ReadInstalled(root)
	require.NoError(t, err)
	return b, root
}

// makeUnsignedBundle installs a minimal unsigned steward-kind bundle around
// binPath. Tests that focus on lifecycle, not trust, start it in controller
// mode, which loads an unsigned bundle in every build.
func makeUnsignedBundle(t *testing.T, binPath string) *bundle.Bundle {
	t.Helper()
	b, _ := installTestBundle(t, binPath, installOpts{})
	return b
}

// TestEchoModuleLifecycle verifies the full lifecycle:
//   - Start() fork/execs echo_module and connects via gRPC
//   - Get() returns "echo:<resource_id>"
//   - Stop() sends Shutdown RPC and the process exits within 10 s
func TestEchoModuleLifecycle(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeUnsignedBundle(t, echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
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
	b := makeUnsignedBundle(t, exitModuleBin)

	start := time.Now()
	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, handle)
	assert.Contains(t, err.Error(), "exited before it was ready",
		"error must identify the module's exit rather than a generic listen timeout; got %v", err)
	assert.Less(t, elapsed, 10*time.Second,
		"Start must report the dead child promptly, not wait out the 30 s listen deadline (took %s)", elapsed)
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

			_, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
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
	_, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
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
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeUnsignedBundle(t, echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(handle))
}

// TestStopIsIdempotent verifies that calling Stop multiple times on the same
// handle does not error or panic.
func TestStopIsIdempotent(t *testing.T) {
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	b := makeUnsignedBundle(t, echoModuleBin)

	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
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
		shortBaseDir(t),
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

	b, _ := installTestBundle(t, echoModuleBin, installOpts{publisher: "cfgms", key: cfgmsPriv})

	rt := testEnforcerRuntimeWithKey(t, cfgmsPub)
	handle, err := rt.Start(b, stewardtypes.ModuleTrustModeStrict, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(handle))
}

// trustCase is one trust mode with a runtime and signing key that satisfies it.
type trustCase struct {
	name string
	mode stewardtypes.ModuleTrustMode
}

// allTrustModes lists the trust modes every build honours. A cfgms_dev_bypass
// build appends bypass (runtime_bypass_allowed_test.go).
var allTrustModes = []trustCase{
	{"controller", stewardtypes.ModuleTrustModeController},
	{"strict", stewardtypes.ModuleTrustModeStrict},
}

// installForMode installs the echo module signed by a CFGMS identity the
// returned runtime trusts, so the same bundle starts in every trust mode.
func installForMode(t *testing.T) (*bundle.Bundle, string, *runtime.ModuleRuntime) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	b, root := installTestBundle(t, echoModuleBin, installOpts{publisher: "cfgms", key: priv})
	return b, root, testEnforcerRuntimeWithKey(t, pub)
}

// TestStartRefusesBinaryModifiedAfterInstall: a binary that changed between
// install and Start is never executed, in any trust mode.
func TestStartRefusesBinaryModifiedAfterInstall(t *testing.T) {
	for _, tc := range allTrustModes {
		t.Run(tc.name, func(t *testing.T) {
			b, root, rt := installForMode(t)
			bin := filepath.Join(root, b.Binaries[goruntime.GOOS+"-"+goruntime.GOARCH])
			orig, err := os.ReadFile(bin)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(bin, append(orig, []byte("tampered")...), 0o755))

			h, err := rt.Start(b, tc.mode, nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
			assert.Nil(t, h)
		})
	}
}

// TestStartRefusesExtraFileInRoot: padding next to the binary is refused at Start.
func TestStartRefusesExtraFileInRoot(t *testing.T) {
	for _, tc := range allTrustModes {
		t.Run(tc.name, func(t *testing.T) {
			b, root, rt := installForMode(t)
			require.NoError(t, os.WriteFile(filepath.Join(root, "extra.dll"), []byte("x"), 0o644))

			h, err := rt.Start(b, tc.mode, nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, bundle.ErrUnexpectedEntry)
			assert.Nil(t, h)
		})
	}
}

// TestStartRefusesSidecarAndBinaryRewrittenTogether: a binary, its digest and the
// sidecar's content hash rewritten consistently are self-consistent but no longer
// hash to the value trust verification covered.
func TestStartRefusesSidecarAndBinaryRewrittenTogether(t *testing.T) {
	b, root, rt := installForMode(t)
	platform := goruntime.GOOS + "-" + goruntime.GOARCH

	other := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Name: "echo", Publisher: "cfgms",
		BinaryContent: map[string][]byte{platform: []byte("replacement binary")},
	})
	replacement := filepath.Join(t.TempDir(), "root")
	other.WriteRoot(t, replacement, bundle.WriteOptions{})
	for _, name := range []string{b.Binaries[platform], bundle.BundleSidecarFileName, bundle.ManifestFileName} {
		data, err := os.ReadFile(filepath.Join(replacement, name))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(root, name), data, 0o755))
	}

	h, err := rt.Start(b, stewardtypes.ModuleTrustModeStrict, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, bundle.ErrContentHashMismatch)
	assert.Nil(t, h)
}

// TestStartRunsPlatformOnlyInstallOfMultiPlatformBundle: a root holding only the
// running platform's binary (digests for others recorded) loads and runs; editing
// the running platform's digest in the sidecar is refused.
func TestStartRunsPlatformOnlyInstallOfMultiPlatformBundle(t *testing.T) {
	platform := goruntime.GOOS + "-" + goruntime.GOARCH
	otherPlatform := "linux-arm64"
	if platform == otherPlatform {
		otherPlatform = "linux-amd64"
	}
	content, err := os.ReadFile(echoModuleBin)
	require.NoError(t, err)
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Name:          "multi",
		Platforms:     []string{platform, otherPlatform},
		BinaryContent: map[string][]byte{platform: content},
	})
	parent := t.TempDir()
	require.NoError(t, install.EnsureProtectedDir(parent))
	root := filepath.Join(parent, "multi")
	sb.WriteRoot(t, root, bundle.WriteOptions{Platform: platform})

	b, err := bundle.ReadInstalled(root)
	require.NoError(t, err)
	assert.Contains(t, b.BinaryDigests, otherPlatform)
	assert.NotContains(t, b.Binaries, otherPlatform)

	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	h, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
	require.NoError(t, err)
	require.NoError(t, rt.Stop(h))

	// Edit the running platform's digest in the sidecar.
	sidecar := filepath.Join(root, bundle.BundleSidecarFileName)
	data, err := os.ReadFile(sidecar)
	require.NoError(t, err)
	digest := b.BinaryDigests[platform]
	flipped := "0" + digest[1:]
	if digest[0] == '0' {
		flipped = "1" + digest[1:]
	}
	require.NoError(t, os.WriteFile(sidecar, []byte(strings.Replace(string(data), digest, flipped, 1)), 0o644))

	_, err = bundle.ReadInstalled(root)
	require.Error(t, err, "load must refuse a sidecar whose digest for this platform was edited")
	h, err = rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
	require.Error(t, err, "Start must refuse the edited sidecar too")
	assert.Nil(t, h)
}

// TestStartRefusesBundleWithoutInstallRoot: a bundle not read from an
// installation root has nothing to verify.
func TestStartRefusesBundleWithoutInstallRoot(t *testing.T) {
	b := makeUnsignedBundle(t, echoModuleBin)
	b.InstallRoot = ""
	rt := runtime.NewModuleRuntime(shortBaseDir(t))
	h, err := rt.Start(b, stewardtypes.ModuleTrustModeController, nil)
	require.ErrorIs(t, err, runtime.ErrNoInstallRoot)
	assert.Nil(t, h)
}
