// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package factory

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	featuremodules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/adapter"
	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	moduleruntime "github.com/cfgis/cfgms/features/steward/modules/runtime"
	stewardtrust "github.com/cfgis/cfgms/features/steward/modules/trust"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	pkgtrust "github.com/cfgis/cfgms/pkg/modules/trust"
)

// --- shared test fixtures: a real, compiled echo_module binary ---

// echoModuleBin is the path to a compiled copy of the steward module
// runtime's own echo_module test fixture
// (features/steward/modules/runtime/testdata/echo_module). Reused rather than
// duplicated: it already implements exactly the minimal ModuleService contract
// these tests need, and that package is explicitly out of scope to edit for
// this story — building its existing testdata, not modifying it, is not an
// edit. Built once in TestMain.
var echoModuleBin string

func TestMain(m *testing.M) {
	os.Exit(runBundleTestMain(m))
}

func runBundleTestMain(m *testing.M) int {
	dir, err := os.MkdirTemp("", "factory-bundle-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle_test: failed to create temp dir: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()

	suffix := ""
	if goruntime.GOOS == "windows" {
		suffix = ".exe"
	}
	echoModuleBin = filepath.Join(dir, "echo_module"+suffix)

	cmd := exec.Command("go", "build", "-o", echoModuleBin, "../modules/runtime/testdata/echo_module")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "bundle_test: failed to build echo_module: %s: %v\n", out, err)
		return 1
	}

	return m.Run()
}

// shortRuntimeDir mirrors runtime_test.go's shortBaseDir: a short temp dir so
// Unix socket paths built from it stay under the sun_path limit.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		return t.TempDir()
	}
	base, err := os.MkdirTemp("/tmp", "cfgms-factory-rt-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	return base
}

// osArch is the current platform's bundle.Binaries key.
func osArch() string { return goruntime.GOOS + "-" + goruntime.GOARCH }

// installEchoBundle writes a real, working steward-kind bundle named name
// under installRoot/name, backed by the compiled echo_module binary, signed
// with privKey (nil for an unsigned bundle) under publisher. Returns the
// installation root (installRoot/name).
func installEchoBundle(t *testing.T, installRoot, name, publisher string, privKey ed25519.PrivateKey) string {
	t.Helper()

	moduleRoot := filepath.Join(installRoot, name)
	require.NoError(t, os.MkdirAll(filepath.Join(moduleRoot, "binaries"), 0o755))

	binBytes, err := os.ReadFile(echoModuleBin)
	require.NoError(t, err)

	binName := "module"
	if goruntime.GOOS == "windows" {
		binName += ".exe"
	}
	destBin := filepath.Join(moduleRoot, "binaries", binName)
	require.NoError(t, os.WriteFile(destBin, binBytes, 0o755))
	require.NoError(t, os.Chmod(destBin, 0o755))

	meta := &featuremodules.ModuleMetadata{
		Name:      name,
		Version:   "0.1.0",
		Publisher: publisher,
		Executors: []string{"steward"},
	}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(moduleRoot, bundle.ManifestFileName), manifestBytes, 0o600))

	binRelPath := filepath.ToSlash(filepath.Join("binaries", binName))
	hash, err := bundle.ComputeContentHash(map[string][]byte{osArch(): binBytes}, manifestBytes)
	require.NoError(t, err)

	b := &bundle.Bundle{
		Manifest:    meta,
		Binaries:    map[string]string{osArch(): binRelPath},
		ContentHash: hash,
	}

	if privKey != nil {
		sig := ed25519.Sign(privKey, []byte(hash))
		b.Signatures = []bundle.BundleSignature{
			{Publisher: publisher, Algorithm: "ed25519", Signature: sig},
		}
	}

	require.NoError(t, bundle.WriteInstalledSidecar(b, moduleRoot))
	return moduleRoot
}

// newTestFactory returns a ModuleFactory with an empty registry, suitable for
// bundle-loading tests.
func newTestFactory() *ModuleFactory {
	return NewWithStewardID(discovery.ModuleRegistry{}, config.ErrorHandlingConfig{}, "test-steward", logging.NewNoopLogger())
}

// fakeConfigState is a minimal modules.ConfigState used only to drive Set's
// ToYAML call in these tests.
type fakeConfigState struct{}

func (c *fakeConfigState) AsMap() map[string]interface{} { return map[string]interface{}{} }
func (c *fakeConfigState) ToYAML() ([]byte, error)       { return []byte("key: value\n"), nil }
func (c *fakeConfigState) FromYAML([]byte) error         { return nil }
func (c *fakeConfigState) Validate() error               { return nil }
func (c *fakeConfigState) GetManagedFields() []string    { return nil }

// --- AC: installed-bundle discovery root is pinned per platform ---

func TestInstalledModulesRoots_PinnedToInstallerPaths(t *testing.T) {
	assert.Equal(t, `C:\Program Files\CFGMS\modules`, installedModulesWindowsRoot,
		"must match build/windows/cfgms-steward.wxs's ProgramFiles64Folder -> CFGMS -> modules nesting")
	assert.Equal(t, `/usr/local/lib/cfgms/modules`, installedModulesUnixRoot,
		"must match build/darwin/build-pkg.sh's MODULES_PAYLOAD_DIR")
}

func TestDefaultInstalledModulesRoot_UsesEnvOverride(t *testing.T) {
	t.Setenv(installedModulesBundleDirEnvVar, "/custom/override/path")
	assert.Equal(t, "/custom/override/path", defaultInstalledModulesRoot())
}

func TestDefaultInstalledModulesRoot_UsesPlatformDefaultWhenUnset(t *testing.T) {
	t.Setenv(installedModulesBundleDirEnvVar, "")
	got := defaultInstalledModulesRoot()
	if goruntime.GOOS == "windows" {
		assert.Equal(t, installedModulesWindowsRoot, got)
	} else {
		assert.Equal(t, installedModulesUnixRoot, got)
	}
}

// --- AC: binary path resolved to an absolute path under the installation root ---

func TestResolveBundleBinaryPaths_ProducesAbsolutePathUnderRoot(t *testing.T) {
	root := t.TempDir()
	b := &bundle.Bundle{
		Manifest:    &featuremodules.ModuleMetadata{Name: "widget", Version: "0.1.0", Publisher: "cfgms", Kind: "steward"},
		Binaries:    map[string]string{osArch(): "binaries/module"},
		ContentHash: "irrelevant-for-this-test",
	}

	resolved, err := resolveBundleBinaryPaths(b, root)
	require.NoError(t, err)

	gotPath := resolved.Binaries[osArch()]
	assert.True(t, filepath.IsAbs(gotPath), "resolved binary path must be absolute, got %q", gotPath)

	absRoot, err := filepath.Abs(root)
	require.NoError(t, err)
	rel, err := filepath.Rel(absRoot, gotPath)
	require.NoError(t, err)
	assert.False(t, rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)),
		"resolved path %q must stay under root %q", gotPath, root)

	// ComputeContentHash hashes binary content and manifest bytes, never the
	// path string, so resolving paths must not change ContentHash.
	assert.Equal(t, b.ContentHash, resolved.ContentHash)

	// b itself must be untouched: resolution operates on a copy.
	assert.Equal(t, "binaries/module", b.Binaries[osArch()])
}

// --- AC: bundle branch loads an installed bundle when no built-in matches ---

func TestLoadModule_BundleBranch_LoadsInstalledBundle_WhenNoBuiltinMatches(t *testing.T) {
	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "cfgms", nil)
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	f := newTestFactory()
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)
	t.Cleanup(func() { f.UnloadAllModules() })

	instance, err := f.LoadModule("widget")
	require.NoError(t, err)
	require.NotNil(t, instance)

	_, isBundleClient := instance.(*adapter.Client)
	assert.True(t, isBundleClient, "a bundle-loaded module must be wrapped in adapter.Client")

	f.mu.RLock()
	_, tracked := f.bundleHandles["widget"]
	f.mu.RUnlock()
	assert.True(t, tracked, "a started bundle handle must be tracked for shutdown")

	// Cached: a second LoadModule call must return the same instance, not start
	// a second process.
	again, err := f.LoadModule("widget")
	require.NoError(t, err)
	assert.Same(t, instance, again)
}

// --- AC: a built-in still wins over a same-named installed bundle ---

func TestLoadModule_BuiltinWinsOverBundle_WhenBothExist(t *testing.T) {
	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "file", "cfgms", nil)
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	f := newTestFactory()
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)
	t.Cleanup(func() { f.UnloadAllModules() })

	instance, err := f.LoadModule("file")
	require.NoError(t, err)
	require.NotNil(t, instance)

	_, isBundleClient := instance.(*adapter.Client)
	assert.False(t, isBundleClient, "a built-in must win over a same-named installed bundle")

	f.mu.RLock()
	_, tracked := f.bundleHandles["file"]
	f.mu.RUnlock()
	assert.False(t, tracked, "no bundle process should have been started when the built-in wins")
}

// --- AC: no runtime configured / no bundle dir behaves exactly like today ---

func TestLoadModule_NoRuntimeConfigured_BehavesLikeToday(t *testing.T) {
	f := newTestFactory()

	_, err := f.LoadModule("totally-unknown-module")
	require.Error(t, err)
	assert.Equal(t, "module totally-unknown-module not found in registry and not a built-in module", err.Error())
}

func TestLoadModule_NoBundleDirectory_BehavesLikeToday(t *testing.T) {
	// A path that is guaranteed not to exist, regardless of what the
	// container's real platform default directory happens to contain.
	t.Setenv(installedModulesBundleDirEnvVar, filepath.Join(t.TempDir(), "does-not-exist"))

	f := newTestFactory()
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)

	_, err := f.LoadModule("totally-unknown-module")
	require.Error(t, err)
	assert.Equal(t, "module totally-unknown-module not found in registry and not a built-in module", err.Error())
}

// --- AC: publisher-trust enforcement is active; no process is spawned on rejection ---

func TestLoadModule_PublisherTrustEnforced_NoProcessSpawned(t *testing.T) {
	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	installRoot := t.TempDir()
	moduleRoot := filepath.Join(installRoot, "widget")
	require.NoError(t, os.MkdirAll(moduleRoot, 0o755))

	meta := &featuremodules.ModuleMetadata{
		Name:      "widget",
		Version:   "0.1.0",
		Publisher: "untrusted-vendor",
		Executors: []string{"steward"},
	}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(moduleRoot, bundle.ManifestFileName), manifestBytes, 0o600))

	// The "binary" is deliberately non-executable junk content, not the real
	// echo_module binary: DiscoverInstalled/ReadInstalled verify installed
	// content against ContentHash (VerifyInstalledContent), so a file must
	// exist at the recorded relative path for discovery to succeed at all. If
	// trust verification were bypassed and the runtime attempted to fork/exec
	// this file anyway, it would fail with an exec-format error rather than a
	// trust error — making an accidental spawn attempt detectable even though
	// no OS process list is inspected directly.
	binContent := []byte("not-a-real-binary")
	binRelPath := filepath.Join("binaries", "module")
	require.NoError(t, os.MkdirAll(filepath.Join(moduleRoot, "binaries"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(moduleRoot, binRelPath), binContent, 0o644))

	hash, err := bundle.ComputeContentHash(map[string][]byte{osArch(): binContent}, manifestBytes)
	require.NoError(t, err)

	sig := ed25519.Sign(unknownPriv, []byte(hash))
	b := &bundle.Bundle{
		Manifest:    meta,
		Binaries:    map[string]string{osArch(): filepath.ToSlash(binRelPath)},
		ContentHash: hash,
		Signatures: []bundle.BundleSignature{
			{Publisher: "untrusted-vendor", Algorithm: "ed25519", Signature: sig},
		},
	}
	require.NoError(t, bundle.WriteInstalledSidecar(b, moduleRoot))

	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	f := newTestFactory()
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeStrict, nil)

	_, err = f.LoadModule("widget")
	require.Error(t, err)
	assert.ErrorIs(t, err, pkgtrust.ErrPublisherNotTrusted,
		"strict mode must refuse an untrusted publisher before any fork/exec is attempted")
}

// --- AC: configured trust mode reaches ModuleRuntime.Start, never hardcoded ---

// testEnforcerRuntime returns a ModuleRuntime whose trust enforcer treats
// cfgmsPub as the baked-in CFGMS publisher identity, mirroring
// runtime_test.go's testEnforcerRuntimeWithKey.
func testEnforcerRuntime(t *testing.T, cfgmsPub ed25519.PublicKey) *moduleruntime.ModuleRuntime {
	t.Helper()
	return moduleruntime.NewModuleRuntimeWithEnforcer(
		shortRuntimeDir(t),
		stewardtrust.NewStewardTrustEnforcerWithIdentity(func() pkgtrust.PublisherIdentity {
			return pkgtrust.PublisherIdentity{
				Name:      "cfgms",
				PublicKey: []byte(cfgmsPub),
				Algorithm: "ed25519",
			}
		}),
	)
}

func TestLoadModule_TrustMode_StrictAcceptsCFGMSSignedBundle(t *testing.T) {
	cfgmsPub, cfgmsPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "cfgms", cfgmsPriv)
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	f := newTestFactory()
	f.SetModuleRuntime(testEnforcerRuntime(t, cfgmsPub), config.ModuleTrustModeStrict, nil)
	t.Cleanup(func() { f.UnloadAllModules() })

	instance, err := f.LoadModule("widget")
	require.NoError(t, err, "strict mode must accept a bundle signed by the configured CFGMS identity")
	assert.NotNil(t, instance)
}

func TestLoadModule_TrustMode_StrictRejectsUnsignedBundleThatControllerModeWouldAccept(t *testing.T) {
	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "cfgms", nil) // unsigned
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	cfgmsPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Same fixture, same enforcer identity: only the configured mode differs
	// between this test and the controller-mode test below. That isolates the
	// mode as the variable that changes the outcome, proving LoadModule forwards
	// the configured mode rather than always applying one behavior.
	fStrict := newTestFactory()
	fStrict.SetModuleRuntime(testEnforcerRuntime(t, cfgmsPub), config.ModuleTrustModeStrict, nil)

	_, err = fStrict.LoadModule("widget")
	require.Error(t, err, "strict mode must reject an unsigned bundle")

	fController := newTestFactory()
	fController.SetModuleRuntime(testEnforcerRuntime(t, cfgmsPub), config.ModuleTrustModeController, nil)
	t.Cleanup(func() { fController.UnloadAllModules() })

	instance, err := fController.LoadModule("widget")
	require.NoError(t, err, "controller mode must accept the same unsigned bundle strict mode rejected")
	assert.NotNil(t, instance)
}

// --- AC: runtime lifecycle tied to steward shutdown ---

func TestUnloadAllModules_StopsBundleModuleProcess(t *testing.T) {
	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "cfgms", nil)
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	f := newTestFactory()
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)

	instance, err := f.LoadModule("widget")
	require.NoError(t, err)

	// Confirm the module process is genuinely alive before shutdown.
	require.NoError(t, instance.Set(context.Background(), "res-1", &fakeConfigState{}))

	f.UnloadAllModules()

	f.mu.RLock()
	remaining := len(f.bundleHandles)
	f.mu.RUnlock()
	assert.Zero(t, remaining, "UnloadAllModules must forget every bundle handle")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = instance.Set(ctx, "res-1", &fakeConfigState{})
	require.Error(t, err, "the module process must not survive UnloadAllModules")
}

func TestUnloadModule_StopsSingleBundleModuleProcess(t *testing.T) {
	installRoot := t.TempDir()
	installEchoBundle(t, installRoot, "widget", "cfgms", nil)
	t.Setenv(installedModulesBundleDirEnvVar, installRoot)

	f := newTestFactory()
	rt := moduleruntime.NewModuleRuntime(shortRuntimeDir(t))
	f.SetModuleRuntime(rt, config.ModuleTrustModeBypass, nil)

	instance, err := f.LoadModule("widget")
	require.NoError(t, err)

	f.UnloadModule("widget")

	f.mu.RLock()
	_, tracked := f.bundleHandles["widget"]
	f.mu.RUnlock()
	assert.False(t, tracked)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = instance.Set(ctx, "res-1", &fakeConfigState{})
	require.Error(t, err, "the module process must not survive UnloadModule")
}

// --- AC: every ModuleFactory construction site in non-test code wires a runtime ---

// TestModuleFactoryConstructionSites_AllCallersSetModuleRuntime mechanically
// enumerates every non-test, non-comment call to factory.New or
// factory.NewWithStewardID in the repository and asserts that its enclosing
// top-level function also calls SetModuleRuntime. A fourth construction site
// added later without wiring a runtime fails this test instead of silently
// reintroducing a convergence path that can never load a bundle module.
func TestModuleFactoryConstructionSites_AllCallersSetModuleRuntime(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	require.NoError(t, err)

	sites := findModuleFactoryConstructionSites(t, repoRoot)
	require.NotEmpty(t, sites, "expected at least one non-test, non-comment ModuleFactory construction site")

	for _, s := range sites {
		s := s
		t.Run(fmt.Sprintf("%s:%d", filepath.Base(s.path), s.line), func(t *testing.T) {
			assertEnclosingFunctionSetsModuleRuntime(t, s.path, s.line)
		})
	}
}

type factorySite struct {
	path string
	line int
}

var moduleFactoryConstructionPattern = regexp.MustCompile(`factory\.New\(|factory\.NewWithStewardID`)

// findModuleFactoryConstructionSites walks repoRoot in-process and scans each
// non-test .go file's lines for a ModuleFactory construction call. It
// deliberately does not shell out to grep and parse "path:line:text" output:
// on Windows repoRoot begins with a drive letter (e.g. `D:\a\...`), which
// collides with grep's own colon-delimited output format and corrupts the
// parsed line number. Scanning in-process sidesteps that entirely and removes
// the dependency on a grep binary being present on the runner.
func findModuleFactoryConstructionSites(t *testing.T, repoRoot string) []factorySite {
	t.Helper()

	var sites []factorySite
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}

		for i, line := range strings.Split(string(data), "\n") {
			if !moduleFactoryConstructionPattern.MatchString(line) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue // doc-comment example, not a real call site
			}
			sites = append(sites, factorySite{path: path, line: i + 1})
		}
		return nil
	})
	require.NoError(t, err)

	return sites
}

// assertEnclosingFunctionSetsModuleRuntime finds the top-level Go function
// enclosing lineNo in path (by scanning for the nearest preceding
// column-0 "func " and the following column-0 "}") and asserts its body
// contains a call to SetModuleRuntime.
func assertEnclosingFunctionSetsModuleRuntime(t *testing.T, path string, lineNo int) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(string(data), "\n")

	start := -1
	for i := lineNo - 1; i >= 0 && i < len(lines); i-- {
		if strings.HasPrefix(lines[i], "func ") {
			start = i
			break
		}
	}
	require.GreaterOrEqualf(t, start, 0, "%s:%d: no enclosing top-level func found", path, lineNo)

	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" {
			end = i
			break
		}
	}

	body := strings.Join(lines[start:end], "\n")
	assert.Contains(t, body, ".SetModuleRuntime(",
		"%s:%d: this ModuleFactory construction site's enclosing function must call SetModuleRuntime "+
			"so this path can load installed bundle modules (Issue #4410)", path, lineNo)
}
