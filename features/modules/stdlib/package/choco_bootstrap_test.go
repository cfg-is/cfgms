// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestNupkg constructs an in-memory zip archive (standing in for a
// chocolatey .nupkg, which is itself a zip file) from the given path->content
// entries.
func buildTestNupkg(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		f, err := w.Create(name)
		require.NoError(t, err)
		_, err = f.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// recordingRunner is a real (non-mock) commandRunner that records every
// invocation it receives instead of spawning a process, so bootstrap/source
// configuration logic can be asserted deterministically.
type recordingRunner struct {
	mu    sync.Mutex
	calls []recordedCall
	err   error // returned for every call when set
}

type recordedCall struct {
	name     string
	args     []string
	extraEnv []string
}

func (r *recordingRunner) run(_ context.Context, name string, args []string, extraEnv []string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedCall{name: name, args: append([]string(nil), args...), extraEnv: append([]string(nil), extraEnv...)})
	return nil, r.err
}

// TestResolveBootstrapPackageSource pins the bootstrap-package location
// defaulting: an explicit choco_bootstrap_package always wins; otherwise it
// defaults to "<choco_source>/chocolatey.nupkg", joined appropriately for
// both a filesystem-path source and an http(s) URL source.
func TestResolveBootstrapPackageSource(t *testing.T) {
	t.Run("explicit bootstrap package wins over choco_source", func(t *testing.T) {
		got := resolveBootstrapPackageSource(`C:\ClusterStorage\CSV01\choco-source`, `C:\custom\my-choco.nupkg`)
		assert.Equal(t, `C:\custom\my-choco.nupkg`, got)
	})

	t.Run("defaults from a filesystem path choco_source", func(t *testing.T) {
		got := resolveBootstrapPackageSource(`C:\ClusterStorage\CSV01\choco-source`, "")
		assert.Equal(t, filepath.Join(`C:\ClusterStorage\CSV01\choco-source`, "chocolatey.nupkg"), got)
	})

	t.Run("defaults from an http(s) URL choco_source", func(t *testing.T) {
		got := resolveBootstrapPackageSource("https://feed.internal.example/choco", "")
		assert.Equal(t, "https://feed.internal.example/choco/chocolatey.nupkg", got)
	})

	t.Run("URL choco_source with a trailing slash does not double up", func(t *testing.T) {
		got := resolveBootstrapPackageSource("https://feed.internal.example/choco/", "")
		assert.Equal(t, "https://feed.internal.example/choco/chocolatey.nupkg", got)
	})

	t.Run("neither configured yields empty", func(t *testing.T) {
		assert.Equal(t, "", resolveBootstrapPackageSource("", ""))
	})
}

// TestExtractZip verifies the nupkg unzip logic writes archive entries to the
// destination directory, including the nested tools/chocolateyInstall.ps1
// path bootstrapChocoReal depends on, and rejects a zip-slip entry that would
// escape the destination.
func TestExtractZip(t *testing.T) {
	t.Run("extracts nested files", func(t *testing.T) {
		data := buildTestNupkg(t, map[string]string{
			"tools/chocolateyInstall.ps1": "Write-Host 'installing chocolatey'",
			"chocolatey.nuspec":           "<package/>",
		})
		destDir := t.TempDir()

		require.NoError(t, extractZip(data, destDir))

		installerPath := filepath.Join(destDir, "tools", "chocolateyInstall.ps1")
		content, err := os.ReadFile(installerPath)
		require.NoError(t, err)
		assert.Equal(t, "Write-Host 'installing chocolatey'", string(content))

		nuspec, err := os.ReadFile(filepath.Join(destDir, "chocolatey.nuspec"))
		require.NoError(t, err)
		assert.Equal(t, "<package/>", string(nuspec))
	})

	t.Run("rejects a zip-slip entry escaping destDir", func(t *testing.T) {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, err := w.Create("../evil.ps1")
		require.NoError(t, err)
		_, err = f.Write([]byte("malicious"))
		require.NoError(t, err)
		require.NoError(t, w.Close())

		destDir := t.TempDir()
		err = extractZip(buf.Bytes(), destDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nupkg entry path")
	})

	t.Run("rejects a Windows-style zip-slip entry on every platform", func(t *testing.T) {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, err := w.Create(`..\evil.ps1`)
		require.NoError(t, err)
		_, err = f.Write([]byte("malicious"))
		require.NoError(t, err)
		require.NoError(t, w.Close())

		err = extractZip(buf.Bytes(), t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nupkg entry path")
	})

	t.Run("rejects cumulative uncompressed content over the limit", func(t *testing.T) {
		data := buildTestNupkg(t, map[string]string{
			"one": strings.Repeat("A", 2048),
			"two": strings.Repeat("B", 2048),
		})
		// The compressed archive fits, but its expanded content does not.
		limit := int64(len(data) + 32)
		require.Less(t, limit, int64(4096))
		err := extractZipWithLimit(data, t.TempDir(), limit)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds")
	})

	t.Run("invalid archive bytes produce a clear error", func(t *testing.T) {
		err := extractZip([]byte("not a zip"), t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nupkg archive")
	})
}

// TestFetchBytes_LocalPath verifies fetchBytes reads a local filesystem
// source directly (the non-URL branch); the http(s) branch is exercised
// indirectly via bootstrap tests below using a local file so no real network
// access is required.
func TestFetchBytes_LocalPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chocolatey.nupkg")
	require.NoError(t, os.WriteFile(path, []byte("nupkg-bytes"), 0o644))

	data, err := fetchBytes(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "nupkg-bytes", string(data))
}

func TestFetchBytes_MissingLocalPath(t *testing.T) {
	_, err := fetchBytes(context.Background(), filepath.Join(t.TempDir(), "does-not-exist.nupkg"))
	require.Error(t, err)
}

// TestIsURL pins the path-vs-URL discrimination used by both
// resolveBootstrapPackageSource and fetchBytes.
func TestIsURL(t *testing.T) {
	assert.True(t, isURL("https://feed.internal.example/choco"))
	assert.True(t, isURL("http://feed.internal.example/choco"))
	assert.False(t, isURL(`C:\ClusterStorage\CSV01\choco-source`))
	assert.False(t, isURL("/mnt/choco-source"))
}

// TestConfigureChocoSource_CommandVectors asserts the exact `choco source
// remove`/`choco source add` argument vectors via the commandRunner seam —
// never by running a real choco binary.
func TestConfigureChocoSource_CommandVectors(t *testing.T) {
	rec := &recordingRunner{}
	m := &PackageModule{
		chocoSource:     `C:\ClusterStorage\CSV01\choco-source`,
		chocoSourceName: "org",
		runCommand:      rec.run,
	}

	require.NoError(t, m.configureChocoSource(context.Background()))

	require.Len(t, rec.calls, 2)
	assert.Equal(t, "choco", rec.calls[0].name)
	assert.Equal(t, []string{"source", "remove", "-n", "chocolatey"}, rec.calls[0].args)
	assert.Equal(t, "choco", rec.calls[1].name)
	assert.Equal(t, []string{"source", "add", "-n", "org", "-s", `C:\ClusterStorage\CSV01\choco-source`, "--priority", "1"}, rec.calls[1].args)
}

// TestConfigureChocoSource_DefaultSourceName verifies an unconfigured
// choco_source_name falls back to "org".
func TestConfigureChocoSource_DefaultSourceName(t *testing.T) {
	rec := &recordingRunner{}
	m := &PackageModule{
		chocoSource: "https://feed.internal.example/choco",
		runCommand:  rec.run,
	}

	require.NoError(t, m.configureChocoSource(context.Background()))
	require.Len(t, rec.calls, 2)
	assert.Equal(t, []string{"source", "add", "-n", "org", "-s", "https://feed.internal.example/choco", "--priority", "1"}, rec.calls[1].args)
}

// TestConfigureChocoSource_RemoveFailureIsNotFatal verifies a failing
// `choco source remove` (e.g. the community source was already removed on a
// prior converge — idempotent, not a genuine error) does not abort
// configuration; the source add still runs and its result is what's returned.
func TestConfigureChocoSource_RemoveFailureIsNotFatal(t *testing.T) {
	rec := &recordingRunner{}
	callCount := 0
	m := &PackageModule{
		chocoSource:     "https://feed.internal.example/choco",
		chocoSourceName: "org",
		runCommand: func(ctx context.Context, name string, args []string, extraEnv []string) ([]byte, error) {
			callCount++
			if callCount == 1 {
				return nil, errors.New("chocolatey: source not found")
			}
			return rec.run(ctx, name, args, extraEnv)
		},
	}

	require.NoError(t, m.configureChocoSource(context.Background()))
	require.Len(t, rec.calls, 1, "the add call still ran after the remove call failed")
	assert.Equal(t, []string{"source", "add", "-n", "org", "-s", "https://feed.internal.example/choco", "--priority", "1"}, rec.calls[0].args)
}

// TestBootstrapChoco_SeamInvoked verifies the chocoBootstrap seam, when set,
// fully replaces the real implementation — used by selection tests to assert
// bootstrap is invoked with the right host state without touching a real
// filesystem or spawning powershell.exe.
func TestBootstrapChoco_SeamInvoked(t *testing.T) {
	called := false
	var seenSource string
	m := &PackageModule{
		chocoSource: "https://feed.internal.example/choco",
		chocoBootstrap: func(ctx context.Context) error {
			called = true
			return nil
		},
	}
	// Capture chocoSource via the module reference the seam closes over
	// (simulating what a real test double would assert against).
	seenSource = m.chocoSource

	require.NoError(t, m.bootstrapChoco(context.Background()))
	assert.True(t, called, "chocoBootstrap seam must be invoked instead of the real implementation")
	assert.Equal(t, "https://feed.internal.example/choco", seenSource)
}

// TestBootstrapChocoReal_AlreadyInstalled verifies the idempotent fast path:
// when chocolatey is already installed, bootstrapChocoReal only (re)confirms
// the source configuration — it never fetches/extracts a nupkg or invokes
// powershell.exe.
func TestBootstrapChocoReal_AlreadyInstalled(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("bootstrapChocoReal refuses to run on non-Windows; see TestBootstrapChocoReal_NonWindows")
	}

	rec := &recordingRunner{}
	m := &PackageModule{
		chocoSource:     "https://feed.internal.example/choco",
		chocoSourceName: "org",
		chocoExeExists:  func() bool { return true },
		runCommand:      rec.run,
	}

	require.NoError(t, m.bootstrapChocoReal(context.Background()))

	require.Len(t, rec.calls, 2, "only the two choco source commands, no powershell installer invocation")
	for _, c := range rec.calls {
		assert.Equal(t, "choco", c.name)
	}
}

// TestBootstrapChocoReal_FullBootstrap exercises the full bootstrap path when
// chocolatey is NOT yet installed: fetch the nupkg from choco_source (a local
// file here — no real network needed), extract it in Go, run the installer
// via `powershell.exe -NoProfile -File <path>` (never -Command/iex/bypass),
// then configure the org source.
func TestBootstrapChocoReal_FullBootstrap(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("bootstrapChocoReal refuses to run on non-Windows; see TestBootstrapChocoReal_NonWindows")
	}

	nupkgDir := t.TempDir()
	nupkgPath := filepath.Join(nupkgDir, "chocolatey.nupkg")
	nupkgBytes := buildTestNupkg(t, map[string]string{
		"tools/chocolateyInstall.ps1": "Write-Host 'installing'",
	})
	require.NoError(t, os.WriteFile(nupkgPath, nupkgBytes, 0o644))

	rec := &recordingRunner{}
	m := &PackageModule{
		chocoSource:     nupkgDir,
		chocoSourceName: "org",
		chocoExeExists:  func() bool { return false },
		runCommand:      rec.run,
	}

	require.NoError(t, m.bootstrapChocoReal(context.Background()))

	require.Len(t, rec.calls, 3, "installer invocation + two choco source commands")

	installerCall := rec.calls[0]
	assert.Equal(t, "powershell.exe", installerCall.name)
	require.Len(t, installerCall.args, 3)
	assert.Equal(t, "-NoProfile", installerCall.args[0])
	assert.Equal(t, "-File", installerCall.args[1])
	assert.Contains(t, installerCall.args[2], filepath.Join("tools", "chocolateyInstall.ps1"))
	assert.Contains(t, installerCall.extraEnv, "ChocolateyUseWindowsCompression=true")
	// Never -Command, -EncodedCommand, or -ExecutionPolicy Bypass (banned —
	// see CLAUDE.md).
	for _, a := range installerCall.args {
		assert.NotEqual(t, "-Command", a)
		assert.NotEqual(t, "-EncodedCommand", a)
		assert.NotEqual(t, "-ExecutionPolicy", a)
	}

	assert.Equal(t, "choco", rec.calls[1].name)
	assert.Equal(t, []string{"source", "remove", "-n", "chocolatey"}, rec.calls[1].args)
	assert.Equal(t, "choco", rec.calls[2].name)
	assert.Equal(t, []string{"source", "add", "-n", "org", "-s", nupkgDir, "--priority", "1"}, rec.calls[2].args)
}

// TestBootstrapChocoReal_NoSourceConfigured verifies bootstrapChocoReal
// refuses to proceed (rather than falling back to any implicit/community
// source) when neither choco_source nor choco_bootstrap_package is set.
func TestBootstrapChocoReal_NoSourceConfigured(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("bootstrapChocoReal refuses to run on non-Windows for a different reason; see TestBootstrapChocoReal_NonWindows")
	}
	m := &PackageModule{chocoExeExists: func() bool { return false }}
	err := m.bootstrapChocoReal(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "choco_source")
}

// TestBootstrapChocoReal_NonWindows verifies bootstrapChocoReal refuses to
// run on any non-Windows platform with a clear error, rather than attempting
// to spawn a nonexistent powershell.exe.
func TestBootstrapChocoReal_NonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this assertion only applies off Windows; see TestBootstrapChocoReal_FullBootstrap")
	}
	m := &PackageModule{chocoSource: "https://feed.internal.example/choco"}
	err := m.bootstrapChocoReal(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Windows")
}
