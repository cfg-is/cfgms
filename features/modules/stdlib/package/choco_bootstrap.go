// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// chocoExePath is the fixed install location chocolatey uses on Windows.
// bootstrapChoco checks this path for idempotency (skip a redundant install)
// and the chocolateyManager invokes "choco" on PATH, which the installer
// places here.
const chocoExePath = `C:\ProgramData\chocolatey\choco.exe`

// chocoDefaultBootstrapFile is the well-known nupkg filename under
// choco_source used to bootstrap chocolatey itself when choco_bootstrap_package
// isn't explicitly configured.
const chocoDefaultBootstrapFile = "chocolatey.nupkg"

// commandRunner abstracts external process execution so chocolatey
// bootstrap/source-configuration logic is unit-testable without spawning real
// processes. extraEnv, when non-empty, is appended to the current environment
// (not a full replacement) — used by the chocolateyInstall.ps1 invocation to
// set ChocolateyUseWindowsCompression=true without losing PATH etc.
type commandRunner func(ctx context.Context, name string, args []string, extraEnv []string) ([]byte, error)

// execCommandRunner is the production commandRunner, backed by os/exec.
func execCommandRunner(ctx context.Context, name string, args []string, extraEnv []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	return cmd.CombinedOutput()
}

// isURL reports whether s is an http(s) URL as opposed to a filesystem path.
func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// joinSourcePath joins a filename onto a choco_source that may be either an
// http(s) URL or a filesystem path, producing the same shape of result
// (URL-joined vs path-joined) as the source itself.
func joinSourcePath(base, file string) string {
	if isURL(base) {
		if u, err := url.Parse(base); err == nil {
			u.Path = strings.TrimSuffix(u.Path, "/") + "/" + file
			return u.String()
		}
		return strings.TrimSuffix(base, "/") + "/" + file
	}
	return filepath.Join(base, file)
}

// resolveBootstrapPackageSource determines the effective location of
// chocolatey.nupkg used to bootstrap chocolatey: the explicitly configured
// bootstrapPackage if set, else chocoSource joined with
// chocoDefaultBootstrapFile, else "" (bootstrap not configured — caller
// surfaces a clear error rather than falling back to the community feed).
func resolveBootstrapPackageSource(chocoSource, bootstrapPackage string) string {
	if bootstrapPackage != "" {
		return bootstrapPackage
	}
	if chocoSource == "" {
		return ""
	}
	return joinSourcePath(chocoSource, chocoDefaultBootstrapFile)
}

// fetchBytes returns the raw bytes of src, which may be a local filesystem
// path or an http(s) URL. This is the only OS/network interaction in package
// acquisition — everything downstream (extractZip) is pure.
func fetchBytes(ctx context.Context, src string) ([]byte, error) {
	if isURL(src) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap package URL %s: %w", src, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to download bootstrap package from %s: %w", src, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to download bootstrap package from %s: HTTP %d", src, resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap package from %s: %w", src, err)
	}
	return data, nil
}

// extractZip extracts the contents of a zip archive — a chocolatey .nupkg is
// itself a zip file — into destDir. Extracting in Go rather than shelling out
// means the resulting files carry no Mark-of-the-Web, so PowerShell's default
// RemoteSigned execution policy runs chocolateyInstall.ps1 without needing
// -ExecutionPolicy Bypass (banned — see CLAUDE.md).
func extractZip(data []byte, destDir string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("invalid nupkg archive: %w", err)
	}

	cleanDest := filepath.Clean(destDir)
	for _, f := range r.File {
		path := filepath.Join(destDir, f.Name)
		// Zip-slip guard: reject any entry that would escape destDir.
		if path != cleanDest && !strings.HasPrefix(path, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("invalid nupkg entry path %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", path, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", filepath.Dir(path), err)
		}
		if err := extractZipFile(f, path); err != nil {
			return fmt.Errorf("failed to extract %s: %w", f.Name, err)
		}
	}
	return nil
}

func extractZipFile(f *zip.File, destPath string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, rc); err != nil {
		_ = out.Close()
		return err
	}
	// Return the Close error so a failed flush of the extracted file surfaces
	// rather than being silently dropped by a deferred close.
	return out.Close()
}

// runner returns the commandRunner this module uses: the injected test seam
// when set, else execCommandRunner. Callers must hold m.mu.
func (m *PackageModule) runner() commandRunner {
	if m.runCommand != nil {
		return m.runCommand
	}
	return execCommandRunner
}

// chocoInstalled reports whether chocolatey is already installed: the
// injected test seam when set, else a real check for chocoExePath. Callers
// must hold m.mu.
func (m *PackageModule) chocoInstalled() bool {
	if m.chocoExeExists != nil {
		return m.chocoExeExists()
	}
	_, err := os.Stat(chocoExePath)
	return err == nil
}

// effectiveChocoSourceName returns the local source name chocolatey
// registers the org feed under: the configured chocoSourceName, else the
// built-in default "org". Callers must hold m.mu.
func (m *PackageModule) effectiveChocoSourceName() string {
	if m.chocoSourceName != "" {
		return m.chocoSourceName
	}
	return "org"
}

// configureChocoSource removes the default community source and adds the
// configured org source (idempotent — adding an existing name is fine; see
// `choco source add` semantics). Callers must hold m.mu.
func (m *PackageModule) configureChocoSource(ctx context.Context) error {
	sourceName := m.effectiveChocoSourceName()
	run := m.runner()

	if logger, ok := m.GetLogger(); ok {
		logger.Info("configuring chocolatey source", "source_name", sourceName, "source", m.chocoSource)
	}

	// Best-effort: remove the default community source. Idempotent across
	// repeated converges — if it was already removed on a prior run, choco
	// exits non-zero here, but the desired end state (no community source
	// configured) already holds, so that is not itself a bootstrap failure.
	if _, err := run(ctx, "choco", []string{"source", "remove", "-n", "chocolatey"}, nil); err != nil {
		if logger, ok := m.GetLogger(); ok {
			logger.Info("chocolatey community source already absent", "error", err.Error())
		}
	}

	if _, err := run(ctx, "choco", []string{"source", "add", "-n", sourceName, "-s", m.chocoSource, "--priority", "1"}, nil); err != nil {
		return fmt.Errorf("failed to configure chocolatey source %s: %w", sourceName, err)
	}
	return nil
}

// bootstrapChoco ensures chocolatey is installed and its source is configured
// to the org feed. It is idempotent — a fast no-op (source reconfirm only)
// when chocolatey is already present. Callers must hold m.mu.
//
// The injected chocoBootstrap seam, when set, entirely replaces this — tests
// use it to assert bootstrap was invoked (with the configured host state)
// without extracting a real nupkg or spawning powershell.exe.
func (m *PackageModule) bootstrapChoco(ctx context.Context) error {
	if m.chocoBootstrap != nil {
		return m.chocoBootstrap(ctx)
	}
	return m.bootstrapChocoReal(ctx)
}

// bootstrapChocoReal is the real bootstrap implementation: chocolatey is
// Windows-only software, so this refuses to run on any other platform. See
// CLAUDE.md's banned-patterns list — this uses ONLY `powershell.exe -NoProfile
// -File <path>` (never -Command/-EncodedCommand/-ExecutionPolicy Bypass/iex).
// Callers must hold m.mu.
func (m *PackageModule) bootstrapChocoReal(ctx context.Context) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("chocolatey bootstrap is only supported on Windows (GOOS=%s)", runtime.GOOS)
	}

	if m.chocoInstalled() {
		return m.configureChocoSource(ctx)
	}

	pkgSrc := resolveBootstrapPackageSource(m.chocoSource, m.chocoBootstrapPackage)
	if pkgSrc == "" {
		return fmt.Errorf("chocolatey bootstrap requires choco_source or choco_bootstrap_package to be configured")
	}

	if logger, ok := m.GetLogger(); ok {
		logger.Info("bootstrapping chocolatey", "bootstrap_package", pkgSrc)
	}

	data, err := fetchBytes(ctx, pkgSrc)
	if err != nil {
		return fmt.Errorf("failed to fetch chocolatey bootstrap package: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "cfgms-choco-bootstrap-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for chocolatey bootstrap: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := extractZip(data, tmpDir); err != nil {
		return fmt.Errorf("failed to extract chocolatey bootstrap package: %w", err)
	}

	installerPath := filepath.Join(tmpDir, "tools", "chocolateyInstall.ps1")
	run := m.runner()
	if _, err := run(ctx, "powershell.exe",
		[]string{"-NoProfile", "-File", installerPath},
		[]string{"ChocolateyUseWindowsCompression=true"},
	); err != nil {
		return fmt.Errorf("chocolatey installer failed: %w", err)
	}

	return m.configureChocoSource(ctx)
}
