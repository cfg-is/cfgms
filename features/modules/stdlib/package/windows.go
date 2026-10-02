// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// wingetFrameworkPatterns are the MSIX framework package directory globs
// winget.exe depends on (VCLibs, WinUI/Xaml). When winget is launched as
// LocalSystem or a service account, the loader cannot resolve these
// framework DLLs via the normal MSIX activation path, producing exit
// -1073741515 (0xC0000135 STATUS_DLL_NOT_FOUND). Proven fix (CFG-AB-02):
// prepend these directories to PATH before invoking winget.exe.
var wingetFrameworkPatterns = []string{
	"Microsoft.VCLibs.140.00.UWPDesktop_*_x64_*",
	"Microsoft.UI.Xaml.2.*_x64_*",
	"Microsoft.VCLibs.140.00_*_x64_*",
}

// wingetFrameworkDirs returns the framework package directories under
// %ProgramFiles%\WindowsApps matching wingetFrameworkPatterns. All matches
// are included — newest is not required since any present framework version
// satisfies the loader.
func wingetFrameworkDirs(programFiles string) []string {
	var dirs []string
	for _, pattern := range wingetFrameworkPatterns {
		matches, err := filepath.Glob(filepath.Join(programFiles, "WindowsApps", pattern))
		if err != nil {
			continue
		}
		dirs = append(dirs, matches...)
	}
	return dirs
}

// wingetAugmentedEnv returns os.Environ() with the winget framework
// dependency directories and the invoked binary's own directory prepended to
// PATH. Every winget.exe invocation (the resolveWingetFullPath probe and
// every wingetManager operation) uses this environment so the MSIX framework
// DLLs resolve regardless of execution context (declared, predictable
// behavior — a Microsoft-signed binary + declared framework paths — per the
// threat model).
func wingetAugmentedEnv(bin string) []string {
	env := os.Environ()

	var prepend []string
	if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
		prepend = append(prepend, wingetFrameworkDirs(programFiles)...)
	}
	if bin != "" {
		if dir := filepath.Dir(bin); dir != "." {
			prepend = append(prepend, dir)
		}
	}
	if len(prepend) == 0 {
		return env
	}

	sep := string(os.PathListSeparator)
	newPath := strings.Join(prepend, sep)

	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, e := range env {
		if len(e) >= 5 && strings.EqualFold(e[:5], "PATH=") {
			out = append(out, "PATH="+newPath+sep+e[5:])
			replaced = true
			continue
		}
		out = append(out, e)
	}
	if !replaced {
		out = append(out, "PATH="+newPath)
	}
	return out
}

// wingetManager implements PackageManager for Windows Package Manager (winget)
// bin is the winget invocation path: the bare command name when the
// app-execution alias resolves on PATH (interactive users), or the fully
// qualified WindowsApps binary for SYSTEM/service contexts, which have no user
// profile and therefore no alias (#2337 — the steward itself runs as
// LocalSystem and needs the same resolution).
// env is the augmented PATH (WindowsApps framework dirs + bin dir) every
// invocation uses so the SYSTEM-context DLL resolution fix applies uniformly.
type wingetManager struct {
	bin string
	env []string
}

// newWingetManagerWithPath returns a wingetManager that invokes the given
// fully qualified winget.exe (see resolveWingetFullPath in factory.go).
func newWingetManagerWithPath(bin string) PackageManager {
	return &wingetManager{bin: bin, env: wingetAugmentedEnv(bin)}
}

func (m *wingetManager) Install(ctx context.Context, name, version string) error {
	// The steward runs as LocalSystem with no interactive user context, so keep
	// the install fully headless (`--silent --disable-interactivity`). Scope is
	// intentionally NOT pinned to machine: a hard `--scope machine` makes winget
	// reject any package that doesn't publish a machine-tagged installer
	// (0x8A15002B, "no applicable installer"). winget install as SYSTEM works well
	// for MSI/EXE-installer packages (verified live: 7zip.7zip installs cleanly as
	// nt authority\system). The one class it CANNOT install is MSIX/AppX — the
	// Local System account may not register AppX packages (0x80070057), a Windows
	// restriction, not a winget flaw. Packages whose winget manifest is MSIX-only
	// (e.g. Microsoft.PowerShell) therefore need a machine-scoped provider such as
	// chocolatey; that is what the per-resource provider allowlist is for.
	// #nosec G204 -- m.bin is a verified winget candidate; package name and
	// version are option-injection-safe by Config validation; no shell is used.
	cmd := exec.CommandContext(ctx, m.bin, "install",
		"--silent", "--disable-interactivity",
		"--accept-source-agreements", "--accept-package-agreements", name)
	if version != "latest" {
		cmd.Args = append(cmd.Args, "--version", version)
	}
	cmd.Env = m.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		out := string(output)
		// winget install on an already-installed package tries to upgrade it and
		// returns non-zero (0x8A15002B, UPDATE_NOT_APPLICABLE) when it is already
		// current. That is compliant, not a failure — normalise to success so a
		// present package does not report a perpetual install error.
		if strings.Contains(out, "No available upgrade") ||
			strings.Contains(out, "No newer package versions are available") ||
			strings.Contains(out, "already installed and current") {
			return nil
		}
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, out)
	}
	return nil
}

func (m *wingetManager) Remove(ctx context.Context, name string) error {
	// #nosec G204 -- m.bin is a verified winget candidate and name is validated
	// against leading options before this shell-free argument vector.
	cmd := exec.CommandContext(ctx, m.bin, "uninstall", "--accept-source-agreements", name)
	cmd.Env = m.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *wingetManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// Positional query matches by id/name/moniker (the same resolution Install
	// uses), so a package referenced by its winget Id (e.g. Microsoft.PowerShell)
	// resolves — unlike `--name`, which only matches the display-name column.
	// #nosec G204 -- m.bin is a verified winget candidate and name is validated
	// against leading options before this shell-free argument vector.
	cmd := exec.CommandContext(ctx, m.bin, "list", name, "--accept-source-agreements")
	cmd.Env = m.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		// winget exits non-zero (0x8a150014) with this message when nothing
		// installed matches the query. That is "absent" — the module maps
		// ErrPackageNotFound to state: absent and installs — not a query failure.
		if strings.Contains(string(output), "No installed package found") {
			return "", ErrPackageNotFound
		}
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}

	// winget prints a table (Name  Id  Version  [Available]  Source). The query
	// matches the Id column; the Version is the field immediately after it.
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if strings.EqualFold(f, name) && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
	}

	// Exited 0 but no row's Id matched the query exactly — treat as not installed
	// so the module reconciles by installing rather than erroring out.
	return "", ErrPackageNotFound
}

func (m *wingetManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	// #nosec G204 -- m.bin is a verified winget candidate and every argument is
	// a fixed literal; no caller-controlled command or shell is involved.
	cmd := exec.CommandContext(ctx, m.bin, "list", "--accept-source-agreements")
	cmd.Env = m.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "Name") || strings.HasPrefix(line, "---") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			result[parts[0]] = parts[1]
		}
	}

	return result, nil
}

func (m *wingetManager) Name() string {
	return "winget"
}

func (m *wingetManager) IsValidManager(name string) bool {
	return name == "winget"
}

// chocolateyManager implements PackageManager for Chocolatey.
// sourceName, when set, is passed as `--source <sourceName>` on every
// operation so packages are resolved only against the configured org source
// (`choco source add -n <sourceName> ...` — see PackageModule.bootstrapChoco
// / configureChocoSource), never the community feed. Empty sourceName is the
// legacy/unconfigured shape (newChocolateyManager), retained for the case
// where chocolatey was pre-installed and pre-configured outside CFGMS.
type chocolateyManager struct {
	sourceName string
}

func newChocolateyManager() PackageManager {
	return &chocolateyManager{}
}

// newChocolateyManagerWithSource returns a chocolateyManager that passes
// `--source <sourceName>` on every operation, restricting package resolution
// to the configured org source.
func newChocolateyManagerWithSource(sourceName string) PackageManager {
	return &chocolateyManager{sourceName: sourceName}
}

// sourceArgs returns the `--source <sourceName>` argument pair when a source
// name is configured, else nil.
func (m *chocolateyManager) sourceArgs() []string {
	if m.sourceName == "" {
		return nil
	}
	return []string{"--source", m.sourceName}
}

func (m *chocolateyManager) Install(ctx context.Context, name, version string) error {
	args := append([]string{"install", "-y", "--no-progress", name}, m.sourceArgs()...)
	if version != "latest" {
		args = append(args, "--version", version)
	}
	// #nosec G204 -- executable is fixed, no shell is used, and package,
	// version, and configured source name are validated before this call.
	cmd := exec.CommandContext(ctx, "choco", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *chocolateyManager) Remove(ctx context.Context, name string) error {
	args := append([]string{"uninstall", "-y", name}, m.sourceArgs()...)
	// #nosec G204 -- executable is fixed, no shell is used, and the package
	// name is validated against option injection before this call.
	cmd := exec.CommandContext(ctx, "choco", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *chocolateyManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// Chocolatey 2.x removed --local-only ("Invalid argument --local-only");
	// `choco list` defaults to installed/local packages in 2.x. This is a query
	// of what is INSTALLED, so it must NOT carry --source: `choco list --source`
	// searches the feed for AVAILABLE packages, which would report a not-installed
	// package as present.
	// #nosec G204 -- executable/options are fixed, name is validated against
	// leading-option injection, and no shell is used.
	cmd := exec.CommandContext(ctx, "choco", "list", name, "--exact", "--limit-output")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}

	// --limit-output emits `name|version` per installed package (machine-readable).
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "|")
		if len(fields) >= 2 && strings.EqualFold(fields[0], name) {
			return fields[1], nil
		}
	}

	// Not present in the installed list → absent. The module maps ErrPackageNotFound
	// to state: absent and installs, rather than erroring out.
	return "", ErrPackageNotFound
}

func (m *chocolateyManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	// Installed query — no --source (see GetInstalledVersion).
	// #nosec G204 -- executable and complete argument vector are fixed literals.
	cmd := exec.CommandContext(ctx, "choco", "list")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "Chocolatey") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			result[parts[0]] = parts[1]
		}
	}

	return result, nil
}

func (m *chocolateyManager) GetVersion(ctx context.Context, name string) (string, error) {
	// Chocolatey 2.x removed --local-only; `choco list` defaults to installed/local.
	args := append([]string{"list", "--exact", name}, m.sourceArgs()...)
	// #nosec G204 -- executable is fixed, no shell is used, and package/source
	// inputs are validated before forming this argument vector.
	cmd := exec.CommandContext(ctx, "choco", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("choco list failed: %v, output: %s", err, string(output))
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	return "", fmt.Errorf("version not found in choco output")
}

func (m *chocolateyManager) IsInstalled(ctx context.Context, name string) (bool, error) {
	// Chocolatey 2.x removed --local-only; `choco list` defaults to installed/local.
	args := append([]string{"list", "--exact", name}, m.sourceArgs()...)
	// #nosec G204 -- executable is fixed, no shell is used, and package/source
	// inputs are validated before forming this argument vector.
	cmd := exec.CommandContext(ctx, "choco", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("choco list failed: %v, output: %s", err, string(output))
	}
	return strings.Contains(string(output), name), nil
}

func (m *chocolateyManager) Update(ctx context.Context, name string) error {
	args := append([]string{"upgrade", "-y", name}, m.sourceArgs()...)
	// #nosec G204 -- executable is fixed, no shell is used, and package/source
	// inputs are validated before forming this argument vector.
	cmd := exec.CommandContext(ctx, "choco", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("choco upgrade failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (m *chocolateyManager) Name() string {
	return "choco"
}

func (m *chocolateyManager) IsValidManager(name string) bool {
	return name == "choco"
}
