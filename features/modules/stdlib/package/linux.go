// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// aptOutputIsNotFound reports whether dpkg-query output indicates the package
// is absent from the system (as opposed to a genuine execution error).
func aptOutputIsNotFound(output []byte) bool {
	return strings.Contains(string(output), "no packages found matching")
}

// rpmOutputIsNotFound reports whether rpm -q output indicates the package is
// not installed (as opposed to a genuine execution error).
func rpmOutputIsNotFound(output []byte) bool {
	return strings.Contains(string(output), "is not installed")
}

// pacmanOutputIsNotFound reports whether pacman -Q output indicates the
// package was not found (as opposed to a genuine execution error).
func pacmanOutputIsNotFound(output []byte) bool {
	return strings.Contains(string(output), "was not found") ||
		strings.Contains(string(output), "target not found")
}

// installCoordinate returns the package argument for an install command.
// A pinned version is joined to the name with sep as one argv element
// (apt: "name=ver", dnf/yum: "name-ver"); "latest" yields the bare name.
func installCoordinate(name, version, sep string) string {
	if version == "latest" {
		return name
	}
	return name + sep + version
}

// aptInstallArgs builds the apt-get argv for installing name at version.
// The coordinate follows "--" as a single element: "name" or "name=version".
// When downgrade is true, --allow-downgrades is added and no other --allow-*
// option: held packages and essential packages are never touched.
func aptInstallArgs(name, version string, downgrade bool) []string {
	args := []string{"install", "-y"}
	if downgrade {
		args = append(args, "--allow-downgrades")
	}
	return append(args, "--", installCoordinate(name, version, "="))
}

// aptSimulateArgs builds the apt-get argv for a dry run (-s) of the downgrade
// that aptInstallArgs(name, version, true) would perform.
func aptSimulateArgs(name, version string) []string {
	return []string{"install", "-s", "-y", "--allow-downgrades", "--", installCoordinate(name, version, "=")}
}

// dnfInstallArgs builds the dnf argv for installing name at version
// ("name" or "name-version", one element after "--"). When downgrade is true
// the verb is "downgrade", which dnf requires to replace a newer installed
// version.
func dnfInstallArgs(name, version string, downgrade bool) []string {
	return []string{rpmInstallVerb(downgrade), "-y", "--", installCoordinate(name, version, "-")}
}

// yumInstallArgs builds the yum argv for installing name at version
// ("name" or "name-version", one element after "--"). When downgrade is true
// the verb is "downgrade".
func yumInstallArgs(name, version string, downgrade bool) []string {
	return []string{rpmInstallVerb(downgrade), "-y", "--", installCoordinate(name, version, "-")}
}

func rpmInstallVerb(downgrade bool) string {
	if downgrade {
		return "downgrade"
	}
	return "install"
}

// downgradeNeeded reports whether declared is an exact version older than the
// installed one. "latest", an absent package (installedErr != nil), an equal
// or older installed version, and an unparseable version all return false,
// which keeps the plain install behaviour.
func downgradeNeeded(installed string, installedErr error, declared string,
	compare func(installed, declared string) (int, error)) bool {
	if declared == "latest" || installedErr != nil {
		return false
	}
	cmp, err := compare(installed, declared)
	return err == nil && cmp > 0
}

// isDowngrade queries the manager's installed version and applies
// downgradeNeeded. A failed query keeps the plain install behaviour.
func isDowngrade(ctx context.Context, mgr PackageManager, name, declared string,
	compare func(installed, declared string) (int, error)) bool {
	if declared == "latest" {
		return false
	}
	installed, err := mgr.GetInstalledVersion(ctx, name)
	return downgradeNeeded(installed, err, declared, compare)
}

// installRPM installs name at version with the fixed rpm-family executable exe
// (dnf or yum). Only %{VERSION} is compared to decide on the downgrade verb;
// the release is never compared.
func installRPM(ctx context.Context, mgr PackageManager, exe string,
	buildArgs func(name, version string, downgrade bool) []string, name, version string) error {
	downgrade := isDowngrade(ctx, mgr, name, version, compareRPMVersions)
	// #nosec G204 -- exe is the fixed "dnf" or "yum" literal from the calling
	// manager; the validated name-version coordinate follows "--" as one argv
	// element (install or downgrade verb), without shell interpretation.
	cmd := exec.CommandContext(ctx, exe, buildArgs(name, version, downgrade)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

// ErrDowngradeNeedsDependency is returned when an apt downgrade of the declared
// package would also change another package, or apt cannot resolve it alone.
var ErrDowngradeNeedsDependency = errors.New("downgrade requires a change to another package")

// checkAptDowngradeSimulation parses the output of an `apt-get -s` run and
// returns an error wrapping ErrDowngradeNeedsDependency when any Inst, Remv or
// Conf line names a package other than name.
func checkAptDowngradeSimulation(name, version, output string) error {
	var others []string
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Inst", "Remv", "Conf":
		default:
			continue
		}
		if fields[1] == name || seen[fields[1]] {
			continue
		}
		seen[fields[1]] = true
		others = append(others, fields[1])
	}
	if len(others) > 0 {
		return fmt.Errorf("apt: downgrading package %s to %s would also change %s: %w; "+
			"declare the dependency at a matching version",
			name, version, strings.Join(others, ", "), ErrDowngradeNeedsDependency)
	}
	return nil
}

// aptCommand builds an apt-get command that never blocks on a debconf prompt.
// DEBIAN_FRONTEND=noninteractive is set on this command only, on top of the
// module process environment, so the shared baseline stays unchanged.
func aptCommand(ctx context.Context, args ...string) *exec.Cmd {
	// #nosec G204 -- fixed apt-get executable; callers pass validated
	// coordinates after "--" as argv elements, with no shell.
	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return cmd
}

// aptManager implements PackageManager for APT (Debian/Ubuntu)
type aptManager struct{}

func newAptManager() PackageManager {
	return &aptManager{}
}

func (m *aptManager) Install(ctx context.Context, name, version string) error {
	downgrade := isDowngrade(ctx, m, name, version, compareDebianVersions)
	if downgrade {
		// Dry run first: apt must change only the declared package. A
		// lockstep dependency would need its own declared version.
		// #nosec G204 -- fixed apt-get executable; the validated name=version
		// coordinate follows "--" as one argv element, with no shell.
		sim := aptCommand(ctx, aptSimulateArgs(name, version)...)
		out, err := sim.CombinedOutput()
		if err != nil {
			return fmt.Errorf("apt: cannot downgrade package %s to %s; declare the dependency at a matching version: %w\nOutput: %s",
				name, version, err, string(out))
		}
		if err := checkAptDowngradeSimulation(name, version, string(out)); err != nil {
			return err
		}
	}
	// Name and version are validated before dispatch; "--" terminates options,
	// and name=version is one argv element passed without a shell.
	cmd := aptCommand(ctx, aptInstallArgs(name, version, downgrade)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *aptManager) Remove(ctx context.Context, name string) error {
	// Validated name follows "--" as one argv to fixed apt-get.
	cmd := aptCommand(ctx, "remove", "-y", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *aptManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// #nosec G204 -- validated name follows "--" as one argv to fixed dpkg-query.
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Version}", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if aptOutputIsNotFound(output) {
			return "", ErrPackageNotFound
		}
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func (m *aptManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *aptManager) Name() string {
	return "apt"
}

func (m *aptManager) IsValidManager(name string) bool {
	return name == "apt"
}

// dnfManager implements PackageManager for DNF (Fedora/RHEL 8+)
type dnfManager struct{}

func newDnfManager() PackageManager {
	return &dnfManager{}
}

func (m *dnfManager) Install(ctx context.Context, name, version string) error {
	return installRPM(ctx, m, "dnf", dnfInstallArgs, name, version)
}

func (m *dnfManager) Remove(ctx context.Context, name string) error {
	// #nosec G204 -- validated name follows "--" as one argv to fixed dnf.
	cmd := exec.CommandContext(ctx, "dnf", "remove", "-y", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *dnfManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// #nosec G204 -- validated name follows "--" as one argv to fixed rpm.
	cmd := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if rpmOutputIsNotFound(output) {
			return "", ErrPackageNotFound
		}
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func (m *dnfManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *dnfManager) Name() string {
	return "dnf"
}

func (m *dnfManager) IsValidManager(name string) bool {
	return name == "dnf"
}

// yumManager implements PackageManager for YUM (RHEL 7 and older)
type yumManager struct{}

func newYumManager() PackageManager {
	return &yumManager{}
}

func (m *yumManager) Install(ctx context.Context, name, version string) error {
	return installRPM(ctx, m, "yum", yumInstallArgs, name, version)
}

func (m *yumManager) Remove(ctx context.Context, name string) error {
	// #nosec G204 -- validated name follows "--" as one argv to fixed yum.
	cmd := exec.CommandContext(ctx, "yum", "remove", "-y", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *yumManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// #nosec G204 -- validated name follows "--" as one argv to fixed rpm.
	cmd := exec.CommandContext(ctx, "rpm", "-q", "--qf", "%{VERSION}", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if rpmOutputIsNotFound(output) {
			return "", ErrPackageNotFound
		}
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}
	return strings.TrimSpace(string(output)), nil
}

func (m *yumManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *yumManager) Name() string {
	return "yum"
}

func (m *yumManager) IsValidManager(name string) bool {
	return name == "yum"
}

// pacmanManager implements PackageManager for Pacman (Arch Linux)
type pacmanManager struct{}

func newPacmanManager() PackageManager {
	return &pacmanManager{}
}

func (m *pacmanManager) Install(ctx context.Context, name, version string) error {
	// pacman cannot install an arbitrary older version from a sync repo, so a
	// pin is rejected rather than silently installing a different version.
	if version != "latest" {
		return fmt.Errorf("pacman: %w: cannot install %s at version %q (declare version: latest)",
			ErrVersionPinUnsupported, name, version)
	}
	// #nosec G204 -- validated name follows "--" as one argv to the fixed
	// pacman executable without shell interpretation.
	cmd := exec.CommandContext(ctx, "pacman", "-S", "--noconfirm", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *pacmanManager) Remove(ctx context.Context, name string) error {
	// #nosec G204 -- validated name follows "--" as one argv to fixed pacman.
	cmd := exec.CommandContext(ctx, "pacman", "-R", "--noconfirm", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove package %s: %w\nOutput: %s", name, err, string(output))
	}
	return nil
}

func (m *pacmanManager) GetInstalledVersion(ctx context.Context, name string) (string, error) {
	// #nosec G204 -- validated name follows "--" as one argv to fixed pacman.
	cmd := exec.CommandContext(ctx, "pacman", "-Q", "--", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if pacmanOutputIsNotFound(output) {
			return "", ErrPackageNotFound
		}
		return "", fmt.Errorf("failed to get version for package %s: %w\nOutput: %s", name, err, string(output))
	}

	// Parse output like "package 1.2.3"
	parts := strings.Fields(string(output))
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid output format for package %s: %s", name, string(output))
	}

	return parts[1], nil
}

func (m *pacmanManager) ListInstalled(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "pacman", "-Q")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list installed packages: %w\nOutput: %s", err, string(output))
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}

	return result, nil
}

func (m *pacmanManager) Name() string {
	return "pacman"
}

func (m *pacmanManager) IsValidManager(name string) bool {
	return name == "pacman"
}
