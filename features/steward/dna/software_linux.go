//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const linuxSwCmdTimeout = 30 * time.Second

// CollectOS gathers detailed operating system information on Linux
func (l *LinuxSoftwareCollector) CollectOS(ctx context.Context, attributes map[string]string) error {
	// Basic OS information
	attributes["os"] = runtime.GOOS
	attributes["go_version"] = runtime.Version()
	attributes["runtime_version"] = runtime.Version()
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
	attributes["runtime_compiler"] = runtime.Compiler

	// Distribution information from /etc/os-release
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "cat", "/etc/os-release").Output(); err == nil {
		l.parseOSRelease(string(output), attributes)
	}
	cancel()

	// Alternative: LSB release information
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "lsb_release", "-a").Output(); err == nil {
		l.parseLSBRelease(string(output), attributes)
	}
	cancel2()

	// Kernel information
	cmdCtx3, cancel3 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx3, "uname", "-a").Output(); err == nil {
		attributes["kernel_info"] = strings.TrimSpace(string(output))
	}
	cancel3()

	cmdCtx4, cancel4 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx4, "uname", "-r").Output(); err == nil {
		attributes["kernel_version"] = strings.TrimSpace(string(output))
	}
	cancel4()

	cmdCtx5, cancel5 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx5, "uname", "-v").Output(); err == nil {
		attributes["kernel_build_info"] = strings.TrimSpace(string(output))
	}
	cancel5()

	// System information
	cmdCtx6, cancel6 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx6, "hostnamectl").Output(); err == nil {
		l.parseHostnamectl(string(output), attributes)
	}
	cancel6()

	// Uptime information
	cmdCtx7, cancel7 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx7, "uptime").Output(); err == nil {
		attributes["system_uptime"] = strings.TrimSpace(string(output))
	}
	cancel7()

	// Boot time
	cmdCtx8, cancel8 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx8, "who", "-b").Output(); err == nil {
		attributes["system_boot_time"] = strings.TrimSpace(string(output))
	}
	cancel8()

	return nil
}

// CollectPackages gathers installed packages/applications on Linux
func (l *LinuxSoftwareCollector) CollectPackages(ctx context.Context, attributes map[string]string) error {
	// Determine package manager and collect packages
	l.collectAPTPackages(ctx, attributes)
	l.collectYUMPackages(ctx, attributes)
	l.collectDNFPackages(ctx, attributes)
	l.collectPacmanPackages(ctx, attributes)
	l.collectZypperPackages(ctx, attributes)
	l.collectSnapPackages(ctx, attributes)
	l.collectFlatpakPackages(ctx, attributes)
	l.collectPipPackages(ctx, attributes)
	l.collectNPMPackages(ctx, attributes)

	return nil
}

// CollectServices gathers installed and running services on Linux
func (l *LinuxSoftwareCollector) CollectServices(ctx context.Context, attributes map[string]string) error {
	// Systemd services
	l.collectSystemdServices(ctx, attributes)

	// Init.d services (legacy)
	l.collectInitDServices(ctx, attributes)

	// Running processes count
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "ps", "aux").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		attributes["running_process_count"] = fmt.Sprintf("%d", len(lines)-1) // -1 for header
	}
	cancel()

	return nil
}

// CollectProcesses gathers information about running processes on Linux
func (l *LinuxSoftwareCollector) CollectProcesses(ctx context.Context, attributes map[string]string) error {
	// Basic process information
	attributes["current_pid"] = fmt.Sprintf("%d", os.Getpid())
	attributes["parent_pid"] = fmt.Sprintf("%d", os.Getppid())

	// User/group IDs
	if uid := os.Getuid(); uid >= 0 {
		attributes["current_uid"] = fmt.Sprintf("%d", uid)
	}

	if gid := os.Getgid(); gid >= 0 {
		attributes["current_gid"] = fmt.Sprintf("%d", gid)
	}

	// Current user
	if user := os.Getenv("USER"); user != "" {
		attributes["current_user"] = user
	}

	// Number of goroutines
	attributes["goroutine_count"] = fmt.Sprintf("%d", runtime.NumGoroutine())

	// Process statistics using ps
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx, "ps", "-eo", "pid,ppid,user,comm,state").Output(); err == nil {
		l.parseProcessStats(string(output), attributes)
	}
	cancel()

	// Top processes by CPU/memory
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	if output, err := exec.CommandContext(cmdCtx2, "ps", "-eo", "pid,comm,pcpu,pmem", "--sort=-pcpu").Output(); err == nil {
		l.parseTopProcesses(string(output), attributes)
	}
	cancel2()

	return nil
}

// parseOSRelease parses /etc/os-release file
func (l *LinuxSoftwareCollector) parseOSRelease(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")

		switch key {
		case "NAME":
			attributes["os_name"] = value
		case "VERSION":
			attributes["os_version"] = value
		case "ID":
			attributes["os_id"] = value
		case "ID_LIKE":
			attributes["os_id_like"] = value
		case "VERSION_ID":
			attributes["os_version_id"] = value
		case "VERSION_CODENAME":
			attributes["os_version_codename"] = value
		case "PRETTY_NAME":
			attributes["os_pretty_name"] = value
		case "HOME_URL":
			attributes["os_home_url"] = value
		case "SUPPORT_URL":
			attributes["os_support_url"] = value
		case "BUG_REPORT_URL":
			attributes["os_bug_report_url"] = value
		}
	}
}

// parseLSBRelease parses lsb_release output
func (l *LinuxSoftwareCollector) parseLSBRelease(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Distributor ID":
			attributes["lsb_distributor_id"] = value
		case "Description":
			attributes["lsb_description"] = value
		case "Release":
			attributes["lsb_release"] = value
		case "Codename":
			attributes["lsb_codename"] = value
		}
	}
}

// parseHostnamectl parses hostnamectl output
func (l *LinuxSoftwareCollector) parseHostnamectl(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Static hostname":
			attributes["static_hostname"] = value
		case "Icon name":
			attributes["icon_name"] = value
		case "Chassis":
			attributes["chassis"] = value
		case "Machine ID":
			attributes["machine_id"] = value
		case "Boot ID":
			attributes["boot_id"] = value
		case "Operating System":
			attributes["hostnamectl_os"] = value
		case "Kernel":
			attributes["hostnamectl_kernel"] = value
		case "Architecture":
			attributes["hostnamectl_arch"] = value
		}
	}
}

// collectAPTPackages collects APT packages (Debian/Ubuntu)
func (l *LinuxSoftwareCollector) collectAPTPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "dpkg", "--get-selections").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var installedCount int
		var packages []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "install" {
				installedCount++
				if installedCount <= 20 { // Store first 20 as sample
					packages = append(packages, fields[0])
				}
			}
		}

		if installedCount > 0 {
			attributes["apt_package_count"] = fmt.Sprintf("%d", installedCount)
			attributes["apt_packages_sample"] = strings.Join(packages, ", ")
		}
		return // dpkg succeeded; skip fallback
	}

	// Fallback: dpkg -l (only if dpkg --get-selections failed)
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel2()

	if output, err := exec.CommandContext(cmdCtx2, "dpkg", "-l").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var installedCount int

		for _, line := range lines {
			if strings.HasPrefix(line, "ii ") { // installed package
				installedCount++
			}
		}

		if installedCount > 0 {
			attributes["dpkg_installed_count"] = fmt.Sprintf("%d", installedCount)
		}
	}
}

// collectYUMPackages collects YUM packages (RHEL/CentOS)
func (l *LinuxSoftwareCollector) collectYUMPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "yum", "list", "installed").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var packageCount int
		var packages []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Loaded plugins") || strings.HasPrefix(line, "Installed Packages") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 3 {
				packageCount++
				if packageCount <= 20 { // Store first 20 as sample
					packages = append(packages, fields[0])
				}
			}
		}

		if packageCount > 0 {
			attributes["yum_package_count"] = fmt.Sprintf("%d", packageCount)
			attributes["yum_packages_sample"] = strings.Join(packages, ", ")
			return // yum succeeded; skip rpm fallback
		}
	}

	// Fallback: rpm -qa (only if yum failed)
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel2()

	if output, err := exec.CommandContext(cmdCtx2, "rpm", "-qa").Output(); err == nil {
		packages := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(packages) > 0 && packages[0] != "" {
			attributes["rpm_package_count"] = fmt.Sprintf("%d", len(packages))

			// Store first 20 as sample
			sampleSize := len(packages)
			if sampleSize > 20 {
				sampleSize = 20
			}
			attributes["rpm_packages_sample"] = strings.Join(packages[:sampleSize], ", ")
		}
	}
}

// collectDNFPackages collects DNF packages (newer Fedora/RHEL)
func (l *LinuxSoftwareCollector) collectDNFPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "dnf", "list", "installed").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var packageCount int

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "Installed Packages") {
				continue
			}

			if strings.Contains(line, "@") { // Typical dnf installed package format
				packageCount++
			}
		}

		if packageCount > 0 {
			attributes["dnf_package_count"] = fmt.Sprintf("%d", packageCount)
		}
	}
}

// collectPacmanPackages collects Pacman packages (Arch Linux)
func (l *LinuxSoftwareCollector) collectPacmanPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "pacman", "-Q").Output(); err == nil {
		packages := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(packages) > 0 && packages[0] != "" {
			attributes["pacman_package_count"] = fmt.Sprintf("%d", len(packages))

			// Store first 20 as sample
			sampleSize := len(packages)
			if sampleSize > 20 {
				sampleSize = 20
			}
			attributes["pacman_packages_sample"] = strings.Join(packages[:sampleSize], ", ")
		}
	}

	// AUR packages if yay is available
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel2()

	if output, err := exec.CommandContext(cmdCtx2, "yay", "-Qm").Output(); err == nil {
		aurPackages := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(aurPackages) > 0 && aurPackages[0] != "" {
			attributes["aur_package_count"] = fmt.Sprintf("%d", len(aurPackages))
		}
	}
}

// collectZypperPackages collects Zypper packages (openSUSE)
func (l *LinuxSoftwareCollector) collectZypperPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "zypper", "search", "--installed-only").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var packageCount int

		for _, line := range lines {
			if strings.HasPrefix(line, "i ") { // installed package
				packageCount++
			}
		}

		if packageCount > 0 {
			attributes["zypper_package_count"] = fmt.Sprintf("%d", packageCount)
		}
	}
}

// collectSnapPackages collects Snap packages
func (l *LinuxSoftwareCollector) collectSnapPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "snap", "list").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		snapCount := len(lines) - 1 // -1 for header
		if snapCount > 0 {
			attributes["snap_package_count"] = fmt.Sprintf("%d", snapCount)

			// Store first 10 snaps as sample
			var snaps []string
			for i := 1; i <= 10 && i < len(lines); i++ {
				fields := strings.Fields(lines[i])
				if len(fields) > 0 {
					snaps = append(snaps, fields[0])
				}
			}
			if len(snaps) > 0 {
				attributes["snap_packages_sample"] = strings.Join(snaps, ", ")
			}
		}
	}
}

// collectFlatpakPackages collects Flatpak packages
func (l *LinuxSoftwareCollector) collectFlatpakPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "flatpak", "list").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var flatpakCount int
		var flatpaks []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) > 0 {
				flatpakCount++
				if flatpakCount <= 10 { // Store first 10 as sample
					flatpaks = append(flatpaks, fields[0])
				}
			}
		}

		if flatpakCount > 0 {
			attributes["flatpak_package_count"] = fmt.Sprintf("%d", flatpakCount)
			attributes["flatpak_packages_sample"] = strings.Join(flatpaks, ", ")
		}
	}
}

// collectPipPackages collects Python pip packages
func (l *LinuxSoftwareCollector) collectPipPackages(ctx context.Context, attributes map[string]string) {
	// Python 3 pip
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "pip3", "list").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		pipCount := len(lines) - 2 // -2 for header lines
		if pipCount > 0 {
			attributes["pip3_package_count"] = fmt.Sprintf("%d", pipCount)
		}
		return // pip3 succeeded; skip pip2 fallback
	}

	// Python 2 pip (if available)
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel2()

	if output, err := exec.CommandContext(cmdCtx2, "pip", "list").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		pipCount := len(lines) - 2 // -2 for header lines
		if pipCount > 0 {
			attributes["pip_package_count"] = fmt.Sprintf("%d", pipCount)
		}
	}
}

// collectNPMPackages collects Node.js npm packages
func (l *LinuxSoftwareCollector) collectNPMPackages(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "npm", "list", "-g", "--depth=0").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var npmCount int

		for _, line := range lines {
			if strings.Contains(line, "├──") || strings.Contains(line, "└──") {
				npmCount++
			}
		}

		if npmCount > 0 {
			attributes["npm_global_package_count"] = fmt.Sprintf("%d", npmCount)
		}
	}
}

// collectSystemdServices collects systemd services
func (l *LinuxSoftwareCollector) collectSystemdServices(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "systemctl", "list-units", "--type=service", "--all").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var totalServices, activeServices, failedServices int

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasSuffix(line, ".service") {
				totalServices++

				if strings.Contains(line, " active ") {
					activeServices++
				} else if strings.Contains(line, " failed ") {
					failedServices++
				}
			}
		}

		attributes["systemd_total_services"] = fmt.Sprintf("%d", totalServices)
		attributes["systemd_active_services"] = fmt.Sprintf("%d", activeServices)
		attributes["systemd_failed_services"] = fmt.Sprintf("%d", failedServices)
	}

	// Enabled services
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel2()

	if output, err := exec.CommandContext(cmdCtx2, "systemctl", "list-unit-files", "--type=service", "--state=enabled").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var enabledServices int

		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) > 0 && strings.Contains(line, "enabled") && strings.HasSuffix(fields[0], ".service") {
				enabledServices++
			}
		}

		attributes["systemd_enabled_services"] = fmt.Sprintf("%d", enabledServices)
	}
}

// collectInitDServices collects init.d services (legacy)
func (l *LinuxSoftwareCollector) collectInitDServices(ctx context.Context, attributes map[string]string) {
	cmdCtx, cancel := context.WithTimeout(ctx, linuxSwCmdTimeout)
	defer cancel()

	if output, err := exec.CommandContext(cmdCtx, "ls", "/etc/init.d/").Output(); err == nil {
		services := strings.Fields(string(output))
		if len(services) > 0 {
			attributes["initd_service_count"] = fmt.Sprintf("%d", len(services))
		}
	}
}

// parseProcessStats parses ps output for process statistics
func (l *LinuxSoftwareCollector) parseProcessStats(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	if len(lines) <= 1 {
		return
	}

	processCount := len(lines) - 2 // -1 for header, -1 for empty last line
	if processCount > 0 {
		attributes["total_process_count"] = fmt.Sprintf("%d", processCount)
	}

	// Count unique users, commands, and states
	users := make(map[string]bool)
	commands := make(map[string]bool)
	states := make(map[string]int)

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 5 {
			user := fields[2]
			command := fields[3]
			state := fields[4]

			users[user] = true
			commands[command] = true
			states[state]++
		}
	}

	attributes["unique_process_users"] = fmt.Sprintf("%d", len(users))
	attributes["unique_process_commands"] = fmt.Sprintf("%d", len(commands))

	// Process states
	for state, count := range states {
		attributes["process_state_"+state] = fmt.Sprintf("%d", count)
	}
}

// parseTopProcesses parses top processes by CPU/memory
func (l *LinuxSoftwareCollector) parseTopProcesses(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var topProcesses []string

	for i := 1; i <= 10 && i < len(lines); i++ { // Skip header, get top 10
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 {
			processInfo := fmt.Sprintf("%s(CPU:%s%%,MEM:%s%%)", fields[1], fields[2], fields[3])
			topProcesses = append(topProcesses, processInfo)
		}
	}

	if len(topProcesses) > 0 {
		attributes["top_processes_by_cpu"] = strings.Join(topProcesses, ", ")
	}
}
