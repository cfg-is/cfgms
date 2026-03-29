//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// WindowsSoftwareCollector handles Windows-specific software collection.
// Each method accepts a context to enforce per-command timeouts on WMI and PowerShell calls.
type WindowsSoftwareCollector struct{}

// CollectOS gathers detailed operating system information on Windows.
// wmic is attempted first; PowerShell is used only as a fallback.
func (w *WindowsSoftwareCollector) CollectOS(ctx context.Context, attributes map[string]string) error {
	// Basic OS information
	attributes["os"] = runtime.GOOS
	attributes["go_version"] = runtime.Version()
	attributes["runtime_version"] = runtime.Version()
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
	attributes["runtime_compiler"] = runtime.Compiler

	// Windows version — primary: wmic
	if output, err := runCommand(ctx, "wmic", "os", "get",
		"Caption,Version,BuildNumber,ServicePackMajorVersion,OSArchitecture", "/format:csv"); err == nil {
		w.parseWMIOSOutput(output, attributes)
	} else {
		// Fallback: PowerShell Get-CimInstance
		if psOutput, psErr := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime | ConvertTo-Csv -NoTypeInformation"); psErr == nil {
			w.parsePowerShellOSOutput(psOutput, attributes)
		}
	}

	// .NET Framework versions
	w.collectDotNetVersions(ctx, attributes)

	// PowerShell version
	if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"$PSVersionTable.PSVersion.ToString()"); err == nil {
		attributes["powershell_version"] = strings.TrimSpace(output)
	}

	return nil
}

// CollectPackages gathers installed packages/applications on Windows.
// Uses registry enumeration instead of Win32_Product to avoid MSI reconfiguration.
func (w *WindowsSoftwareCollector) CollectPackages(ctx context.Context, attributes map[string]string) error {
	// Installed programs via registry scan (fast — no MSI reconfiguration)
	w.collectInstalledPrograms(ctx, attributes)

	// Windows Features
	w.collectWindowsFeatures(ctx, attributes)

	// Chocolatey packages (if available)
	w.collectChocolateyPackages(ctx, attributes)

	// Winget packages (if available)
	w.collectWingetPackages(ctx, attributes)

	// Windows Store apps
	w.collectWindowsStoreApps(ctx, attributes)

	// System updates/hotfixes
	w.collectInstalledUpdates(ctx, attributes)

	return nil
}

// CollectServices gathers installed and running services on Windows.
func (w *WindowsSoftwareCollector) CollectServices(ctx context.Context, attributes map[string]string) error {
	// Windows services — primary: wmic
	if output, err := runCommand(ctx, "wmic", "service", "get",
		"Name,State,StartMode,ServiceType", "/format:csv"); err == nil {
		w.parseWMIServicesOutput(output, attributes)
	} else {
		// Fallback: PowerShell
		if psOutput, psErr := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-CimInstance -ClassName Win32_Service | Select-Object Name,State,StartMode,ServiceType | ConvertTo-Csv -NoTypeInformation"); psErr == nil {
			w.parseWMIServicesOutput(psOutput, attributes)
		}
	}

	// Running processes count
	if output, err := runCommand(ctx, "tasklist", "/fo", "csv"); err == nil {
		lines := strings.Split(output, "\n")
		attributes["running_process_count"] = fmt.Sprintf("%d", len(lines)-1) // -1 for header
	}

	// Startup programs
	w.collectStartupPrograms(ctx, attributes)

	return nil
}

// CollectProcesses gathers information about running processes on Windows.
func (w *WindowsSoftwareCollector) CollectProcesses(ctx context.Context, attributes map[string]string) error {
	// Basic process information
	attributes["current_pid"] = fmt.Sprintf("%d", os.Getpid())
	attributes["parent_pid"] = fmt.Sprintf("%d", os.Getppid())

	// Current user
	if user, err := runCommand(ctx, "whoami"); err == nil {
		attributes["current_user"] = strings.TrimSpace(user)
	}

	// Number of goroutines
	attributes["goroutine_count"] = fmt.Sprintf("%d", runtime.NumGoroutine())

	// Detailed process information using tasklist
	if output, err := runCommand(ctx, "tasklist", "/fo", "csv", "/v"); err == nil {
		w.parseTasklistOutput(output, attributes)
	}

	// Process statistics using PowerShell
	if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-Process | Group-Object ProcessName | Select-Object Count,Name | Sort-Object Count -Descending | Select-Object -First 10 | ConvertTo-Csv -NoTypeInformation"); err == nil {
		w.parsePowerShellProcessStatsOutput(output, attributes)
	}

	return nil
}

// parseWMIOSOutput parses WMI OS output
func (w *WindowsSoftwareCollector) parseWMIOSOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 6 {
			if fields[1] != "" {
				attributes["windows_build_number"] = fields[1]
			}
			if fields[2] != "" {
				attributes["windows_caption"] = fields[2]
			}
			if fields[3] != "" {
				attributes["windows_os_architecture"] = fields[3]
			}
			if fields[4] != "" {
				attributes["windows_service_pack"] = fields[4]
			}
			if fields[5] != "" {
				attributes["windows_version"] = fields[5]
			}
		}
	}
}

// parsePowerShellOSOutput parses PowerShell OS output
func (w *WindowsSoftwareCollector) parsePowerShellOSOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if i == 0 { // Skip header
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := w.parseCSVLine(line)
		if len(fields) >= 6 {
			if fields[0] != "" {
				attributes["windows_build_number_ps"] = fields[0]
			}
			if fields[1] != "" {
				attributes["windows_caption_ps"] = fields[1]
			}
			if fields[2] != "" {
				attributes["windows_install_date"] = fields[2]
			}
			if fields[3] != "" {
				attributes["windows_last_boot_time"] = fields[3]
			}
			if fields[4] != "" {
				attributes["windows_os_architecture_ps"] = fields[4]
			}
			if fields[5] != "" {
				attributes["windows_version_ps"] = fields[5]
			}
		}
		break // Only process first OS entry
	}
}

// collectDotNetVersions collects .NET Framework versions
func (w *WindowsSoftwareCollector) collectDotNetVersions(ctx context.Context, attributes map[string]string) {
	// .NET Framework versions via registry (using PowerShell)
	if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-ChildItem 'HKLM:SOFTWARE\\Microsoft\\NET Framework Setup\\NDP' -recurse | Get-ItemProperty -name Version,Release -EA 0 | Where { $_.PSChildName -match '^(?!S)\\p{L}'} | Select PSChildName, Version, Release"); err == nil {
		lines := strings.Split(output, "\n")
		var dotnetVersions []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "Version") {
				dotnetVersions = append(dotnetVersions, line)
			}
		}
		if len(dotnetVersions) > 0 {
			attributes["dotnet_framework_versions"] = strings.Join(dotnetVersions, "; ")
		}
	}

	// .NET Core/5+ versions
	if output, err := runCommand(ctx, "dotnet", "--list-runtimes"); err == nil {
		attributes["dotnet_core_runtimes"] = strings.TrimSpace(output)
	}
}

// collectInstalledPrograms collects installed programs via registry scan.
//
// This replaces the old wmic product get approach which used Win32_Product — a
// known anti-pattern that triggers MSI repair/reconfiguration for every installed
// product and takes 5-15 minutes on typical Windows systems.
//
// The registry scan reads directly from the Uninstall keys and completes in
// under 2 seconds.
func (w *WindowsSoftwareCollector) collectInstalledPrograms(ctx context.Context, attributes map[string]string) {
	// Read from both 64-bit and 32-bit uninstall registry hives
	output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-ItemProperty "+
			"'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"+
			"'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "+
			"2>$null "+
			"| Select-Object DisplayName,DisplayVersion,Publisher,InstallDate "+
			"| Where-Object { $_.DisplayName -ne $null -and $_.DisplayName -ne '' } "+
			"| ConvertTo-Csv -NoTypeInformation")
	if err != nil {
		return
	}

	lines := strings.Split(output, "\n")
	var programCount int
	var programs []string

	for i, line := range lines {
		if i == 0 { // Skip CSV header
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := w.parseCSVLine(line)
		if len(fields) >= 1 && fields[0] != "" {
			programCount++
			if programCount <= 20 { // Store first 20 as sample
				programInfo := fields[0] // DisplayName
				if len(fields) > 1 && fields[1] != "" {
					programInfo += " " + fields[1] // DisplayVersion
				}
				programs = append(programs, programInfo)
			}
		}
	}

	attributes["installed_program_count"] = fmt.Sprintf("%d", programCount)
	if len(programs) > 0 {
		attributes["installed_programs_sample"] = strings.Join(programs, "; ")
	}
}

// collectWindowsFeatures collects Windows features
func (w *WindowsSoftwareCollector) collectWindowsFeatures(ctx context.Context, attributes map[string]string) {
	if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Select-Object FeatureName | ConvertTo-Csv -NoTypeInformation"); err == nil {
		lines := strings.Split(output, "\n")
		featureCount := len(lines) - 1 // -1 for header
		if featureCount > 0 {
			attributes["windows_features_enabled_count"] = fmt.Sprintf("%d", featureCount)

			// Store first 10 features as sample
			var features []string
			for i := 1; i <= 10 && i < len(lines); i++ {
				feature := strings.Trim(strings.TrimSpace(lines[i]), "\"")
				if feature != "" {
					features = append(features, feature)
				}
			}
			if len(features) > 0 {
				attributes["windows_features_sample"] = strings.Join(features, ", ")
			}
		}
	}
}

// collectChocolateyPackages collects Chocolatey packages if available
func (w *WindowsSoftwareCollector) collectChocolateyPackages(ctx context.Context, attributes map[string]string) {
	if output, err := runCommand(ctx, "choco", "list", "--local-only"); err == nil {
		lines := strings.Split(output, "\n")
		var packageCount int
		var packages []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "packages installed") {
				continue
			}
			packageCount++
			if packageCount <= 10 { // Store first 10 as sample
				packages = append(packages, line)
			}
		}

		if packageCount > 0 {
			attributes["chocolatey_package_count"] = fmt.Sprintf("%d", packageCount)
			attributes["chocolatey_packages_sample"] = strings.Join(packages, "; ")
		}
	}
}

// collectWingetPackages collects Winget packages if available
func (w *WindowsSoftwareCollector) collectWingetPackages(ctx context.Context, attributes map[string]string) {
	// List installed packages
	if output, err := runCommand(ctx, "winget", "list"); err == nil {
		lines := strings.Split(output, "\n")
		var packageCount int
		var packages []string
		var headerFound bool

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Skip until we find the header line with "Name" and "Id"
			if !headerFound {
				if strings.Contains(line, "Name") && strings.Contains(line, "Id") {
					headerFound = true
				}
				continue
			}

			// Skip separator line (dashes)
			if strings.Contains(line, "---") {
				continue
			}

			// Parse package line
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				packageCount++
				if packageCount <= 15 { // Store first 15 as sample
					packageInfo := fields[0]
					if len(fields) > 2 {
						for _, field := range fields {
							if strings.Contains(field, ".") && (strings.ContainsAny(field, "0123456789")) {
								packageInfo += " " + field
								break
							}
						}
					}
					packages = append(packages, packageInfo)
				}
			}
		}

		if packageCount > 0 {
			attributes["winget_package_count"] = fmt.Sprintf("%d", packageCount)
			attributes["winget_packages_sample"] = strings.Join(packages, "; ")
		}
	}

	// Get winget version for diagnostics
	if output, err := runCommand(ctx, "winget", "--version"); err == nil {
		version := strings.TrimSpace(output)
		if version != "" {
			attributes["winget_version"] = version
		}
	}

	// Check for winget sources
	if output, err := runCommand(ctx, "winget", "source", "list"); err == nil {
		lines := strings.Split(output, "\n")
		var sourceCount int
		var sources []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "Name") || strings.Contains(line, "---") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 1 {
				sourceCount++
				sources = append(sources, fields[0])
			}
		}

		if sourceCount > 0 {
			attributes["winget_source_count"] = fmt.Sprintf("%d", sourceCount)
			attributes["winget_sources"] = strings.Join(sources, ", ")
		}
	}
}

// collectWindowsStoreApps collects Windows Store apps
func (w *WindowsSoftwareCollector) collectWindowsStoreApps(ctx context.Context, attributes map[string]string) {
	if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-AppxPackage | Select-Object Name,Version | ConvertTo-Csv -NoTypeInformation"); err == nil {
		lines := strings.Split(output, "\n")
		appCount := len(lines) - 1 // -1 for header
		if appCount > 0 {
			attributes["windows_store_app_count"] = fmt.Sprintf("%d", appCount)

			// Store first 10 apps as sample
			var apps []string
			for i := 1; i <= 10 && i < len(lines); i++ {
				fields := w.parseCSVLine(lines[i])
				if len(fields) >= 2 && fields[0] != "" {
					appInfo := fields[0]
					if fields[1] != "" {
						appInfo += " " + fields[1]
					}
					apps = append(apps, appInfo)
				}
			}
			if len(apps) > 0 {
				attributes["windows_store_apps_sample"] = strings.Join(apps, "; ")
			}
		}
	}
}

// collectInstalledUpdates collects system updates/hotfixes
func (w *WindowsSoftwareCollector) collectInstalledUpdates(ctx context.Context, attributes map[string]string) {
	if output, err := runCommand(ctx, "wmic", "qfe", "get",
		"HotFixID,InstalledOn,Description", "/format:csv"); err == nil {
		lines := strings.Split(output, "\n")
		var updateCount int
		var updates []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Node") {
				continue
			}

			fields := strings.Split(line, ",")
			if len(fields) >= 4 && fields[2] != "" { // HotFixID field
				updateCount++
				if updateCount <= 10 { // Store first 10 as sample
					updateInfo := fields[2]                 // HotFixID
					if len(fields) > 3 && fields[3] != "" { // InstalledOn
						updateInfo += " (" + fields[3] + ")"
					}
					updates = append(updates, updateInfo)
				}
			}
		}

		attributes["installed_update_count"] = fmt.Sprintf("%d", updateCount)
		if len(updates) > 0 {
			attributes["installed_updates_sample"] = strings.Join(updates, "; ")
		}
	}
}

// parseWMIServicesOutput parses WMI services output
func (w *WindowsSoftwareCollector) parseWMIServicesOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var totalServices, runningServices, stoppedServices int
	var autoStartServices, manualStartServices int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 5 {
			totalServices++

			// Service state
			if len(fields) > 3 && fields[3] != "" {
				switch strings.ToLower(fields[3]) {
				case "running":
					runningServices++
				case "stopped":
					stoppedServices++
				}
			}

			// Start mode
			if len(fields) > 2 && fields[2] != "" {
				switch strings.ToLower(fields[2]) {
				case "auto":
					autoStartServices++
				case "manual":
					manualStartServices++
				}
			}
		}
	}

	attributes["total_service_count"] = fmt.Sprintf("%d", totalServices)
	attributes["running_service_count"] = fmt.Sprintf("%d", runningServices)
	attributes["stopped_service_count"] = fmt.Sprintf("%d", stoppedServices)
	attributes["auto_start_service_count"] = fmt.Sprintf("%d", autoStartServices)
	attributes["manual_start_service_count"] = fmt.Sprintf("%d", manualStartServices)
}

// collectStartupPrograms collects startup programs
func (w *WindowsSoftwareCollector) collectStartupPrograms(ctx context.Context, attributes map[string]string) {
	if output, err := runCommand(ctx, "wmic", "startup", "get",
		"Name,Command,Location", "/format:csv"); err == nil {
		lines := strings.Split(output, "\n")
		var startupCount int
		var startupPrograms []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Node") {
				continue
			}

			fields := strings.Split(line, ",")
			if len(fields) >= 4 && fields[2] != "" { // Name field
				startupCount++
				if startupCount <= 10 { // Store first 10 as sample
					startupPrograms = append(startupPrograms, fields[2])
				}
			}
		}

		attributes["startup_program_count"] = fmt.Sprintf("%d", startupCount)
		if len(startupPrograms) > 0 {
			attributes["startup_programs_sample"] = strings.Join(startupPrograms, "; ")
		}
	}
}

// parseTasklistOutput parses tasklist output for process information
func (w *WindowsSoftwareCollector) parseTasklistOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	if len(lines) <= 1 {
		return
	}

	processCount := len(lines) - 1 // -1 for header
	attributes["total_process_count"] = fmt.Sprintf("%d", processCount)

	// Count unique process names and users
	processes := make(map[string]int)
	users := make(map[string]bool)

	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		fields := w.parseCSVLine(line)
		if len(fields) >= 8 {
			processName := fields[0]
			userName := fields[6]

			processes[processName]++
			users[userName] = true
		}
	}

	attributes["unique_process_names"] = fmt.Sprintf("%d", len(processes))
	attributes["unique_process_users"] = fmt.Sprintf("%d", len(users))

	// Find top processes by count
	type processInfo struct {
		name  string
		count int
	}

	var topProcesses []processInfo
	for name, count := range processes {
		topProcesses = append(topProcesses, processInfo{name, count})
	}

	// Simple sort by count (descending)
	for i := 0; i < len(topProcesses)-1; i++ {
		for j := i + 1; j < len(topProcesses); j++ {
			if topProcesses[j].count > topProcesses[i].count {
				topProcesses[i], topProcesses[j] = topProcesses[j], topProcesses[i]
			}
		}
	}

	// Store top 5 processes
	var topProcessNames []string
	for i := 0; i < 5 && i < len(topProcesses); i++ {
		topProcessNames = append(topProcessNames, fmt.Sprintf("%s(%d)", topProcesses[i].name, topProcesses[i].count))
	}
	if len(topProcessNames) > 0 {
		attributes["top_processes"] = strings.Join(topProcessNames, ", ")
	}
}

// parsePowerShellProcessStatsOutput parses PowerShell process statistics output
func (w *WindowsSoftwareCollector) parsePowerShellProcessStatsOutput(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var processStats []string

	for i := 1; i < len(lines) && i <= 6; i++ { // Skip header, get top 5
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		fields := w.parseCSVLine(line)
		if len(fields) >= 2 {
			processStats = append(processStats, fmt.Sprintf("%s(%s)", fields[1], fields[0]))
		}
	}

	if len(processStats) > 0 {
		attributes["top_processes_ps"] = strings.Join(processStats, ", ")
	}
}

// parseCSVLine handles basic CSV parsing with quoted fields
func (w *WindowsSoftwareCollector) parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, char := range line {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				fields = append(fields, strings.TrimSpace(current.String()))
				current.Reset()
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}

	// Add the last field
	fields = append(fields, strings.TrimSpace(current.String()))

	return fields
}
