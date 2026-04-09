//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// WindowsSoftwareCollector handles Windows-specific software collection using
// native Windows APIs (registry, SCM, process snapshots) instead of external
// commands for significantly improved performance.
type WindowsSoftwareCollector struct{}

// CollectOS gathers OS information using native registry reads.
// External calls are kept only for PowerShell version and .NET Core runtimes
// (no native Go API available) and run concurrently.
func (w *WindowsSoftwareCollector) CollectOS(ctx context.Context, attributes map[string]string) error {
	attributes["os"] = runtime.GOOS
	attributes["go_version"] = runtime.Version()
	attributes["runtime_version"] = runtime.Version()
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
	attributes["runtime_compiler"] = runtime.Compiler

	// Native: OS version from registry (sub-millisecond)
	w.collectOSVersion(attributes)

	// Native: .NET Framework versions from registry (sub-millisecond)
	w.collectDotNetVersions(attributes)

	// External calls (no native API) — run concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(2)
	go func() {
		defer wg.Done()
		if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"$PSVersionTable.PSVersion.ToString()"); err == nil {
			mu.Lock()
			attributes["powershell_version"] = strings.TrimSpace(output)
			mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		if output, err := runCommand(ctx, "dotnet", "--list-runtimes"); err == nil {
			mu.Lock()
			attributes["dotnet_core_runtimes"] = strings.TrimSpace(output)
			mu.Unlock()
		}
	}()
	wg.Wait()

	return nil
}

// CollectPackages gathers installed packages using native registry reads and
// concurrent external calls for third-party package managers.
func (w *WindowsSoftwareCollector) CollectPackages(ctx context.Context, attributes map[string]string) error {
	// Native: installed programs via registry (fast, <100ms)
	w.collectInstalledPrograms(attributes)

	// Native: system updates/hotfixes via CBS registry
	w.collectInstalledUpdates(attributes)

	// External package manager calls — run concurrently
	type externalCollector func(context.Context, map[string]string)
	collectors := []externalCollector{
		w.collectChocolateyPackages,
		w.collectWingetPackages,
		w.collectWindowsStoreApps,
	}

	// Opt-in: Windows Features via DISM (notoriously slow)
	if os.Getenv("CFGMS_DNA_COLLECT_DISM_FEATURES") != "" {
		collectors = append(collectors, w.collectWindowsFeatures)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, fn := range collectors {
		wg.Add(1)
		go func(collect externalCollector) {
			defer wg.Done()
			localAttrs := make(map[string]string)
			collect(ctx, localAttrs)
			mu.Lock()
			for k, v := range localAttrs {
				attributes[k] = v
			}
			mu.Unlock()
		}(fn)
	}
	wg.Wait()

	return nil
}

// CollectServices gathers service information using the native Service Control
// Manager API with wmic fallback, process count via snapshot, and startup
// programs from registry.
func (w *WindowsSoftwareCollector) CollectServices(ctx context.Context, attributes map[string]string) error {
	// Primary: native SCM API (requires service manager access — steward runs as SYSTEM)
	if err := w.collectServicesViaSCM(attributes); err != nil {
		// Fallback: wmic (works with limited access)
		if output, wmicErr := runCommand(ctx, "wmic", "service", "get",
			"Name,State,StartMode,ServiceType", "/format:csv"); wmicErr == nil {
			w.parseWMIServicesOutput(output, attributes)
		}
	}

	// Native: process count via snapshot
	attributes["running_process_count"] = fmt.Sprintf("%d", countProcesses())

	// Native: startup programs from Run/RunOnce registry keys
	w.collectStartupPrograms(attributes)

	return nil
}

// CollectProcesses gathers process information using CreateToolhelp32Snapshot
// and native token lookups for process owners.
func (w *WindowsSoftwareCollector) CollectProcesses(ctx context.Context, attributes map[string]string) error {
	attributes["current_pid"] = fmt.Sprintf("%d", os.Getpid())
	attributes["parent_pid"] = fmt.Sprintf("%d", os.Getppid())

	// Native: current user via os/user (no whoami process spawn)
	if u, err := user.Current(); err == nil {
		attributes["current_user"] = u.Username
	}

	attributes["goroutine_count"] = fmt.Sprintf("%d", runtime.NumGoroutine())

	// Native: process snapshot with owner lookups
	w.collectProcessSnapshot(attributes)

	return nil
}

// ---------- OS info helpers ----------

// collectOSVersion reads Windows version information directly from the registry.
// Replaces wmic os and PowerShell Get-CimInstance calls.
func (w *WindowsSoftwareCollector) collectOSVersion(attributes map[string]string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	if product, _, err := key.GetStringValue("ProductName"); err == nil {
		attributes["windows_caption"] = product
	}

	if build, _, err := key.GetStringValue("CurrentBuildNumber"); err == nil {
		attributes["windows_build_number"] = build
	}

	// Full version string (e.g., "10.0.19045")
	major, _, majorErr := key.GetIntegerValue("CurrentMajorVersionNumber")
	minor, _, minorErr := key.GetIntegerValue("CurrentMinorVersionNumber")
	buildStr, _, buildErr := key.GetStringValue("CurrentBuildNumber")
	if majorErr == nil && minorErr == nil && buildErr == nil {
		attributes["windows_version"] = fmt.Sprintf("%d.%d.%s", major, minor, buildStr)
	}

	// Service pack (empty on Windows 10+)
	if csd, _, err := key.GetStringValue("CSDVersion"); err == nil && csd != "" {
		attributes["windows_service_pack"] = csd
	} else {
		attributes["windows_service_pack"] = "0"
	}

	// Install date (stored as Unix timestamp DWORD)
	if installDate, _, err := key.GetIntegerValue("InstallDate"); err == nil && installDate > 0 {
		t := time.Unix(int64(installDate), 0)
		attributes["windows_install_date"] = t.Format("2006-01-02 15:04:05")
	}

	// OS architecture from processor environment registry
	envKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE)
	if err == nil {
		if arch, _, err := envKey.GetStringValue("PROCESSOR_ARCHITECTURE"); err == nil {
			switch arch {
			case "AMD64":
				attributes["windows_os_architecture"] = "64-bit"
			case "x86":
				attributes["windows_os_architecture"] = "32-bit"
			case "ARM64":
				attributes["windows_os_architecture"] = "ARM 64-bit"
			default:
				attributes["windows_os_architecture"] = arch
			}
		}
		envKey.Close()
	}

	// Last boot time derived from system uptime via kernel32.GetTickCount64
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	if getTickCount64.Find() == nil {
		ret, _, _ := getTickCount64.Call()
		uptimeMs := uint64(ret)
		bootTime := time.Now().Add(-time.Duration(uptimeMs) * time.Millisecond)
		attributes["windows_last_boot_time"] = bootTime.Format("2006-01-02 15:04:05")
	}
}

// collectDotNetVersions reads .NET Framework versions directly from the registry.
// Replaces the PowerShell Get-ChildItem HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP call.
func (w *WindowsSoftwareCollector) collectDotNetVersions(attributes map[string]string) {
	ndpPath := `SOFTWARE\Microsoft\NET Framework Setup\NDP`
	ndpKey, err := registry.OpenKey(registry.LOCAL_MACHINE, ndpPath, registry.READ)
	if err != nil {
		return
	}

	subkeys, err := ndpKey.ReadSubKeyNames(-1)
	ndpKey.Close()
	if err != nil {
		return
	}

	var versions []string
	for _, name := range subkeys {
		if !strings.HasPrefix(name, "v") {
			continue
		}

		subPath := ndpPath + `\` + name
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath, registry.READ)
		if err != nil {
			continue
		}

		// Try to read Version directly from this key (v2.x, v3.x)
		if ver, _, err := sk.GetStringValue("Version"); err == nil && ver != "" {
			versions = append(versions, name+" "+ver)
			sk.Close()
			continue
		}

		// Check Full/Client subkeys (v4+)
		childKeys, _ := sk.ReadSubKeyNames(-1)
		sk.Close()

		for _, child := range childKeys {
			if child != "Full" && child != "Client" {
				continue
			}
			childKey, err := registry.OpenKey(registry.LOCAL_MACHINE, subPath+`\`+child, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if ver, _, err := childKey.GetStringValue("Version"); err == nil && ver != "" {
				versions = append(versions, name+"/"+child+" "+ver)
			}
			childKey.Close()
		}
	}

	if len(versions) > 0 {
		attributes["dotnet_framework_versions"] = strings.Join(versions, "; ")
	}
}

// ---------- Package/update helpers ----------

// collectInstalledPrograms reads installed programs directly from the Uninstall
// registry keys (both 64-bit and WOW6432Node). Replaces the PowerShell registry scan.
func (w *WindowsSoftwareCollector) collectInstalledPrograms(attributes map[string]string) {
	paths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	var programs []string
	var programCount int

	for _, path := range paths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue
		}

		subkeys, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err != nil {
			continue
		}

		for _, subkey := range subkeys {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+subkey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			displayName, _, err := sk.GetStringValue("DisplayName")
			if err != nil || displayName == "" {
				sk.Close()
				continue
			}

			programCount++
			if len(programs) < 20 {
				programInfo := displayName
				if version, _, verr := sk.GetStringValue("DisplayVersion"); verr == nil && version != "" {
					programInfo += " " + version
				}
				programs = append(programs, programInfo)
			}
			sk.Close()
		}
	}

	attributes["installed_program_count"] = fmt.Sprintf("%d", programCount)
	if len(programs) > 0 {
		attributes["installed_programs_sample"] = strings.Join(programs, "; ")
	}
}

// collectInstalledUpdates reads hotfix/KB information from the CBS packages
// registry. Replaces wmic qfe.
func (w *WindowsSoftwareCollector) collectInstalledUpdates(attributes map[string]string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`,
		registry.READ)
	if err != nil {
		return
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	// Deduplicate KB numbers (multiple packages per KB)
	kbs := make(map[string]bool)
	for _, name := range subkeys {
		if !strings.HasPrefix(name, "Package_for_KB") {
			continue
		}
		parts := strings.SplitN(name, "~", 2)
		if len(parts) > 0 {
			kb := strings.TrimPrefix(parts[0], "Package_for_")
			kbs[kb] = true
		}
	}

	attributes["installed_update_count"] = fmt.Sprintf("%d", len(kbs))

	var updates []string
	for kb := range kbs {
		if len(updates) >= 10 {
			break
		}
		updates = append(updates, kb)
	}
	if len(updates) > 0 {
		attributes["installed_updates_sample"] = strings.Join(updates, "; ")
	}
}

// collectWindowsFeatures collects Windows optional features via DISM PowerShell.
// Gated behind CFGMS_DNA_COLLECT_DISM_FEATURES env var because
// Get-WindowsOptionalFeature is notoriously slow.
func (w *WindowsSoftwareCollector) collectWindowsFeatures(ctx context.Context, attributes map[string]string) {
	if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Select-Object FeatureName | ConvertTo-Csv -NoTypeInformation"); err == nil {
		lines := strings.Split(output, "\n")
		featureCount := len(lines) - 1 // -1 for header
		if featureCount > 0 {
			attributes["windows_features_enabled_count"] = fmt.Sprintf("%d", featureCount)

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

// collectChocolateyPackages collects Chocolatey packages if available.
// Kept as external call — chocolatey is a third-party package manager.
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
			if packageCount <= 10 {
				packages = append(packages, line)
			}
		}

		if packageCount > 0 {
			attributes["chocolatey_package_count"] = fmt.Sprintf("%d", packageCount)
			attributes["chocolatey_packages_sample"] = strings.Join(packages, "; ")
		}
	}
}

// collectWingetPackages collects Winget packages if available.
// Kept as external call — winget is a third-party package manager.
func (w *WindowsSoftwareCollector) collectWingetPackages(ctx context.Context, attributes map[string]string) {
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

			if !headerFound {
				if strings.Contains(line, "Name") && strings.Contains(line, "Id") {
					headerFound = true
				}
				continue
			}

			if strings.Contains(line, "---") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 2 {
				packageCount++
				if packageCount <= 15 {
					packageInfo := fields[0]
					if len(fields) > 2 {
						for _, field := range fields {
							if strings.Contains(field, ".") && strings.ContainsAny(field, "0123456789") {
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

	if output, err := runCommand(ctx, "winget", "--version"); err == nil {
		version := strings.TrimSpace(output)
		if version != "" {
			attributes["winget_version"] = version
		}
	}

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

// collectWindowsStoreApps collects Windows Store apps.
// Kept as external call — requires PowerShell AppX cmdlets.
func (w *WindowsSoftwareCollector) collectWindowsStoreApps(ctx context.Context, attributes map[string]string) {
	if output, err := runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-AppxPackage | Select-Object Name,Version | ConvertTo-Csv -NoTypeInformation"); err == nil {
		lines := strings.Split(output, "\n")
		appCount := len(lines) - 1 // -1 for header
		if appCount > 0 {
			attributes["windows_store_app_count"] = fmt.Sprintf("%d", appCount)

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

// ---------- Service helpers ----------

// collectServicesViaSCM enumerates Windows services using the native Service
// Control Manager API. Replaces wmic service.
func (w *WindowsSoftwareCollector) collectServicesViaSCM(attributes map[string]string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	serviceNames, err := m.ListServices()
	if err != nil {
		return err
	}

	totalServices := len(serviceNames)
	var runningServices, stoppedServices int
	var autoStartServices, manualStartServices int

	for _, name := range serviceNames {
		s, err := m.OpenService(name)
		if err != nil {
			// Skip services we can't access (permission restricted)
			continue
		}

		if status, err := s.Query(); err == nil {
			switch status.State {
			case svc.Running:
				runningServices++
			case svc.Stopped:
				stoppedServices++
			}
		}

		if config, err := s.Config(); err == nil {
			switch config.StartType {
			case windows.SERVICE_AUTO_START:
				autoStartServices++
			case windows.SERVICE_DEMAND_START:
				manualStartServices++
			}
		}

		s.Close()
	}

	attributes["total_service_count"] = fmt.Sprintf("%d", totalServices)
	attributes["running_service_count"] = fmt.Sprintf("%d", runningServices)
	attributes["stopped_service_count"] = fmt.Sprintf("%d", stoppedServices)
	attributes["auto_start_service_count"] = fmt.Sprintf("%d", autoStartServices)
	attributes["manual_start_service_count"] = fmt.Sprintf("%d", manualStartServices)
	return nil
}

// parseWMIServicesOutput parses WMI services output (fallback for non-admin contexts).
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

			if len(fields) > 3 && fields[3] != "" {
				switch strings.ToLower(fields[3]) {
				case "running":
					runningServices++
				case "stopped":
					stoppedServices++
				}
			}

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

// collectStartupPrograms reads startup programs from Run/RunOnce registry keys.
// Replaces wmic startup.
func (w *WindowsSoftwareCollector) collectStartupPrograms(attributes map[string]string) {
	paths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}

	var startupPrograms []string
	var startupCount int

	for _, path := range paths {
		// Machine-level
		if key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE); err == nil {
			names, _ := key.ReadValueNames(-1)
			for _, name := range names {
				startupCount++
				if len(startupPrograms) < 10 {
					startupPrograms = append(startupPrograms, name)
				}
			}
			key.Close()
		}

		// User-level
		if key, err := registry.OpenKey(registry.CURRENT_USER, path, registry.QUERY_VALUE); err == nil {
			names, _ := key.ReadValueNames(-1)
			for _, name := range names {
				startupCount++
				if len(startupPrograms) < 10 {
					startupPrograms = append(startupPrograms, name)
				}
			}
			key.Close()
		}
	}

	attributes["startup_program_count"] = fmt.Sprintf("%d", startupCount)
	if len(startupPrograms) > 0 {
		attributes["startup_programs_sample"] = strings.Join(startupPrograms, "; ")
	}
}

// ---------- Process helpers ----------

// countProcesses returns the total number of running processes via a snapshot.
func countProcesses() int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	count := 0

	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		count++
		entry.Size = uint32(unsafe.Sizeof(entry))
		err = windows.Process32Next(snapshot, &entry)
	}
	return count
}

// collectProcessSnapshot gathers detailed process information using
// CreateToolhelp32Snapshot. Replaces tasklist and PowerShell Get-Process.
func (w *WindowsSoftwareCollector) collectProcessSnapshot(attributes map[string]string) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	processes := make(map[string]int)
	users := make(map[string]bool)
	sidCache := make(map[string]string)
	var totalCount int

	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		totalCount++
		name := windows.UTF16ToString(entry.ExeFile[:])
		processes[name]++

		if owner := lookupProcessOwner(entry.ProcessID, sidCache); owner != "" {
			users[owner] = true
		}

		entry.Size = uint32(unsafe.Sizeof(entry))
		err = windows.Process32Next(snapshot, &entry)
	}

	attributes["total_process_count"] = fmt.Sprintf("%d", totalCount)
	attributes["unique_process_names"] = fmt.Sprintf("%d", len(processes))
	attributes["unique_process_users"] = fmt.Sprintf("%d", len(users))

	// Top processes by instance count (descending)
	type processInfo struct {
		name  string
		count int
	}
	var topProcesses []processInfo
	for pName, count := range processes {
		topProcesses = append(topProcesses, processInfo{pName, count})
	}
	for i := 0; i < len(topProcesses)-1; i++ {
		for j := i + 1; j < len(topProcesses); j++ {
			if topProcesses[j].count > topProcesses[i].count {
				topProcesses[i], topProcesses[j] = topProcesses[j], topProcesses[i]
			}
		}
	}

	var topNames []string
	for i := 0; i < 5 && i < len(topProcesses); i++ {
		topNames = append(topNames, fmt.Sprintf("%s(%d)", topProcesses[i].name, topProcesses[i].count))
	}
	if len(topNames) > 0 {
		attributes["top_processes"] = strings.Join(topNames, ", ")
	}
}

// lookupProcessOwner resolves the owner of a process by PID using token lookups.
// Results are cached by SID to avoid repeated domain controller queries.
func lookupProcessOwner(pid uint32, cache map[string]string) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return ""
	}

	sidStr := tokenUser.User.Sid.String()
	if cached, ok := cache[sidStr]; ok {
		return cached
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		cache[sidStr] = ""
		return ""
	}

	username := domain + `\` + account
	cache[sidStr] = username
	return username
}

// ---------- Utility ----------

// parseCSVLine handles basic CSV parsing with quoted fields.
// Needed for Windows Store apps output parsing.
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

	fields = append(fields, strings.TrimSpace(current.String()))

	return fields
}
