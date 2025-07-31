package dna

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// CollectOS gathers detailed operating system information on macOS
func (d *DarwinSoftwareCollector) CollectOS(attributes map[string]string) error {
	// Basic OS information
	attributes["os"] = runtime.GOOS
	attributes["go_version"] = runtime.Version()
	attributes["runtime_version"] = runtime.Version()
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
	attributes["runtime_compiler"] = runtime.Compiler
	
	// macOS-specific OS information
	if version, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		attributes["macos_version"] = strings.TrimSpace(string(version))
	}
	
	if build, err := exec.Command("sw_vers", "-buildVersion").Output(); err == nil {
		attributes["macos_build"] = strings.TrimSpace(string(build))
	}
	
	if name, err := exec.Command("sw_vers", "-productName").Output(); err == nil {
		attributes["macos_product_name"] = strings.TrimSpace(string(name))
	}
	
	// Kernel information
	if kernelVersion, err := exec.Command("uname", "-r").Output(); err == nil {
		attributes["kernel_version"] = strings.TrimSpace(string(kernelVersion))
	}
	
	if kernelName, err := exec.Command("uname", "-s").Output(); err == nil {
		attributes["kernel_name"] = strings.TrimSpace(string(kernelName))
	}
	
	// System uptime
	if uptime, err := exec.Command("uptime").Output(); err == nil {
		attributes["system_uptime"] = strings.TrimSpace(string(uptime))
	}
	
	return nil
}

// CollectPackages gathers installed packages/applications on macOS
func (d *DarwinSoftwareCollector) CollectPackages(attributes map[string]string) error {
	// Homebrew packages
	d.collectHomebrewPackages(attributes)
	
	// MacPorts packages (if available)
	d.collectMacPortsPackages(attributes)
	
	// Applications in /Applications
	d.collectApplications(attributes)
	
	// System frameworks and libraries
	d.collectSystemLibraries(attributes)
	
	return nil
}

// CollectServices gathers installed and running services on macOS
func (d *DarwinSoftwareCollector) CollectServices(attributes map[string]string) error {
	// LaunchDaemons (system services)
	d.collectLaunchDaemons(attributes)
	
	// LaunchAgents (user services)
	d.collectLaunchAgents(attributes)
	
	// Running processes count as a service indicator
	if output, err := exec.Command("ps", "aux").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		attributes["running_process_count"] = fmt.Sprintf("%d", len(lines)-1) // -1 for header
	}
	
	return nil
}

// CollectProcesses gathers information about running processes on macOS
func (d *DarwinSoftwareCollector) CollectProcesses(attributes map[string]string) error {
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
	
	// Process statistics
	if output, err := exec.Command("ps", "-eo", "pid,ppid,user,comm").Output(); err == nil {
		d.parseProcessStats(string(output), attributes)
	}
	
	return nil
}

// collectHomebrewPackages collects installed Homebrew packages
func (d *DarwinSoftwareCollector) collectHomebrewPackages(attributes map[string]string) {
	if output, err := exec.Command("brew", "list", "--formula").Output(); err == nil {
		packages := strings.Fields(string(output))
		attributes["homebrew_formula_count"] = fmt.Sprintf("%d", len(packages))
		
		// Store first 10 packages as example
		if len(packages) > 0 {
			count := len(packages)
			if count > 10 {
				count = 10
			}
			attributes["homebrew_formulas_sample"] = strings.Join(packages[:count], ",")
		}
	}
	
	if output, err := exec.Command("brew", "list", "--cask").Output(); err == nil {
		casks := strings.Fields(string(output))
		attributes["homebrew_cask_count"] = fmt.Sprintf("%d", len(casks))
		
		// Store first 10 casks as example
		if len(casks) > 0 {
			count := len(casks)
			if count > 10 {
				count = 10
			}
			attributes["homebrew_casks_sample"] = strings.Join(casks[:count], ",")
		}
	}
}

// collectMacPortsPackages collects installed MacPorts packages
func (d *DarwinSoftwareCollector) collectMacPortsPackages(attributes map[string]string) {
	if output, err := exec.Command("port", "installed").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var packageCount int
		for _, line := range lines {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "The following") {
				packageCount++
			}
		}
		if packageCount > 0 {
			attributes["macports_package_count"] = fmt.Sprintf("%d", packageCount)
		}
	}
}

// collectApplications collects applications in /Applications
func (d *DarwinSoftwareCollector) collectApplications(attributes map[string]string) {
	if output, err := exec.Command("find", "/Applications", "-name", "*.app", "-maxdepth", "2").Output(); err == nil {
		apps := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(apps) > 0 && apps[0] != "" {
			attributes["applications_count"] = fmt.Sprintf("%d", len(apps))
			
			// Store first 10 application names as sample
			var appNames []string
			for i, app := range apps {
				if i >= 10 {
					break
				}
				if app != "" {
					// Extract app name from path
					parts := strings.Split(app, "/")
					if len(parts) > 0 {
						appName := parts[len(parts)-1]
						appName = strings.TrimSuffix(appName, ".app")
						appNames = append(appNames, appName)
					}
				}
			}
			if len(appNames) > 0 {
				attributes["applications_sample"] = strings.Join(appNames, ",")
			}
		}
	}
}

// collectSystemLibraries collects information about system libraries
func (d *DarwinSoftwareCollector) collectSystemLibraries(attributes map[string]string) {
	// Count dylibs in /usr/lib
	if output, err := exec.Command("find", "/usr/lib", "-name", "*.dylib", "-type", "f").Output(); err == nil {
		libs := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(libs) > 0 && libs[0] != "" {
			attributes["system_dylib_count"] = fmt.Sprintf("%d", len(libs))
		}
	}
	
	// Count frameworks in /System/Library/Frameworks
	if output, err := exec.Command("find", "/System/Library/Frameworks", "-name", "*.framework", "-maxdepth", "1").Output(); err == nil {
		frameworks := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(frameworks) > 0 && frameworks[0] != "" {
			attributes["system_framework_count"] = fmt.Sprintf("%d", len(frameworks))
		}
	}
}

// collectLaunchDaemons collects system launch daemons
func (d *DarwinSoftwareCollector) collectLaunchDaemons(attributes map[string]string) {
	if output, err := exec.Command("find", "/System/Library/LaunchDaemons", "-name", "*.plist").Output(); err == nil {
		daemons := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(daemons) > 0 && daemons[0] != "" {
			attributes["system_launch_daemon_count"] = fmt.Sprintf("%d", len(daemons))
		}
	}
	
	if output, err := exec.Command("find", "/Library/LaunchDaemons", "-name", "*.plist").Output(); err == nil {
		daemons := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(daemons) > 0 && daemons[0] != "" {
			attributes["user_launch_daemon_count"] = fmt.Sprintf("%d", len(daemons))
		}
	}
}

// collectLaunchAgents collects user launch agents
func (d *DarwinSoftwareCollector) collectLaunchAgents(attributes map[string]string) {
	if output, err := exec.Command("find", "/System/Library/LaunchAgents", "-name", "*.plist").Output(); err == nil {
		agents := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(agents) > 0 && agents[0] != "" {
			attributes["system_launch_agent_count"] = fmt.Sprintf("%d", len(agents))
		}
	}
	
	if output, err := exec.Command("find", "/Library/LaunchAgents", "-name", "*.plist").Output(); err == nil {
		agents := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(agents) > 0 && agents[0] != "" {
			attributes["user_launch_agent_count"] = fmt.Sprintf("%d", len(agents))
		}
	}
}

// parseProcessStats parses ps output for process statistics
func (d *DarwinSoftwareCollector) parseProcessStats(psOutput string, attributes map[string]string) {
	lines := strings.Split(psOutput, "\n")
	if len(lines) <= 1 {
		return
	}
	
	// Skip header line
	processCount := len(lines) - 2 // -1 for header, -1 for empty last line
	if processCount > 0 {
		attributes["total_process_count"] = fmt.Sprintf("%d", processCount)
	}
	
	// Count unique users and commands
	users := make(map[string]bool)
	commands := make(map[string]bool)
	
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			user := fields[2]
			command := fields[3]
			
			users[user] = true
			commands[command] = true
		}
	}
	
	attributes["unique_process_users"] = fmt.Sprintf("%d", len(users))
	attributes["unique_process_commands"] = fmt.Sprintf("%d", len(commands))
}