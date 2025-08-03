package dna

import (
	"fmt"
	"os"
	"runtime"
)

// SoftwareCollector defines the interface for platform-specific software inventory collection
type SoftwareCollector interface {
	// CollectOS gathers detailed operating system information
	CollectOS(attributes map[string]string) error
	
	// CollectPackages gathers installed packages/applications
	CollectPackages(attributes map[string]string) error
	
	// CollectServices gathers installed and running services
	CollectServices(attributes map[string]string) error
	
	// CollectProcesses gathers information about running processes
	CollectProcesses(attributes map[string]string) error
}

// NewSoftwareCollector creates a platform-specific software collector
func NewSoftwareCollector() SoftwareCollector {
	return newPlatformSoftwareCollector()
}

// GenericSoftwareCollector provides basic cross-platform software collection
// This is used as a fallback when platform-specific collectors are not available
type GenericSoftwareCollector struct{}

func (g *GenericSoftwareCollector) CollectOS(attributes map[string]string) error {
	// Basic OS information available on all platforms
	attributes["os"] = runtime.GOOS
	attributes["go_version"] = runtime.Version()
	attributes["runtime_version"] = runtime.Version()
	
	// Architecture information
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["runtime_os"] = runtime.GOOS
	attributes["runtime_compiler"] = runtime.Compiler
	
	return nil
}

func (g *GenericSoftwareCollector) CollectPackages(attributes map[string]string) error {
	// Generic package collection - limited without platform-specific APIs
	attributes["package_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSoftwareCollector) CollectServices(attributes map[string]string) error {
	// Generic service collection - limited without platform-specific APIs
	attributes["service_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericSoftwareCollector) CollectProcesses(attributes map[string]string) error {
	// Basic process information available on all platforms
	attributes["current_pid"] = fmt.Sprintf("%d", os.Getpid())
	attributes["parent_pid"] = fmt.Sprintf("%d", os.Getppid())
	
	// User/group IDs (Unix-like systems)  
	if uid := os.Getuid(); uid >= 0 {
		attributes["current_uid"] = fmt.Sprintf("%d", uid)
	}
	
	if gid := os.Getgid(); gid >= 0 {
		attributes["current_gid"] = fmt.Sprintf("%d", gid)
	}
	
	// Number of goroutines as a basic runtime metric
	attributes["goroutine_count"] = fmt.Sprintf("%d", runtime.NumGoroutine())
	
	return nil
}

// Platform-specific collector types (implementations in separate files)

// WindowsSoftwareCollector handles Windows-specific software collection
type WindowsSoftwareCollector struct{}

func (w *WindowsSoftwareCollector) CollectOS(attributes map[string]string) error {
	return (&GenericSoftwareCollector{}).CollectOS(attributes)
}

func (w *WindowsSoftwareCollector) CollectPackages(attributes map[string]string) error {
	return (&GenericSoftwareCollector{}).CollectPackages(attributes)
}

func (w *WindowsSoftwareCollector) CollectServices(attributes map[string]string) error {
	return (&GenericSoftwareCollector{}).CollectServices(attributes)
}

func (w *WindowsSoftwareCollector) CollectProcesses(attributes map[string]string) error {
	return (&GenericSoftwareCollector{}).CollectProcesses(attributes)
}

// LinuxSoftwareCollector handles Linux-specific software collection
type LinuxSoftwareCollector struct{}


// DarwinSoftwareCollector handles macOS-specific software collection
type DarwinSoftwareCollector struct{}

