// Package dna provides system DNA (system attributes) collection for stewards.
//
// DNA represents the digital fingerprint of a system, containing hardware,
// software, and configuration attributes that uniquely identify and describe
// the system. This information is used by the controller for configuration
// targeting and system management.
//
// Basic usage:
//
//	collector := dna.NewCollector(logger)
//	dna, err := collector.Collect()
//	if err != nil {
//		log.Fatal(err)
//	}
//	
//	fmt.Printf("System ID: %s\n", dna.Id)
//	fmt.Printf("OS: %s\n", dna.Attributes["os"])
//
package dna

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Collector collects system DNA (attributes) for identification and targeting.
//
// The collector gathers hardware, software, and network information to create
// a comprehensive system profile. This information is used by the controller
// for configuration targeting and system management.
type Collector struct {
	logger logging.Logger
}

// NewCollector creates a new DNA collector.
//
// The collector will gather system information using platform-specific methods
// and create a comprehensive DNA profile for the system.
func NewCollector(logger logging.Logger) *Collector {
	return &Collector{
		logger: logger,
	}
}

// Collect gathers the current system DNA (attributes).
//
// This method collects comprehensive system information including:
//   - Hardware: CPU, memory, architecture
//   - Software: OS, kernel, runtime version
//   - Network: Hostname, IP addresses, MAC addresses
//   - Environment: User, working directory, environment variables
//
// Returns a DNA structure with a unique system ID and all collected attributes.
// The system ID is generated from stable hardware identifiers.
func (c *Collector) Collect() (*commonpb.DNA, error) {
	c.logger.Debug("Collecting system DNA")

	attributes := make(map[string]string)

	// Collect basic system information
	c.collectBasicInfo(attributes)
	
	// Collect hardware information
	c.collectHardwareInfo(attributes)
	
	// Collect software information
	c.collectSoftwareInfo(attributes)
	
	// Collect network information
	c.collectNetworkInfo(attributes)
	
	// Collect environment information
	c.collectEnvironmentInfo(attributes)

	// Generate stable system ID from hardware characteristics
	systemID := c.generateSystemID(attributes)

	dna := &commonpb.DNA{
		Id:          systemID,
		Attributes:  attributes,
		LastUpdated: timestamppb.New(time.Now()),
	}

	c.logger.Info("System DNA collected", 
		"id", systemID,
		"attributes", len(attributes))

	return dna, nil
}

// collectBasicInfo collects basic system information.
func (c *Collector) collectBasicInfo(attributes map[string]string) {
	attributes["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	attributes["runtime_version"] = runtime.Version()
	attributes["runtime_os"] = runtime.GOOS
	attributes["runtime_arch"] = runtime.GOARCH
	attributes["num_cpu"] = fmt.Sprintf("%d", runtime.NumCPU())
	
	if hostname, err := os.Hostname(); err == nil {
		attributes["hostname"] = hostname
	}
	
	if wd, err := os.Getwd(); err == nil {
		attributes["working_directory"] = wd
	}
}

// collectHardwareInfo collects hardware-specific information.
func (c *Collector) collectHardwareInfo(attributes map[string]string) {
	// CPU information
	attributes["cpu_count"] = fmt.Sprintf("%d", runtime.NumCPU())
	
	// Memory information (basic runtime stats)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	attributes["memory_alloc"] = fmt.Sprintf("%d", m.Alloc)
	attributes["memory_sys"] = fmt.Sprintf("%d", m.Sys)
	
	// Architecture
	attributes["arch"] = runtime.GOARCH
	
	// TODO: Add more detailed hardware info using platform-specific methods
	// - CPU model, speed, features
	// - Total memory, disk space
	// - Hardware serial numbers
}

// collectSoftwareInfo collects software and OS information.
func (c *Collector) collectSoftwareInfo(attributes map[string]string) {
	attributes["os"] = runtime.GOOS
	attributes["go_version"] = runtime.Version()
	
	// Environment-based OS info
	if osName := os.Getenv("OS"); osName != "" {
		attributes["os_name"] = osName
	}
	
	// Process information
	attributes["pid"] = fmt.Sprintf("%d", os.Getpid())
	attributes["ppid"] = fmt.Sprintf("%d", os.Getppid())
	
	if uid := os.Getuid(); uid >= 0 {
		attributes["uid"] = fmt.Sprintf("%d", uid)
	}
	
	if gid := os.Getgid(); gid >= 0 {
		attributes["gid"] = fmt.Sprintf("%d", gid)
	}
	
	// TODO: Add more detailed software info
	// - Kernel version
	// - Installed packages
	// - Running services
}

// collectNetworkInfo collects network configuration information.
func (c *Collector) collectNetworkInfo(attributes map[string]string) {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		c.logger.Error("Failed to get network interfaces", "error", err)
		return
	}

	var ipAddresses []string
	var macAddresses []string

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Collect MAC address
		if iface.HardwareAddr != nil {
			macAddresses = append(macAddresses, iface.HardwareAddr.String())
		}

		// Get IP addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ipAddresses = append(ipAddresses, ipnet.IP.String())
				}
			}
		}
	}

	if len(ipAddresses) > 0 {
		attributes["ip_addresses"] = strings.Join(ipAddresses, ",")
		attributes["primary_ip"] = ipAddresses[0]
	}

	if len(macAddresses) > 0 {
		attributes["mac_addresses"] = strings.Join(macAddresses, ",")
		attributes["primary_mac"] = macAddresses[0]
	}

	// Network interface count
	attributes["network_interface_count"] = fmt.Sprintf("%d", len(interfaces))
}

// collectEnvironmentInfo collects environment and user information.
func (c *Collector) collectEnvironmentInfo(attributes map[string]string) {
	// User information
	if user := os.Getenv("USER"); user != "" {
		attributes["user"] = user
	}
	if home := os.Getenv("HOME"); home != "" {
		attributes["home_directory"] = home
	}
	
	// Path information
	if path := os.Getenv("PATH"); path != "" {
		// Store only the count to avoid exposing sensitive paths
		attributes["path_elements"] = fmt.Sprintf("%d", len(strings.Split(path, string(os.PathListSeparator))))
	}
	
	// Shell information
	if shell := os.Getenv("SHELL"); shell != "" {
		attributes["shell"] = shell
	}
	
	// Terminal information
	if term := os.Getenv("TERM"); term != "" {
		attributes["terminal"] = term
	}
	
	// Timezone
	if tz := os.Getenv("TZ"); tz != "" {
		attributes["timezone"] = tz
	} else {
		// Get timezone from system
		if zone, offset := time.Now().Zone(); zone != "" {
			attributes["timezone"] = zone
			attributes["timezone_offset"] = fmt.Sprintf("%d", offset)
		}
	}
}

// generateSystemID creates a stable system identifier from hardware characteristics.
//
// The system ID is generated from stable hardware identifiers like MAC addresses
// and hostname to ensure the same system gets the same ID across restarts.
func (c *Collector) generateSystemID(attributes map[string]string) string {
	// Use stable identifiers to generate system ID
	var identifiers []string
	
	// Primary MAC address (most stable)
	if mac := attributes["primary_mac"]; mac != "" {
		identifiers = append(identifiers, mac)
	}
	
	// Hostname (usually stable)
	if hostname := attributes["hostname"]; hostname != "" {
		identifiers = append(identifiers, hostname)
	}
	
	// CPU count and architecture (hardware characteristics)
	if cpuCount := attributes["cpu_count"]; cpuCount != "" {
		identifiers = append(identifiers, cpuCount)
	}
	if arch := attributes["arch"]; arch != "" {
		identifiers = append(identifiers, arch)
	}
	
	// If we have no stable identifiers, use runtime characteristics
	if len(identifiers) == 0 {
		identifiers = append(identifiers, 
			attributes["runtime_os"],
			attributes["runtime_arch"],
			fmt.Sprintf("%d", time.Now().Unix()/3600), // Change hourly as fallback
		)
	}
	
	// Generate SHA256 hash of identifiers
	data := strings.Join(identifiers, "|")
	hash := sha256.Sum256([]byte(data))
	
	// Return first 16 characters of hex encoding
	return fmt.Sprintf("%x", hash[:8])
}

// RefreshDNA collects fresh DNA information.
//
// This is a convenience method that calls Collect() to get fresh system information.
// It's useful for periodic DNA updates where some attributes may have changed.
func (c *Collector) RefreshDNA() (*commonpb.DNA, error) {
	return c.Collect()
}

// CompareDNA compares two DNA structures and returns true if they represent the same system.
//
// This method compares the system IDs and key hardware characteristics to determine
// if two DNA structures represent the same physical system.
func CompareDNA(dna1, dna2 *commonpb.DNA) bool {
	if dna1 == nil || dna2 == nil {
		return false
	}
	
	// Primary comparison: system ID
	if dna1.Id != dna2.Id {
		return false
	}
	
	// Secondary comparison: key hardware characteristics
	keyAttributes := []string{"primary_mac", "hostname", "cpu_count", "arch"}
	
	for _, attr := range keyAttributes {
		if dna1.Attributes[attr] != dna2.Attributes[attr] {
			return false
		}
	}
	
	return true
}