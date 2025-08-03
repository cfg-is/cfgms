package dna

import (
	"fmt"
	"net"
	"runtime"
	"strings"
)

// NetworkCollector defines the interface for platform-specific network configuration collection
type NetworkCollector interface {
	// CollectInterfaces gathers network interface details
	CollectInterfaces(attributes map[string]string) error
	
	// CollectRouting gathers routing table information
	CollectRouting(attributes map[string]string) error
	
	// CollectDNS gathers DNS configuration
	CollectDNS(attributes map[string]string) error
	
	// CollectFirewall gathers firewall rules and configuration
	CollectFirewall(attributes map[string]string) error
}

// NewNetworkCollector creates a platform-specific network collector
func NewNetworkCollector() NetworkCollector {
	switch runtime.GOOS {
	case "windows":
		return &WindowsNetworkCollector{}
	case "linux":
		return &LinuxNetworkCollector{}
	case "darwin":
		return &DarwinNetworkCollector{}
	default:
		return &GenericNetworkCollector{}
	}
}

// GenericNetworkCollector provides basic cross-platform network collection
// This is used as a fallback when platform-specific collectors are not available
type GenericNetworkCollector struct{}

func (g *GenericNetworkCollector) CollectInterfaces(attributes map[string]string) error {
	// Get all network interfaces using Go's standard library
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	var ipAddresses []string
	var macAddresses []string
	var interfaceNames []string

	for _, iface := range interfaces {
		// Skip loopback interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Collect interface names
		interfaceNames = append(interfaceNames, iface.Name)

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

	// Store collected information
	if len(ipAddresses) > 0 {
		attributes["ip_addresses"] = strings.Join(ipAddresses, ",")
		attributes["primary_ip"] = ipAddresses[0]
	}

	if len(macAddresses) > 0 {
		attributes["mac_addresses"] = strings.Join(macAddresses, ",")
		attributes["primary_mac"] = macAddresses[0]
	}

	if len(interfaceNames) > 0 {
		attributes["network_interfaces"] = strings.Join(interfaceNames, ",")
	}

	attributes["network_interface_count"] = fmt.Sprintf("%d", len(interfaces))

	return nil
}

func (g *GenericNetworkCollector) CollectRouting(attributes map[string]string) error {
	// Generic routing collection - limited without platform-specific APIs
	attributes["routing_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericNetworkCollector) CollectDNS(attributes map[string]string) error {
	// Generic DNS collection - limited without platform-specific APIs
	attributes["dns_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericNetworkCollector) CollectFirewall(attributes map[string]string) error {
	// Generic firewall collection - limited without platform-specific APIs
	attributes["firewall_info"] = "generic_collector_limited"
	return nil
}

// Platform-specific collector types (implementations in separate files)

// WindowsNetworkCollector handles Windows-specific network collection
type WindowsNetworkCollector struct{}

func (w *WindowsNetworkCollector) CollectInterfaces(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectInterfaces(attributes)
}

func (w *WindowsNetworkCollector) CollectRouting(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectRouting(attributes)
}

func (w *WindowsNetworkCollector) CollectDNS(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectDNS(attributes)
}

func (w *WindowsNetworkCollector) CollectFirewall(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectFirewall(attributes)
}

// LinuxNetworkCollector handles Linux-specific network collection
type LinuxNetworkCollector struct{}

func (l *LinuxNetworkCollector) CollectInterfaces(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectInterfaces(attributes)
}

func (l *LinuxNetworkCollector) CollectRouting(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectRouting(attributes)
}

func (l *LinuxNetworkCollector) CollectDNS(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectDNS(attributes)
}

func (l *LinuxNetworkCollector) CollectFirewall(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectFirewall(attributes)
}

// DarwinNetworkCollector handles macOS-specific network collection
type DarwinNetworkCollector struct{}

func (d *DarwinNetworkCollector) CollectInterfaces(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectInterfaces(attributes)
}

func (d *DarwinNetworkCollector) CollectRouting(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectRouting(attributes)
}

func (d *DarwinNetworkCollector) CollectDNS(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectDNS(attributes)
}

func (d *DarwinNetworkCollector) CollectFirewall(attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectFirewall(attributes)
}