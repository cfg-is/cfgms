// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// NetworkCollector defines the interface for platform-specific network configuration collection
type NetworkCollector interface {
	// CollectInterfaces gathers network interface details
	CollectInterfaces(ctx context.Context, attributes map[string]string) error

	// CollectRouting gathers routing table information
	CollectRouting(ctx context.Context, attributes map[string]string) error

	// CollectDNS gathers DNS configuration
	CollectDNS(ctx context.Context, attributes map[string]string) error

	// CollectFirewall gathers firewall rules and configuration
	CollectFirewall(ctx context.Context, attributes map[string]string) error
}

// NewNetworkCollector creates a platform-specific network collector
func NewNetworkCollector() NetworkCollector {
	return newPlatformNetworkCollector()
}

// GenericNetworkCollector provides basic cross-platform network collection
// This is used as a fallback when platform-specific collectors are not available
type GenericNetworkCollector struct{}

func (g *GenericNetworkCollector) CollectInterfaces(_ context.Context, attributes map[string]string) error {
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

func (g *GenericNetworkCollector) CollectRouting(_ context.Context, attributes map[string]string) error {
	// Generic routing collection - limited without platform-specific APIs
	attributes["routing_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericNetworkCollector) CollectDNS(_ context.Context, attributes map[string]string) error {
	// Generic DNS collection - limited without platform-specific APIs
	attributes["dns_info"] = "generic_collector_limited"
	return nil
}

func (g *GenericNetworkCollector) CollectFirewall(_ context.Context, attributes map[string]string) error {
	// Generic firewall collection - limited without platform-specific APIs
	attributes["firewall_info"] = "generic_collector_limited"
	return nil
}

// DarwinNetworkCollector handles macOS-specific network collection
type DarwinNetworkCollector struct{}
