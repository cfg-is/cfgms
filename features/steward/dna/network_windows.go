//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/cfgis/cfgms/pkg/logging"
)

// WindowsNetworkCollector handles Windows-specific network collection.
type WindowsNetworkCollector struct{}

// CollectInterfaces delegates to GenericNetworkCollector for base interface data.
func (w *WindowsNetworkCollector) CollectInterfaces(ctx context.Context, attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectInterfaces(ctx, attributes)
}

// CollectRouting gathers routing table information on Windows using route print -4.
// Attribute keys: default_gateway (sanitised), ipv4_route_count (capped at 500).
// IP/gateway values are tenant-sensitive (internal RFC1918 topology); sanitised before storage.
func (w *WindowsNetworkCollector) CollectRouting(ctx context.Context, attributes map[string]string) error {
	output, err := runCommand(ctx, "route", "print", "-4")
	if err != nil {
		return nil
	}
	w.parseWindowsRouteOutput(output, attributes)
	return nil
}

// parseWindowsRouteOutput parses "route print -4" output, extracting default gateway and route count.
func (w *WindowsNetworkCollector) parseWindowsRouteOutput(output string, attributes map[string]string) {
	const maxRoutes = 500
	routeCount := 0
	inActiveRoutes := false

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "Active Routes:" {
			inActiveRoutes = true
			continue
		}

		if strings.HasPrefix(line, "Persistent Routes:") {
			break
		}

		if !inActiveRoutes {
			continue
		}

		if strings.HasPrefix(line, "Network Destination") {
			continue
		}

		// Skip separator lines
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		if routeCount >= maxRoutes {
			break
		}
		routeCount++

		// Default route: destination 0.0.0.0, netmask 0.0.0.0
		if fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" && attributes["default_gateway"] == "" {
			if fields[2] != "On-link" {
				attributes["default_gateway"] = logging.SanitizeLogValue(fields[2])
			}
		}
	}

	if routeCount > 0 {
		attributes["ipv4_route_count"] = fmt.Sprintf("%d", routeCount)
	}
}

// CollectDNS reads DNS server configuration from the Windows registry.
// Primary source: per-adapter keys under Tcpip\Parameters\Interfaces (DhcpNameServer / NameServer).
// Attribute keys: dns_servers (comma-separated, sanitised, truncated to 256 chars), dns_domain (sanitised).
// DNS server addresses are tenant-sensitive routing data; sanitised before storage.
func (w *WindowsNetworkCollector) CollectDNS(_ context.Context, attributes map[string]string) error {
	w.collectDNSServersFromRegistry(attributes)
	w.collectDNSDomainFromRegistry(attributes)
	return nil
}

// collectDNSServersFromRegistry enumerates per-adapter interface registry keys to gather DNS servers.
func (w *WindowsNetworkCollector) collectDNSServersFromRegistry(attributes map[string]string) {
	ifaceKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		registry.READ)
	if err != nil {
		return
	}
	defer func() { _ = ifaceKey.Close() }()

	subkeys, err := ifaceKey.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	seen := make(map[string]struct{})
	var servers []string

	for _, subkey := range subkeys {
		w.collectDNSFromAdapter(ifaceKey, subkey, seen, &servers)
	}

	if len(servers) > 0 {
		joined := strings.Join(servers, ",")
		if len(joined) > 256 {
			joined = joined[:256]
		}
		attributes["dns_servers"] = joined
	}
}

// collectDNSFromAdapter reads DhcpNameServer and NameServer from one adapter's registry key.
func (w *WindowsNetworkCollector) collectDNSFromAdapter(
	parent registry.Key, subkey string,
	seen map[string]struct{}, servers *[]string,
) {
	adapterKey, err := registry.OpenKey(parent, subkey, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer func() { _ = adapterKey.Close() }()

	for _, valueName := range []string{"DhcpNameServer", "NameServer"} {
		val, _, err := adapterKey.GetStringValue(valueName)
		if err != nil || val == "" {
			continue
		}
		// Values may be space- or comma-separated
		for _, s := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ' ' }) {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, exists := seen[s]; !exists {
				seen[s] = struct{}{}
				*servers = append(*servers, logging.SanitizeLogValue(s))
			}
		}
	}
}

// collectDNSDomainFromRegistry reads the configured DNS domain from global Tcpip parameters.
func (w *WindowsNetworkCollector) collectDNSDomainFromRegistry(attributes map[string]string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer func() { _ = key.Close() }()

	for _, valueName := range []string{"Domain", "DhcpDomain"} {
		val, _, err := key.GetStringValue(valueName)
		if err != nil || val == "" {
			continue
		}
		attributes["dns_domain"] = logging.SanitizeLogValue(val)
		return
	}
}

// CollectFirewall reads Windows Firewall profile states via netsh advfirewall.
// Attribute keys: windows_firewall_domain_profile, windows_firewall_private_profile,
// windows_firewall_public_profile. Each value is "enabled" or "disabled".
func (w *WindowsNetworkCollector) CollectFirewall(ctx context.Context, attributes map[string]string) error {
	output, err := runCommand(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return nil
	}
	w.parseNetshFirewallOutput(output, attributes)
	return nil
}

// parseNetshFirewallOutput parses "netsh advfirewall show allprofiles state" output.
func (w *WindowsNetworkCollector) parseNetshFirewallOutput(output string, attributes map[string]string) {
	currentProfile := ""

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		switch {
		case strings.Contains(lower, "domain profile"):
			currentProfile = "domain"
		case strings.Contains(lower, "private profile"):
			currentProfile = "private"
		case strings.Contains(lower, "public profile"):
			currentProfile = "public"
		case strings.HasPrefix(lower, "state") && currentProfile != "":
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			state := strings.ToLower(fields[len(fields)-1])
			var val string
			switch state {
			case "on":
				val = "enabled"
			case "off":
				val = "disabled"
			default:
				continue
			}
			switch currentProfile {
			case "domain":
				attributes["windows_firewall_domain_profile"] = val
			case "private":
				attributes["windows_firewall_private_profile"] = val
			case "public":
				attributes["windows_firewall_public_profile"] = val
			}
		}
	}
}
