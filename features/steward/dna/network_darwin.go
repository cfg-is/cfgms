//go:build darwin

package dna

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// CollectInterfaces gathers detailed network interface information on macOS
func (d *DarwinNetworkCollector) CollectInterfaces(attributes map[string]string) error {
	// First collect basic interface info using Go's standard library
	if err := (&GenericNetworkCollector{}).CollectInterfaces(attributes); err != nil {
		return err
	}

	// Enhanced interface information using ifconfig
	if output, err := exec.Command("ifconfig").Output(); err == nil {
		d.parseIfconfigOutput(string(output), attributes)
	}

	// Network service information using networksetup
	if output, err := exec.Command("networksetup", "-listallnetworkservices").Output(); err == nil {
		d.parseNetworkServices(string(output), attributes)
	}

	// Wi-Fi information if available
	d.collectWiFiInfo(attributes)

	return nil
}

// CollectRouting gathers routing table information on macOS
func (d *DarwinNetworkCollector) CollectRouting(attributes map[string]string) error {
	// IPv4 routing table
	if output, err := exec.Command("netstat", "-rn", "-f", "inet").Output(); err == nil {
		d.parseRoutingTable(string(output), attributes, "ipv4")
	}

	// IPv6 routing table
	if output, err := exec.Command("netstat", "-rn", "-f", "inet6").Output(); err == nil {
		d.parseRoutingTable(string(output), attributes, "ipv6")
	}

	// Default gateway information
	if output, err := exec.Command("route", "get", "default").Output(); err == nil {
		d.parseDefaultGateway(string(output), attributes)
	}

	return nil
}

// CollectDNS gathers DNS configuration on macOS
func (d *DarwinNetworkCollector) CollectDNS(attributes map[string]string) error {
	// DNS configuration using scutil
	if output, err := exec.Command("scutil", "--dns").Output(); err == nil {
		d.parseDNSConfig(string(output), attributes)
	}

	// System DNS servers using networksetup
	d.collectDNSServers(attributes)

	// Search domains
	d.collectSearchDomains(attributes)

	// /etc/hosts file information
	if output, err := exec.Command("wc", "-l", "/etc/hosts").Output(); err == nil {
		hostsLines := strings.TrimSpace(string(output))
		if lines := strings.Fields(hostsLines); len(lines) > 0 {
			attributes["hosts_file_lines"] = lines[0]
		}
	}

	return nil
}

// CollectFirewall gathers firewall configuration on macOS
func (d *DarwinNetworkCollector) CollectFirewall(attributes map[string]string) error {
	// macOS firewall status using defaults
	if output, err := exec.Command("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate").Output(); err == nil {
		firewallState := strings.TrimSpace(string(output))
		switch firewallState {
		case "0":
			attributes["macos_firewall_state"] = "disabled"
		case "1":
			attributes["macos_firewall_state"] = "enabled_essential"
		case "2":
			attributes["macos_firewall_state"] = "enabled_all"
		default:
			attributes["macos_firewall_state"] = "unknown_" + firewallState
		}
	}

	// pfctl firewall rules (if enabled and accessible)
	if output, err := exec.Command("pfctl", "-s", "rules").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		var ruleCount int
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				ruleCount++
			}
		}
		if ruleCount > 0 {
			attributes["pfctl_rule_count"] = fmt.Sprintf("%d", ruleCount)
		}
	}

	// Stealth mode status
	if output, err := exec.Command("defaults", "read", "/Library/Preferences/com.apple.alf", "stealthenabled").Output(); err == nil {
		stealthMode := strings.TrimSpace(string(output))
		attributes["macos_firewall_stealth"] = stealthMode
	}

	// Logging enabled status
	if output, err := exec.Command("defaults", "read", "/Library/Preferences/com.apple.alf", "loggingenabled").Output(); err == nil {
		loggingEnabled := strings.TrimSpace(string(output))
		attributes["macos_firewall_logging"] = loggingEnabled
	}

	return nil
}

// parseIfconfigOutput parses ifconfig output for detailed interface information
func (d *DarwinNetworkCollector) parseIfconfigOutput(output string, attributes map[string]string) {
	interfaces := strings.Split(output, "\n\n")
	var activeInterfaces []string
	var wiredInterfaces []string
	var wirelessInterfaces []string

	for _, interfaceBlock := range interfaces {
		lines := strings.Split(interfaceBlock, "\n")
		if len(lines) == 0 {
			continue
		}

		// Parse interface name from first line
		firstLine := lines[0]
		if strings.Contains(firstLine, ":") {
			interfaceName := strings.Split(firstLine, ":")[0]

			// Check if interface is active (has RUNNING flag)
			if strings.Contains(firstLine, "RUNNING") {
				activeInterfaces = append(activeInterfaces, interfaceName)
			}

			// Categorize interface types
			if strings.HasPrefix(interfaceName, "en") {
				if strings.Contains(interfaceBlock, "media: Ethernet") {
					wiredInterfaces = append(wiredInterfaces, interfaceName)
				} else if strings.Contains(interfaceBlock, "media: IEEE 802.11") {
					wirelessInterfaces = append(wirelessInterfaces, interfaceName)
				}
			}

			// Extract MTU information
			if strings.Contains(firstLine, "mtu") {
				parts := strings.Fields(firstLine)
				for i, part := range parts {
					if part == "mtu" && i+1 < len(parts) {
						attributes["interface_"+interfaceName+"_mtu"] = parts[i+1]
						break
					}
				}
			}
		}
	}

	if len(activeInterfaces) > 0 {
		attributes["active_interfaces"] = strings.Join(activeInterfaces, ",")
		attributes["active_interface_count"] = fmt.Sprintf("%d", len(activeInterfaces))
	}

	if len(wiredInterfaces) > 0 {
		attributes["wired_interfaces"] = strings.Join(wiredInterfaces, ",")
	}

	if len(wirelessInterfaces) > 0 {
		attributes["wireless_interfaces"] = strings.Join(wirelessInterfaces, ",")
	}
}

// parseNetworkServices parses networksetup network services
func (d *DarwinNetworkCollector) parseNetworkServices(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	var services []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "*") {
			services = append(services, line)
		}
	}

	if len(services) > 0 {
		attributes["network_service_count"] = fmt.Sprintf("%d", len(services))
		// Store first 5 services as sample
		sampleSize := len(services)
		if sampleSize > 5 {
			sampleSize = 5
		}
		attributes["network_services_sample"] = strings.Join(services[:sampleSize], ", ")
	}
}

// collectWiFiInfo collects Wi-Fi specific information
func (d *DarwinNetworkCollector) collectWiFiInfo(attributes map[string]string) {
	// Current Wi-Fi SSID
	if output, err := exec.Command("networksetup", "-getairportnetwork", "en0").Output(); err == nil {
		ssidLine := strings.TrimSpace(string(output))
		if strings.Contains(ssidLine, ":") {
			parts := strings.SplitN(ssidLine, ":", 2)
			if len(parts) == 2 {
				ssid := strings.TrimSpace(parts[1])
				if ssid != "" && ssid != "You are not associated with an AirPort network." {
					attributes["wifi_current_ssid"] = ssid
				}
			}
		}
	}

	// Wi-Fi power status
	if output, err := exec.Command("networksetup", "-getairportpower", "en0").Output(); err == nil {
		powerStatus := strings.TrimSpace(string(output))
		if strings.Contains(powerStatus, ":") {
			parts := strings.SplitN(powerStatus, ":", 2)
			if len(parts) == 2 {
				attributes["wifi_power_status"] = strings.TrimSpace(parts[1])
			}
		}
	}
}

// parseRoutingTable parses netstat routing table output
func (d *DarwinNetworkCollector) parseRoutingTable(output string, attributes map[string]string, ipVersion string) {
	lines := strings.Split(output, "\n")
	var routeCount int
	var defaultRoutes []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Destination") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			routeCount++

			// Check for default routes
			if fields[0] == "default" || fields[0] == "0.0.0.0" || fields[0] == "::" {
				if len(fields) >= 2 {
					defaultRoutes = append(defaultRoutes, fields[1])
				}
			}
		}
	}

	if routeCount > 0 {
		attributes["routing_table_"+ipVersion+"_count"] = fmt.Sprintf("%d", routeCount)
	}

	if len(defaultRoutes) > 0 {
		attributes["default_gateways_"+ipVersion] = strings.Join(defaultRoutes, ",")
	}
}

// parseDefaultGateway parses route get default output
func (d *DarwinNetworkCollector) parseDefaultGateway(output string, attributes map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "gateway:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				gateway := strings.TrimSpace(parts[1])
				attributes["default_gateway"] = gateway
			}
		} else if strings.Contains(line, "interface:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				iface := strings.TrimSpace(parts[1])
				attributes["default_interface"] = iface
			}
		}
	}
}

// parseDNSConfig parses scutil --dns output
func (d *DarwinNetworkCollector) parseDNSConfig(output string, attributes map[string]string) {
	// Count DNS resolvers
	resolverCount := strings.Count(output, "resolver #")
	if resolverCount > 0 {
		attributes["dns_resolver_count"] = fmt.Sprintf("%d", resolverCount)
	}

	// Extract first few nameservers
	lines := strings.Split(output, "\n")
	var nameservers []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "nameserver[") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				ns := strings.TrimSpace(parts[1])
				if ns != "" {
					nameservers = append(nameservers, ns)
					if len(nameservers) >= 5 { // Limit to first 5
						break
					}
				}
			}
		}
	}

	if len(nameservers) > 0 {
		attributes["dns_nameservers"] = strings.Join(nameservers, ",")
	}
}

// collectDNSServers collects DNS servers using networksetup
func (d *DarwinNetworkCollector) collectDNSServers(attributes map[string]string) {
	services := []string{"Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"}

	for _, service := range services {
		if output, err := exec.Command("networksetup", "-getdnsservers", service).Output(); err == nil {
			dnsOutput := strings.TrimSpace(string(output))
			if dnsOutput != "" && !strings.Contains(dnsOutput, "There aren't any DNS Servers") {
				servers := strings.Split(dnsOutput, "\n")
				var validServers []string
				for _, server := range servers {
					server = strings.TrimSpace(server)
					if server != "" && net.ParseIP(server) != nil {
						validServers = append(validServers, server)
					}
				}
				if len(validServers) > 0 {
					serviceKey := strings.ToLower(strings.Replace(service, " ", "_", -1))
					attributes["dns_servers_"+serviceKey] = strings.Join(validServers, ",")
				}
			}
		}
	}
}

// collectSearchDomains collects DNS search domains
func (d *DarwinNetworkCollector) collectSearchDomains(attributes map[string]string) {
	services := []string{"Wi-Fi", "Ethernet"}

	for _, service := range services {
		if output, err := exec.Command("networksetup", "-getsearchdomains", service).Output(); err == nil {
			searchOutput := strings.TrimSpace(string(output))
			if searchOutput != "" && !strings.Contains(searchOutput, "There aren't any Search Domains") {
				domains := strings.Split(searchOutput, "\n")
				var validDomains []string
				for _, domain := range domains {
					domain = strings.TrimSpace(domain)
					if domain != "" {
						validDomains = append(validDomains, domain)
					}
				}
				if len(validDomains) > 0 {
					serviceKey := strings.ToLower(strings.Replace(service, " ", "_", -1))
					attributes["search_domains_"+serviceKey] = strings.Join(validDomains, ",")
				}
			}
		}
	}
}
