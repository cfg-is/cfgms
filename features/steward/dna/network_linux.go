//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cfgis/cfgms/pkg/logging"
)

// CollectInterfaces delegates to GenericNetworkCollector for base interface data.
func (l *LinuxNetworkCollector) CollectInterfaces(ctx context.Context, attributes map[string]string) error {
	return (&GenericNetworkCollector{}).CollectInterfaces(ctx, attributes)
}

// CollectRouting gathers routing table information on Linux by reading /proc/net/route.
// Attribute keys: default_gateway (first default route next-hop IP, sanitised),
// ipv4_route_count (total routes, capped at 500).
// IP/gateway values are tenant-sensitive (internal RFC1918 topology); sanitised before storage.
func (l *LinuxNetworkCollector) CollectRouting(_ context.Context, attributes map[string]string) error {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	const maxRoutes = 500
	routeCount := 0
	firstLine := true

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if firstLine {
			firstLine = false
			continue
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		if routeCount >= maxRoutes {
			break
		}
		routeCount++

		dest := fields[1]
		gateway := fields[2]
		mask := fields[7]

		// Default route: destination and mask both 00000000
		if dest == "00000000" && mask == "00000000" && attributes["default_gateway"] == "" {
			if gw := parseLinuxHexIP(gateway); gw != "" {
				attributes["default_gateway"] = logging.SanitizeLogValue(gw)
			}
		}
	}

	if routeCount > 0 {
		attributes["ipv4_route_count"] = fmt.Sprintf("%d", routeCount)
	}

	return nil
}

// parseLinuxHexIP converts a little-endian 32-bit hex string (as used in /proc/net/route)
// to a dotted-decimal IPv4 address string. Returns empty string on parse failure.
func parseLinuxHexIP(hexStr string) string {
	n, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return ""
	}
	// /proc/net/route stores addresses in host byte order (little-endian on x86/x64).
	// The first byte of the uint32 (least significant) is the first octet.
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24)).String()
}

// CollectDNS parses /etc/resolv.conf for DNS server and search domain configuration.
// Attribute keys: dns_servers (comma-separated, sanitised, truncated to 256 chars),
// dns_search_domains (sanitised, truncated to 256 chars).
// Note: On systemd-resolved systems the nameserver is the stub 127.0.0.53 — this is normal and not an error.
// DNS server addresses are tenant-sensitive routing data; sanitised before storage.
func (l *LinuxNetworkCollector) CollectDNS(_ context.Context, attributes map[string]string) error {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var servers []string
	var searchDomains []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "nameserver":
			servers = append(servers, logging.SanitizeLogValue(fields[1]))
		case "search", "domain":
			for _, d := range fields[1:] {
				searchDomains = append(searchDomains, logging.SanitizeLogValue(d))
			}
		}
	}

	if len(servers) > 0 {
		joined := strings.Join(servers, ",")
		if len(joined) > 256 {
			joined = joined[:256]
		}
		attributes["dns_servers"] = joined
	}

	if len(searchDomains) > 0 {
		joined := strings.Join(searchDomains, ",")
		if len(joined) > 256 {
			joined = joined[:256]
		}
		attributes["dns_search_domains"] = joined
	}

	return nil
}

// CollectFirewall detects Linux firewall state.
// Tries ufw first; falls back to counting iptables rules; degrades to firewall_state=unknown
// when tools are absent or permission is denied.
func (l *LinuxNetworkCollector) CollectFirewall(ctx context.Context, attributes map[string]string) error {
	// Primary: ufw status
	cmdCtx, cancel := context.WithTimeout(ctx, linuxCmdTimeout)
	output, err := exec.CommandContext(cmdCtx, "ufw", "status").Output()
	cancel()
	if err == nil {
		l.parseUFWStatus(string(output), attributes)
		return nil
	}

	// Fallback: iptables -L --line-numbers; degrades gracefully on permission denied
	cmdCtx2, cancel2 := context.WithTimeout(ctx, linuxCmdTimeout)
	output2, err2 := exec.CommandContext(cmdCtx2, "iptables", "-L", "--line-numbers").Output()
	cancel2()
	if err2 != nil {
		attributes["firewall_state"] = "unknown"
		return nil
	}

	attributes["iptables_rule_count"] = fmt.Sprintf("%d", l.countIPTablesRules(string(output2)))
	return nil
}

// parseUFWStatus parses "ufw status" output to extract the firewall state.
func (l *LinuxNetworkCollector) parseUFWStatus(output string, attributes map[string]string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "status:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				state := strings.TrimSpace(strings.ToLower(parts[1]))
				// Use HasPrefix to avoid "inactive" matching "active" via Contains.
				if strings.HasPrefix(state, "active") {
					attributes["ufw_firewall_state"] = "active"
				} else {
					attributes["ufw_firewall_state"] = "inactive"
				}
				return
			}
		}
	}
	attributes["ufw_firewall_state"] = "inactive"
}

// countIPTablesRules counts non-header lines in iptables -L output.
func (l *LinuxNetworkCollector) countIPTablesRules(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "target ") {
			continue
		}
		count++
	}
	return count
}
