//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxNetworkCollector(t *testing.T) {
	ctx := context.Background()
	collector := &LinuxNetworkCollector{}

	t.Run("CollectRouting", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectRouting(ctx, attrs)
		require.NoError(t, err)

		assert.NotEmpty(t, attrs["default_gateway"], "default_gateway must be non-empty")

		countStr := attrs["ipv4_route_count"]
		require.NotEmpty(t, countStr, "ipv4_route_count must be set")
		count, err := strconv.Atoi(countStr)
		require.NoError(t, err, "ipv4_route_count must be a parseable integer")
		assert.GreaterOrEqual(t, count, 1, "ipv4_route_count must be >= 1")
	})

	t.Run("CollectDNS", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectDNS(ctx, attrs)
		require.NoError(t, err)

		assert.NotEmpty(t, attrs["dns_servers"], "dns_servers must be non-empty")
	})

	t.Run("CollectFirewall", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectFirewall(ctx, attrs)
		require.NoError(t, err)

		// At least one firewall attribute must be present and not the stub value
		firewallKeys := []string{"ufw_firewall_state", "iptables_rule_count", "firewall_state"}
		found := false
		for _, key := range firewallKeys {
			if val, ok := attrs[key]; ok && val != "" && val != "generic_collector_limited" {
				found = true
				break
			}
		}
		assert.True(t, found, "at least one non-stub firewall attribute must be present (got: %v)", attrs)
	})

	t.Run("CollectInterfaces_PopulatesInterfaceCount", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectInterfaces(ctx, attrs)
		require.NoError(t, err)

		count, exists := attrs["network_interface_count"]
		assert.True(t, exists, "network_interface_count must be set by CollectInterfaces")
		n, err := strconv.Atoi(count)
		require.NoError(t, err, "network_interface_count must be parseable as integer")
		assert.GreaterOrEqual(t, n, 1, "network_interface_count must be >= 1")
	})

	t.Run("CollectRouting_RouteCountCappedAt500", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectRouting(ctx, attrs)
		require.NoError(t, err)

		if countStr, ok := attrs["ipv4_route_count"]; ok {
			count, err := strconv.Atoi(countStr)
			require.NoError(t, err)
			assert.LessOrEqual(t, count, 500, "ipv4_route_count must not exceed 500")
		}
	})

	t.Run("CollectDNS_TruncatedTo256", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectDNS(ctx, attrs)
		require.NoError(t, err)

		if servers, ok := attrs["dns_servers"]; ok {
			assert.LessOrEqual(t, len(servers), 256, "dns_servers must be truncated to 256 chars")
		}
	})
}

func TestParseLinuxHexIP(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		// /proc/net/route gateway for 172.17.0.1 in little-endian hex
		{"010011AC", "172.17.0.1"},
		// 192.168.1.1
		{"0101A8C0", "192.168.1.1"},
		// 10.0.0.1
		{"0100000A", "10.0.0.1"},
		// Default route gateway field value of 0 (no gateway)
		{"00000000", "0.0.0.0"},
		// Invalid hex
		{"GGGGGGGG", ""},
		// Empty string
		{"", ""},
	}

	for _, tc := range cases {
		result := parseLinuxHexIP(tc.input)
		assert.Equal(t, tc.expected, result, "parseLinuxHexIP(%q)", tc.input)
	}
}

func TestParseUFWStatus(t *testing.T) {
	collector := &LinuxNetworkCollector{}

	t.Run("Active", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseUFWStatus("Status: active\n\n     To   Action   From\n", attrs)
		assert.Equal(t, "active", attrs["ufw_firewall_state"])
	})

	t.Run("Inactive", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseUFWStatus("Status: inactive\n", attrs)
		assert.Equal(t, "inactive", attrs["ufw_firewall_state"])
	})

	t.Run("NoStatusLine_DefaultsInactive", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseUFWStatus("some output\nwithout a status line\n", attrs)
		assert.Equal(t, "inactive", attrs["ufw_firewall_state"])
	})

	t.Run("EmptyOutput_DefaultsInactive", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseUFWStatus("", attrs)
		assert.Equal(t, "inactive", attrs["ufw_firewall_state"])
	})
}

func TestCountIPTablesRules(t *testing.T) {
	collector := &LinuxNetworkCollector{}

	t.Run("OneRule", func(t *testing.T) {
		output := "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nDROP       all  --  0.0.0.0/0            0.0.0.0/0\n\nChain FORWARD (policy DROP)\ntarget     prot opt source               destination\n\n"
		count := collector.countIPTablesRules(output)
		assert.Equal(t, 1, count, "should count one actual rule")
	})

	t.Run("NoRules", func(t *testing.T) {
		output := "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\n\nChain FORWARD (policy DROP)\ntarget     prot opt source               destination\n\n"
		count := collector.countIPTablesRules(output)
		assert.Equal(t, 0, count)
	})

	t.Run("EmptyOutput", func(t *testing.T) {
		count := collector.countIPTablesRules("")
		assert.Equal(t, 0, count)
	})
}
