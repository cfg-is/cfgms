//go:build windows

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

func TestWindowsNetworkCollector(t *testing.T) {
	ctx := context.Background()
	collector := &WindowsNetworkCollector{}

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
		assert.LessOrEqual(t, count, 500, "ipv4_route_count must not exceed 500")
	})

	t.Run("CollectDNS", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectDNS(ctx, attrs)
		require.NoError(t, err)

		assert.NotEmpty(t, attrs["dns_servers"], "dns_servers must be non-empty")

		if servers, ok := attrs["dns_servers"]; ok {
			assert.LessOrEqual(t, len(servers), 256, "dns_servers must be truncated to 256 chars")
		}
	})

	t.Run("CollectFirewall", func(t *testing.T) {
		attrs := make(map[string]string)
		err := collector.CollectFirewall(ctx, attrs)
		require.NoError(t, err)

		assert.NotEmpty(t, attrs["windows_firewall_domain_profile"], "domain firewall profile must be set")
		assert.NotEmpty(t, attrs["windows_firewall_private_profile"], "private firewall profile must be set")
		assert.NotEmpty(t, attrs["windows_firewall_public_profile"], "public firewall profile must be set")

		validStates := map[string]bool{"enabled": true, "disabled": true}
		assert.True(t, validStates[attrs["windows_firewall_domain_profile"]],
			"domain profile must be 'enabled' or 'disabled', got: %q", attrs["windows_firewall_domain_profile"])
		assert.True(t, validStates[attrs["windows_firewall_private_profile"]],
			"private profile must be 'enabled' or 'disabled', got: %q", attrs["windows_firewall_private_profile"])
		assert.True(t, validStates[attrs["windows_firewall_public_profile"]],
			"public profile must be 'enabled' or 'disabled', got: %q", attrs["windows_firewall_public_profile"])
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
}

func TestParseWindowsRouteOutput(t *testing.T) {
	collector := &WindowsNetworkCollector{}

	sampleOutput := `
===========================================================================
Interface List
 14...00 15 5d 01 3c 02 ......Hyper-V Virtual Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.1.1    192.168.1.100     21
        127.0.0.0        255.0.0.0         On-link          127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link          127.0.0.1    331
  192.168.1.0    255.255.255.0         On-link    192.168.1.100     21
===========================================================================

Persistent Routes:
  None
`

	t.Run("ParsesDefaultGateway", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseWindowsRouteOutput(sampleOutput, attrs)
		assert.Equal(t, "192.168.1.1", attrs["default_gateway"])
	})

	t.Run("ParsesRouteCount", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseWindowsRouteOutput(sampleOutput, attrs)
		count, err := strconv.Atoi(attrs["ipv4_route_count"])
		require.NoError(t, err)
		assert.Equal(t, 4, count)
	})

	t.Run("EmptyOutput_NoAttributes", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseWindowsRouteOutput("", attrs)
		assert.Empty(t, attrs["default_gateway"])
		assert.Empty(t, attrs["ipv4_route_count"])
	})

	t.Run("NoActiveRoutesSection", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseWindowsRouteOutput("some unrelated output\n", attrs)
		assert.Empty(t, attrs["default_gateway"])
	})
}

func TestParseNetshFirewallOutput(t *testing.T) {
	collector := &WindowsNetworkCollector{}

	sampleOutput := `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON


Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF


Public Profile Settings:
----------------------------------------------------------------------
State                                 ON

Ok.
`

	t.Run("ParsesAllProfiles", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseNetshFirewallOutput(sampleOutput, attrs)
		assert.Equal(t, "enabled", attrs["windows_firewall_domain_profile"])
		assert.Equal(t, "disabled", attrs["windows_firewall_private_profile"])
		assert.Equal(t, "enabled", attrs["windows_firewall_public_profile"])
	})

	t.Run("EmptyOutput_NoAttributes", func(t *testing.T) {
		attrs := make(map[string]string)
		collector.parseNetshFirewallOutput("", attrs)
		assert.Empty(t, attrs["windows_firewall_domain_profile"])
		assert.Empty(t, attrs["windows_firewall_private_profile"])
		assert.Empty(t, attrs["windows_firewall_public_profile"])
	})

	t.Run("AllDisabled", func(t *testing.T) {
		output := "Domain Profile Settings:\nState OFF\nPrivate Profile Settings:\nState OFF\nPublic Profile Settings:\nState OFF\n"
		attrs := make(map[string]string)
		collector.parseNetshFirewallOutput(output, attrs)
		assert.Equal(t, "disabled", attrs["windows_firewall_domain_profile"])
		assert.Equal(t, "disabled", attrs["windows_firewall_private_profile"])
		assert.Equal(t, "disabled", attrs["windows_firewall_public_profile"])
	})
}
