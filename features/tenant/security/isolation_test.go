// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsIPInRange(t *testing.T) {
	engine := &TenantIsolationEngine{}

	tests := []struct {
		name      string
		ip        string
		cidrRange string
		want      bool
	}{
		// Match-all wildcard
		{"all-match cidr 0.0.0.0/0 with arbitrary IP", "1.2.3.4", "0.0.0.0/0", true},
		{"all-match cidr 0.0.0.0/0 with another IP", "255.255.255.255", "0.0.0.0/0", true},

		// /24 network
		{"192.168.1.0/24 matches host in range", "192.168.1.5", "192.168.1.0/24", true},
		{"192.168.1.0/24 rejects host outside range", "192.168.2.5", "192.168.1.0/24", false},

		// /8 network
		{"10.0.0.0/8 matches highest host", "10.255.255.255", "10.0.0.0/8", true},
		{"10.0.0.0/8 rejects 11.0.0.0", "11.0.0.0", "10.0.0.0/8", false},

		// /12 network (172.16.0.0 – 172.31.255.255)
		{"172.16.0.0/12 matches lower bound", "172.16.0.1", "172.16.0.0/12", true},
		{"172.16.0.0/12 matches upper bound", "172.31.255.255", "172.16.0.0/12", true},
		{"172.16.0.0/12 rejects address just above range", "172.32.0.0", "172.16.0.0/12", false},

		// /16 network
		{"10.0.0.0/16 matches host in range", "10.0.0.1", "10.0.0.0/16", true},
		{"10.0.0.0/16 rejects 10.1.0.0", "10.1.0.0", "10.0.0.0/16", false},

		// IPv6 /32 network
		{"2001:db8::/32 matches address in range", "2001:db8:1::1", "2001:db8::/32", true},
		{"2001:db8::/32 rejects address outside range", "2001:db9::1", "2001:db8::/32", false},

		// Invalid inputs — must return false, no panic
		{"invalid CIDR returns false", "192.168.1.1", "not-a-cidr", false},
		{"invalid IP returns false", "not-an-ip", "192.168.1.0/24", false},
		{"empty IP returns false", "", "192.168.1.0/24", false},
		{"empty CIDR returns false", "192.168.1.1", "", false},
		{"both empty returns false", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.isIPInRange(tt.ip, tt.cidrRange)
			assert.Equal(t, tt.want, got)
		})
	}
}
