package firewall

import (
	"context"
	"testing"
)

func TestFirewallModule(t *testing.T) {
	// Create a new firewall module instance
	module := New()

	// Define test cases
	tests := []struct {
		name          string
		resourceID    string
		configData    string
		wantErr       bool
		wantTestErr   bool
		wantTestMatch bool
	}{
		{
			name:       "Basic allow rule",
			resourceID: "allow-http",
			configData: `
name: allow-http
action: allow
protocol: tcp
port: 80
source: 0.0.0.0/0
destination: 10.0.0.0/24
`,
			wantErr:       false,
			wantTestErr:   false,
			wantTestMatch: true,
		},
		{
			name:       "Deny rule",
			resourceID: "deny-ssh",
			configData: `
name: deny-ssh
action: deny
protocol: tcp
port: 22
source: 192.168.1.0/24
destination: 10.0.0.0/24
`,
			wantErr:       false,
			wantTestErr:   false,
			wantTestMatch: true,
		},
		{
			name:       "Service-based rule",
			resourceID: "allow-https",
			configData: `
name: allow-https
action: allow
service: https
source: 0.0.0.0/0
destination: 10.0.0.0/24
`,
			wantErr:       false,
			wantTestErr:   false,
			wantTestMatch: true,
		},
		{
			name:       "Multiple ports",
			resourceID: "allow-dns",
			configData: `
name: allow-dns
action: allow
protocol: udp
ports: [53, 5353]
source: 10.0.0.0/24
destination: 8.8.8.8
`,
			wantErr:       false,
			wantTestErr:   false,
			wantTestMatch: true,
		},
		{
			name:       "Disabled rule",
			resourceID: "disabled-rule",
			configData: `
name: disabled-rule
action: allow
protocol: tcp
port: 8080
source: 0.0.0.0/0
destination: 10.0.0.0/24
enabled: false
`,
			wantErr:       false,
			wantTestErr:   false,
			wantTestMatch: true,
		},
		{
			name:       "Invalid protocol",
			resourceID: "invalid-protocol",
			configData: `
name: invalid-protocol
action: allow
protocol: invalid
port: 80
source: 0.0.0.0/0
destination: 10.0.0.0/24
`,
			wantErr:       true,
			wantTestErr:   true,
			wantTestMatch: false,
		},
		{
			name:       "Invalid port",
			resourceID: "invalid-port",
			configData: `
name: invalid-port
action: allow
protocol: tcp
port: 70000
source: 0.0.0.0/0
destination: 10.0.0.0/24
`,
			wantErr:       true,
			wantTestErr:   true,
			wantTestMatch: false,
		},
		{
			name:       "Invalid IP",
			resourceID: "invalid-ip",
			configData: `
name: invalid-ip
action: allow
protocol: tcp
port: 80
source: invalid-ip
destination: 10.0.0.0/24
`,
			wantErr:       true,
			wantTestErr:   true,
			wantTestMatch: false,
		},
		{
			name:       "Missing required fields",
			resourceID: "missing-fields",
			configData: `
name: missing-fields
action: allow
`,
			wantErr:       true,
			wantTestErr:   true,
			wantTestMatch: false,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Set
			err := module.Set(context.Background(), tt.resourceID, tt.configData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Test Get (only if Set was successful)
			if !tt.wantErr {
				config, err := module.Get(context.Background(), tt.resourceID)
				if err != nil {
					t.Errorf("Get() error = %v", err)
					return
				}
				if config == "" {
					t.Error("Get() returned empty config")
				}
			}

			// Test Test
			matches, err := module.Test(context.Background(), tt.resourceID, tt.configData)
			if (err != nil) != tt.wantTestErr {
				t.Errorf("Test() error = %v, wantTestErr %v", err, tt.wantTestErr)
				return
			}
			if matches != tt.wantTestMatch {
				t.Errorf("Test() matches = %v, want %v", matches, tt.wantTestMatch)
			}
		})
	}
}
