// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package firewall

import (
	"context"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// createConfigFromYAML creates a firewallConfig from YAML string
func createConfigFromYAML(yamlData string) modules.ConfigState {
	var config firewallConfig
	if err := yaml.Unmarshal([]byte(yamlData), &config); err != nil {
		return nil
	}
	return &config
}

func TestFirewallModule(t *testing.T) {
	// Create a new firewall module instance
	module := New()

	// Define test cases
	tests := []struct {
		name       string
		resourceID string
		configData string
		wantErr    bool
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
enabled: true
`,
			wantErr: false,
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
enabled: true
`,
			wantErr: false,
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
enabled: true
`,
			wantErr: false,
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
enabled: true
`,
			wantErr: false,
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
			wantErr: false,
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
enabled: true
`,
			wantErr: true,
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
enabled: true
`,
			wantErr: true,
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
enabled: true
`,
			wantErr: true,
		},
		{
			name:       "Missing required fields",
			resourceID: "missing-fields",
			configData: `
name: missing-fields
action: allow
enabled: true
`,
			wantErr: true,
		},
		{
			name:       "Invalid action",
			resourceID: "invalid-action",
			configData: `
name: invalid-action
action: maybe
protocol: tcp
port: 80
source: 0.0.0.0/0
destination: 10.0.0.0/24
enabled: true
`,
			wantErr: true,
		},
	}

	// Run tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create ConfigState from YAML
			configState := createConfigFromYAML(tt.configData)
			if configState == nil && !tt.wantErr {
				t.Errorf("Failed to create config from YAML: %s", tt.configData)
				return
			}

			// Test Set
			err := module.Set(context.Background(), tt.resourceID, configState)
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
				if config == nil {
					t.Error("Get() returned nil config")
				}
			}
		})
	}
}

func TestFirewallModule_EdgeCases(t *testing.T) {
	module := New()

	// Test with nil config
	err := module.Set(context.Background(), "test-rule", nil)
	if err == nil {
		t.Error("Set() with nil config should fail")
	}

	// Test Get with non-existent rule
	_, err = module.Get(context.Background(), "non-existent")
	if err != ErrRuleNotFound {
		t.Errorf("Get() with non-existent rule error = %v, want %v", err, ErrRuleNotFound)
	}

	// Test successful rule creation and retrieval
	configData := `
name: test-rule
action: allow
protocol: tcp
port: 443
source: 192.168.1.0/24
destination: 10.0.0.0/24
description: Test HTTPS rule
enabled: true
`
	configState := createConfigFromYAML(configData)
	if configState == nil {
		t.Fatal("Failed to create config from YAML")
	}

	err = module.Set(context.Background(), "test-rule", configState)
	if err != nil {
		t.Errorf("Set() failed: %v", err)
	}

	// Verify the rule was stored correctly
	retrieved, err := module.Get(context.Background(), "test-rule")
	if err != nil {
		t.Errorf("Get() failed: %v", err)
	}

	if retrieved == nil {
		t.Error("Get() returned nil")
	}

	// Check that the retrieved config has expected values
	retrievedMap := retrieved.AsMap()
	if retrievedMap["name"] != "test-rule" {
		t.Errorf("Retrieved rule name = %v, want %v", retrievedMap["name"], "test-rule")
	}
	if retrievedMap["action"] != "allow" {
		t.Errorf("Retrieved rule action = %v, want %v", retrievedMap["action"], "allow")
	}
	if retrievedMap["port"] != 443 {
		t.Errorf("Retrieved rule port = %v, want %v", retrievedMap["port"], 443)
	}
}
