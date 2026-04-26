// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package firewall

import (
	"context"
	"errors"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules"
)

// testFirewallExecutor is an in-package test implementation of firewallExecutor.
// It tracks applied and deleted rules and returns configurable errors. No mock
// library is used; the executor simulates OS state via an in-memory installed set.
type testFirewallExecutor struct {
	installed    map[string]firewallConfig
	applyErr     error
	deleteErr    error
	existsErr    error
	appliedRules []firewallConfig
	deletedRules []firewallConfig
}

func newTestExecutor() *testFirewallExecutor {
	return &testFirewallExecutor{
		installed: make(map[string]firewallConfig),
	}
}

func (e *testFirewallExecutor) applyRule(rule firewallConfig) error {
	if e.applyErr != nil {
		return e.applyErr
	}
	e.installed[rule.Name] = rule
	e.appliedRules = append(e.appliedRules, rule)
	return nil
}

func (e *testFirewallExecutor) deleteRule(rule firewallConfig) error {
	if e.deleteErr != nil {
		return e.deleteErr
	}
	delete(e.installed, rule.Name)
	e.deletedRules = append(e.deletedRules, rule)
	return nil
}

func (e *testFirewallExecutor) ruleExists(name string) (bool, error) {
	if e.existsErr != nil {
		return false, e.existsErr
	}
	_, ok := e.installed[name]
	return ok, nil
}

// newTestModule constructs a firewallModule wired to the given test executor.
func newTestModule(exec *testFirewallExecutor) *firewallModule {
	return &firewallModule{
		rules:    make(map[string]firewallConfig),
		executor: exec,
	}
}

// createConfigFromYAML creates a firewallConfig from YAML string.
// It calls t.Fatalf on parse error so callers surface the actual YAML error.
func createConfigFromYAML(t testing.TB, yamlData string) modules.ConfigState {
	t.Helper()
	var config firewallConfig
	if err := yaml.Unmarshal([]byte(yamlData), &config); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\nInput: %s", err, yamlData)
		return nil
	}
	return &config
}

func TestFirewallModule(t *testing.T) {
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
direction: input
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
direction: input
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
direction: input
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
direction: input
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
direction: output
protocol: tcp
port: 8080
source: 0.0.0.0/0
destination: 10.0.0.0/24
enabled: false
`,
			wantErr: false,
		},
		{
			name:       "Forward direction rule",
			resourceID: "forward-rule",
			configData: `
name: forward-rule
action: allow
direction: forward
protocol: tcp
port: 443
source: 192.168.1.0/24
destination: 10.0.0.0/24
enabled: true
`,
			wantErr: false,
		},
		{
			name:       "Invalid protocol",
			resourceID: "invalid-protocol",
			configData: `
name: invalid-protocol
action: allow
direction: input
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
direction: input
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
direction: input
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
direction: input
protocol: tcp
port: 80
source: 0.0.0.0/0
destination: 10.0.0.0/24
enabled: true
`,
			wantErr: true,
		},
		{
			name:       "Invalid direction",
			resourceID: "invalid-direction",
			configData: `
name: invalid-direction
action: allow
direction: sideways
protocol: tcp
port: 80
source: 0.0.0.0/0
destination: 10.0.0.0/24
enabled: true
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := newTestExecutor()
			module := newTestModule(exec)

			configState := createConfigFromYAML(t, tt.configData)

			err := module.Set(context.Background(), tt.resourceID, configState)
			if (err != nil) != tt.wantErr {
				t.Errorf("Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

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
	exec := newTestExecutor()
	module := newTestModule(exec)

	// Test with nil config
	err := module.Set(context.Background(), "test-rule", nil)
	if err == nil {
		t.Error("Set() with nil config should fail")
	}

	// Test Get with non-existent rule
	_, err = module.Get(context.Background(), "non-existent")
	if !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("Get() with non-existent rule error = %v, want %v", err, ErrRuleNotFound)
	}

	// Test successful rule creation and retrieval
	configData := `
name: test-rule
action: allow
direction: input
protocol: tcp
port: 443
source: 192.168.1.0/24
destination: 10.0.0.0/24
description: Test HTTPS rule
enabled: true
`
	configState := createConfigFromYAML(t, configData)

	err = module.Set(context.Background(), "test-rule", configState)
	if err != nil {
		t.Errorf("Set() failed: %v", err)
	}

	retrieved, err := module.Get(context.Background(), "test-rule")
	if err != nil {
		t.Errorf("Get() failed: %v", err)
	}
	if retrieved == nil {
		t.Error("Get() returned nil")
	}

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
	if retrievedMap["direction"] != "input" {
		t.Errorf("Retrieved rule direction = %v, want %v", retrievedMap["direction"], "input")
	}
}

// TestSet_InvokesApplyRule verifies that Set calls applyRule on the executor
// for a valid config.
func TestSet_InvokesApplyRule(t *testing.T) {
	exec := newTestExecutor()
	module := newTestModule(exec)

	configState := createConfigFromYAML(t, `
name: http-rule
action: allow
direction: input
protocol: tcp
port: 80
source: 0.0.0.0/0
destination: 10.0.0.0/24
enabled: true
`)

	if err := module.Set(context.Background(), "http-rule", configState); err != nil {
		t.Fatalf("Set() unexpected error: %v", err)
	}

	if len(exec.appliedRules) != 1 {
		t.Fatalf("expected 1 applyRule call, got %d", len(exec.appliedRules))
	}
	if exec.appliedRules[0].Name != "http-rule" {
		t.Errorf("applyRule called with Name=%q, want %q", exec.appliedRules[0].Name, "http-rule")
	}
}

// TestGet_ReturnsErrRuleNotFound_WhenRuleExistsFalse verifies that Get returns
// ErrRuleNotFound when the executor reports the rule is not installed.
func TestGet_ReturnsErrRuleNotFound_WhenRuleExistsFalse(t *testing.T) {
	exec := newTestExecutor()
	module := newTestModule(exec)

	// Manually insert rule into m.rules without going through the executor,
	// so ruleExists returns false (rule not in exec.installed).
	module.rules["ghost-rule"] = firewallConfig{
		Name:        "ghost-rule",
		Action:      "allow",
		Direction:   "input",
		Protocol:    "tcp",
		Port:        80,
		Source:      "0.0.0.0/0",
		Destination: "10.0.0.0/24",
	}

	_, err := module.Get(context.Background(), "ghost-rule")
	if !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("Get() error = %v, want ErrRuleNotFound", err)
	}
}

// TestSet_InvalidDirection_DoesNotCallApplyRule verifies that Set rejects invalid
// Direction values before reaching the executor.
func TestSet_InvalidDirection_DoesNotCallApplyRule(t *testing.T) {
	exec := newTestExecutor()
	module := newTestModule(exec)

	configState := createConfigFromYAML(t, `
name: bad-dir
action: allow
direction: sideways
protocol: tcp
port: 80
source: 0.0.0.0/0
destination: 10.0.0.0/24
enabled: true
`)

	err := module.Set(context.Background(), "bad-dir", configState)
	if !errors.Is(err, ErrInvalidDirection) {
		t.Errorf("Set() error = %v, want ErrInvalidDirection", err)
	}
	if len(exec.appliedRules) != 0 {
		t.Errorf("applyRule called %d times, want 0", len(exec.appliedRules))
	}
}

// TestSet_ExecutorFailure_DoesNotUpdateRules verifies that when applyRule returns
// an error, m.rules is not updated (write-through cache semantics).
func TestSet_ExecutorFailure_DoesNotUpdateRules(t *testing.T) {
	exec := newTestExecutor()
	exec.applyErr = errors.New("iptables: permission denied")
	module := newTestModule(exec)

	configState := createConfigFromYAML(t, `
name: fail-rule
action: allow
direction: output
protocol: tcp
port: 443
source: 10.0.0.1
destination: 8.8.8.8
enabled: true
`)

	err := module.Set(context.Background(), "fail-rule", configState)
	if err == nil {
		t.Fatal("Set() expected error when executor fails, got nil")
	}

	module.mu.RLock()
	_, exists := module.rules["fail-rule"]
	module.mu.RUnlock()

	if exists {
		t.Error("m.rules updated despite executor failure; write-through cache violated")
	}
}

// TestSet_AbsentState_DeletesRule verifies the deletion path: Set with state=absent
// looks up the rule from m.rules, calls deleteRule, and removes the entry.
func TestSet_AbsentState_DeletesRule(t *testing.T) {
	exec := newTestExecutor()
	module := newTestModule(exec)

	// First, create a rule
	configState := createConfigFromYAML(t, `
name: temp-rule
action: allow
direction: forward
protocol: tcp
port: 8080
source: 192.168.0.0/24
destination: 10.0.0.0/24
enabled: true
`)
	if err := module.Set(context.Background(), "temp-rule", configState); err != nil {
		t.Fatalf("Set() create failed: %v", err)
	}

	// Now delete it via state: absent
	deleteConfig := &firewallConfig{State: "absent"}
	if err := module.Set(context.Background(), "temp-rule", deleteConfig); err != nil {
		t.Fatalf("Set() delete failed: %v", err)
	}

	// Verify rule removed from m.rules
	module.mu.RLock()
	_, exists := module.rules["temp-rule"]
	module.mu.RUnlock()
	if exists {
		t.Error("rule still in m.rules after deletion")
	}

	// Verify deleteRule was called
	if len(exec.deletedRules) != 1 {
		t.Errorf("expected 1 deleteRule call, got %d", len(exec.deletedRules))
	}

	// Verify Get returns ErrRuleNotFound after deletion
	_, err := module.Get(context.Background(), "temp-rule")
	if !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("Get() after deletion error = %v, want ErrRuleNotFound", err)
	}
}

// TestSet_AbsentState_NotFound returns ErrRuleNotFound when deleting a
// rule that was never installed.
func TestSet_AbsentState_NotFound(t *testing.T) {
	exec := newTestExecutor()
	module := newTestModule(exec)

	deleteConfig := &firewallConfig{State: "absent"}
	err := module.Set(context.Background(), "nonexistent", deleteConfig)
	if !errors.Is(err, ErrRuleNotFound) {
		t.Errorf("Set() absent on missing rule = %v, want ErrRuleNotFound", err)
	}
	if len(exec.deletedRules) != 0 {
		t.Errorf("deleteRule called %d times, want 0", len(exec.deletedRules))
	}
}
