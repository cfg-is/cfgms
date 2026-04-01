// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"os/exec"
	"runtime"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// initSystemAvailable returns true when the platform init system (systemd,
// launchctl, SCM) is accessible to the test process. Service management tests
// that interact with the OS service manager are skipped when this returns false.
//
// Justification for skip: starting/stopping/enabling OS services requires
// a running init system and elevated privileges. These conditions are not
// present in CI containers without systemd. Config-layer tests run regardless.
func initSystemAvailable() bool {
	switch runtime.GOOS {
	case "linux":
		// systemctl list-units succeeds only when systemd is PID 1 and the
		// session bus is reachable. Exit 0 = systemd is running.
		return exec.Command("systemctl", "list-units", "--no-pager", "--quiet").Run() == nil
	case "darwin":
		return exec.Command("launchctl", "list").Run() == nil
	case "windows":
		return exec.Command("sc", "query", "type=", "all").Run() == nil
	default:
		return false
	}
}

// TestServiceModule_New verifies the module constructor returns a non-nil Module.
func TestServiceModule_New(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestServiceConfig_Validate covers the Validate() method for all valid and
// invalid state values without making any OS calls.
func TestServiceConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ServiceConfig
		wantErr bool
	}{
		{
			name:    "running state is valid",
			config:  ServiceConfig{State: "running", Enabled: true},
			wantErr: false,
		},
		{
			name:    "stopped state is valid",
			config:  ServiceConfig{State: "stopped", Enabled: false},
			wantErr: false,
		},
		{
			name:    "stopped with enabled true is valid",
			config:  ServiceConfig{State: "stopped", Enabled: true},
			wantErr: false,
		},
		{
			name:    "running with enabled false is valid",
			config:  ServiceConfig{State: "running", Enabled: false},
			wantErr: false,
		},
		{
			name:    "empty state is invalid",
			config:  ServiceConfig{State: ""},
			wantErr: true,
		},
		{
			name:    "unknown state is invalid",
			config:  ServiceConfig{State: "started"},
			wantErr: true,
		},
		{
			name:    "restarting state is invalid",
			config:  ServiceConfig{State: "restarting"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestServiceConfig_AsMap verifies AsMap returns the expected keys and values.
func TestServiceConfig_AsMap(t *testing.T) {
	tests := []struct {
		name     string
		config   ServiceConfig
		wantKeys []string
		checks   map[string]interface{}
	}{
		{
			name:     "running enabled",
			config:   ServiceConfig{State: "running", Enabled: true},
			wantKeys: []string{"state", "enabled"},
			checks:   map[string]interface{}{"state": "running", "enabled": true},
		},
		{
			name:     "stopped disabled",
			config:   ServiceConfig{State: "stopped", Enabled: false},
			wantKeys: []string{"state", "enabled"},
			checks:   map[string]interface{}{"state": "stopped", "enabled": false},
		},
		{
			name:     "empty state defaults to stopped",
			config:   ServiceConfig{State: "", Enabled: false},
			wantKeys: []string{"state", "enabled"},
			checks:   map[string]interface{}{"state": "stopped", "enabled": false},
		},
		{
			name:     "empty state with enabled true defaults to stopped",
			config:   ServiceConfig{State: "", Enabled: true},
			wantKeys: []string{"state", "enabled"},
			checks:   map[string]interface{}{"state": "stopped", "enabled": true},
		},
		{
			name:     "restart_on is excluded from map",
			config:   ServiceConfig{State: "running", Enabled: true, RestartOn: "some-resource"},
			wantKeys: []string{"state", "enabled"},
			checks:   map[string]interface{}{"state": "running", "enabled": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.config.AsMap()
			for k, wantV := range tt.checks {
				got, ok := m[k]
				if !ok {
					t.Errorf("AsMap() missing key %q", k)
					continue
				}
				if got != wantV {
					t.Errorf("AsMap()[%q] = %v, want %v", k, got, wantV)
				}
			}
			// RestartOn must never appear in the map.
			if _, found := m["restart_on"]; found {
				t.Error("AsMap() must not include restart_on (dependency hint, not observable state)")
			}
		})
	}
}

// TestServiceConfig_YAMLRoundTrip verifies ToYAML and FromYAML are inverse operations.
func TestServiceConfig_YAMLRoundTrip(t *testing.T) {
	original := &ServiceConfig{
		State:     "running",
		Enabled:   true,
		RestartOn: "my-config-file",
	}

	data, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error: %v", err)
	}

	decoded := &ServiceConfig{}
	if err := decoded.FromYAML(data); err != nil {
		t.Fatalf("FromYAML() error: %v", err)
	}

	if decoded.State != original.State {
		t.Errorf("State: got %q, want %q", decoded.State, original.State)
	}
	if decoded.Enabled != original.Enabled {
		t.Errorf("Enabled: got %v, want %v", decoded.Enabled, original.Enabled)
	}
	if decoded.RestartOn != original.RestartOn {
		t.Errorf("RestartOn: got %q, want %q", decoded.RestartOn, original.RestartOn)
	}
}

// TestServiceConfig_GetManagedFields verifies the fields reported as managed.
func TestServiceConfig_GetManagedFields(t *testing.T) {
	config := &ServiceConfig{State: "running", Enabled: true}
	fields := config.GetManagedFields()

	required := map[string]bool{"state": false, "enabled": false}
	for _, f := range fields {
		required[f] = true
	}
	for field, found := range required {
		if !found {
			t.Errorf("GetManagedFields() missing required field %q", field)
		}
	}
}

// TestServiceModule_Get_InvalidResourceID verifies Get rejects an empty resource ID.
func TestServiceModule_Get_InvalidResourceID(t *testing.T) {
	m := New()
	_, err := m.Get(context.Background(), "")
	if err == nil {
		t.Error("Get() with empty resource ID must return an error")
	}
}

// TestServiceModule_Get_InvalidServiceName verifies Get rejects names with unsafe characters.
func TestServiceModule_Get_InvalidServiceName(t *testing.T) {
	m := New()
	ctx := context.Background()

	invalidNames := []string{
		"--force",           // flag injection attempt
		"service; rm -rf /", // command injection attempt
		"svc with spaces",   // spaces not allowed
		"svc\x00null",       // null byte
		"../etc/passwd",     // path traversal
	}

	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			_, err := m.Get(ctx, name)
			if err == nil {
				t.Errorf("Get(%q) must return an error for invalid service name", name)
			}
		})
	}
}

// TestServiceModule_Set_InvalidInputs verifies Set rejects empty resource IDs and nil configs.
func TestServiceModule_Set_InvalidInputs(t *testing.T) {
	m := New()
	ctx := context.Background()

	validConfig := &ServiceConfig{State: "running", Enabled: true}

	if err := m.Set(ctx, "", validConfig); err == nil {
		t.Error("Set() with empty resource ID must return an error")
	}

	if err := m.Set(ctx, "some-service", nil); err == nil {
		t.Error("Set() with nil config must return an error")
	}
}

// TestServiceModule_Set_InvalidServiceName verifies Set rejects names with unsafe characters.
func TestServiceModule_Set_InvalidServiceName(t *testing.T) {
	m := New()
	ctx := context.Background()
	validConfig := &ServiceConfig{State: "running", Enabled: true}

	invalidNames := []string{
		"--user",        // flag injection
		"svc && reboot", // shell command chaining
		"svc\nother",    // newline injection
	}

	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			err := m.Set(ctx, name, validConfig)
			if err == nil {
				t.Errorf("Set(%q) must return an error for invalid service name", name)
			}
		})
	}
}

// TestServiceModule_Set_InvalidState verifies Set rejects configs with invalid state values.
func TestServiceModule_Set_InvalidState(t *testing.T) {
	m := New()
	ctx := context.Background()

	badConfig := &ServiceConfig{State: "invalid-state"}
	if err := m.Set(ctx, "some-service", badConfig); err == nil {
		t.Error("Set() with invalid state must return an error")
	}
}

// TestValidateServiceName verifies the service name validation function directly.
func TestValidateServiceName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple name", "cfgms-controller", false},
		{"with dots", "com.cfgms.controller", false},
		{"with underscore", "cfgms_controller", false},
		{"with at sign", "getty@tty1", false},
		{"numeric", "123service", false},
		{"max length boundary", "a" + func() string {
			b := make([]byte, 254)
			for i := range b {
				b[i] = 'a'
			}
			return string(b)
		}(), false},
		{"empty", "", true},
		{"starts with dash", "-cfgms", true},
		{"starts with dot", ".hidden", true},
		{"spaces", "my service", true},
		{"semicolon", "svc;reboot", true},
		{"ampersand", "svc&&evil", true},
		{"dollar sign", "$PATH", true},
		{"backtick", "`whoami`", true},
		{"null byte", "svc\x00", true},
		{"newline", "svc\n", true},
		{"path traversal", "../etc/passwd", true},
		{"flag injection", "--force", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServiceName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateServiceName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// TestServiceModule_Get_NonExistentService verifies that querying a non-existent service
// returns a stopped/disabled state rather than an error, when the init system is available.
// This mirrors the file module's behaviour of returning State: "absent" for missing files.
func TestServiceModule_Get_NonExistentService(t *testing.T) {
	if !initSystemAvailable() {
		t.Skip("skipping: OS service manager is not available (no running init system); " +
			"this is expected in containers without systemd/launchd/SCM")
	}

	m := New()
	// Use a name that will never exist on any real system.
	const phantomService = "cfgms-test-phantom-service-xyzzy"
	state, err := m.Get(context.Background(), phantomService)
	if err != nil {
		t.Fatalf("Get() on non-existent service returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("Get() returned nil state for non-existent service")
	}

	m2 := state.AsMap()
	if s, ok := m2["state"].(string); !ok || s != "stopped" {
		t.Errorf("expected state='stopped' for non-existent service, got %v", m2["state"])
	}
	if e, ok := m2["enabled"].(bool); !ok || e {
		t.Errorf("expected enabled=false for non-existent service, got %v", m2["enabled"])
	}
}

// TestServiceModule_Set_NonExistentService verifies that Set returns an error when
// applied to a non-existent service, when the init system is available.
func TestServiceModule_Set_NonExistentService(t *testing.T) {
	if !initSystemAvailable() {
		t.Skip("skipping: OS service manager is not available (no running init system); " +
			"this is expected in containers without systemd/launchd/SCM")
	}

	m := New()
	const phantomService = "cfgms-test-phantom-service-xyzzy"
	config := &ServiceConfig{State: "running", Enabled: true}

	// Attempting to start or enable a non-existent service must fail.
	err := m.Set(context.Background(), phantomService, config)
	if err == nil {
		t.Error("Set() on a non-existent service must return an error")
	}
}

// TestServiceModule_LoggingInjection verifies the module implements LoggingInjectable
// and that SetLogger actually stores the logger for use by subsequent operations.
func TestServiceModule_LoggingInjection(t *testing.T) {
	m := New()

	// The module must implement LoggingInjectable via DefaultLoggingSupport.
	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("New() must return a value implementing modules.LoggingInjectable")
	}

	// Before injection, GetLogger should report no injected logger.
	_, injected := injectable.GetLogger()
	if injected {
		t.Error("GetLogger() must return injected=false before SetLogger is called")
	}

	// Inject a real logger and verify the injection succeeds.
	testLogger := logging.ForModule("service-test")
	if err := injectable.SetLogger(testLogger); err != nil {
		t.Fatalf("SetLogger() returned unexpected error: %v", err)
	}

	// After injection, GetLogger must return the injected logger.
	got, injected := injectable.GetLogger()
	if !injected {
		t.Error("GetLogger() must return injected=true after SetLogger succeeds")
	}
	if got == nil {
		t.Error("GetLogger() must return a non-nil logger after SetLogger")
	}

	// SetLogger with nil must return an error (DefaultLoggingSupport contract).
	if err := injectable.SetLogger(nil); err == nil {
		t.Error("SetLogger(nil) must return an error")
	}
}
