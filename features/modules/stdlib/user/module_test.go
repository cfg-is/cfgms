// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package user

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/conformance"
	"github.com/cfgis/cfgms/features/modules/stdlib/file"
	"github.com/cfgis/cfgms/pkg/logging"
)

// currentTestUser returns a username that reliably exists on the current
// platform for read-only conformance testing. It never modifies any account.
func currentTestUser() string {
	switch runtime.GOOS {
	case "windows":
		if u := os.Getenv("USERNAME"); u != "" {
			return u
		}
		return "Administrator"
	default:
		// Linux/macOS: $USER is set by the shell; "root" is the universal fallback.
		if u := os.Getenv("USER"); u != "" {
			return u
		}
		return "root"
	}
}

// TestUserModule_New verifies the module constructor returns a non-nil Module.
func TestUserModule_New(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestUserConfig_Validate covers valid and invalid state values.
func TestUserConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  UserConfig
		wantErr bool
	}{
		{name: "present is valid", config: UserConfig{State: "present"}, wantErr: false},
		{name: "absent is valid", config: UserConfig{State: "absent"}, wantErr: false},
		{name: "empty state is invalid", config: UserConfig{State: ""}, wantErr: true},
		{name: "unknown state is invalid", config: UserConfig{State: "enabled"}, wantErr: true},
		{name: "active state is invalid", config: UserConfig{State: "active"}, wantErr: true},
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

// TestUserConfig_AsMap verifies AsMap returns the expected keys and values,
// and that groups are sorted alphabetically for deterministic output.
func TestUserConfig_AsMap(t *testing.T) {
	tests := []struct {
		name   string
		config UserConfig
		checks map[string]interface{}
	}{
		{
			name:   "present with groups",
			config: UserConfig{State: "present", FullName: "Alice Smith", Groups: []string{"wheel", "audio"}, Locked: false, HasCredential: true},
			checks: map[string]interface{}{
				"state": "present", "full_name": "Alice Smith", "locked": false, "has_credential": true,
			},
		},
		{
			name:   "absent",
			config: UserConfig{State: "absent"},
			checks: map[string]interface{}{"state": "absent", "locked": false, "has_credential": false},
		},
		{
			name:   "locked user",
			config: UserConfig{State: "present", Locked: true},
			checks: map[string]interface{}{"state": "present", "locked": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.config.AsMap()
			for k, want := range tt.checks {
				got, ok := m[k]
				if !ok {
					t.Errorf("AsMap() missing key %q", k)
					continue
				}
				if got != want {
					t.Errorf("AsMap()[%q] = %v, want %v", k, got, want)
				}
			}
			// Required keys must always be present.
			for _, required := range []string{"state", "full_name", "groups", "locked", "has_credential"} {
				if _, ok := m[required]; !ok {
					t.Errorf("AsMap() missing required key %q", required)
				}
			}
		})
	}
}

// TestUserConfig_AsMap_GroupsAreSorted verifies that AsMap() sorts groups
// alphabetically regardless of the input order, ensuring determinism.
func TestUserConfig_AsMap_GroupsAreSorted(t *testing.T) {
	c := &UserConfig{
		State:  "present",
		Groups: []string{"wheel", "audio", "adm", "docker"},
	}
	m := c.AsMap()
	groups, ok := m["groups"].([]string)
	if !ok {
		t.Fatal("AsMap() groups is not []string")
	}
	expected := []string{"adm", "audio", "docker", "wheel"}
	if len(groups) != len(expected) {
		t.Fatalf("groups length: got %d, want %d", len(groups), len(expected))
	}
	for i, g := range groups {
		if g != expected[i] {
			t.Errorf("groups[%d] = %q, want %q", i, g, expected[i])
		}
	}
}

// TestUserConfig_YAMLRoundTrip verifies ToYAML and FromYAML are inverse operations.
func TestUserConfig_YAMLRoundTrip(t *testing.T) {
	original := &UserConfig{
		State:         "present",
		FullName:      "Test User",
		Groups:        []string{"users", "wheel"},
		Locked:        false,
		HasCredential: true,
	}
	data, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error: %v", err)
	}
	decoded := &UserConfig{}
	if err := decoded.FromYAML(data); err != nil {
		t.Fatalf("FromYAML() error: %v", err)
	}
	if decoded.State != original.State {
		t.Errorf("State: got %q, want %q", decoded.State, original.State)
	}
	if decoded.FullName != original.FullName {
		t.Errorf("FullName: got %q, want %q", decoded.FullName, original.FullName)
	}
	if len(decoded.Groups) != len(original.Groups) {
		t.Errorf("Groups length: got %d, want %d", len(decoded.Groups), len(original.Groups))
	}
	if decoded.Locked != original.Locked {
		t.Errorf("Locked: got %v, want %v", decoded.Locked, original.Locked)
	}
	if decoded.HasCredential != original.HasCredential {
		t.Errorf("HasCredential: got %v, want %v", decoded.HasCredential, original.HasCredential)
	}
}

// TestUserConfig_GetManagedFields verifies has_credential is absent from managed fields
// (it is observed-only and must never be set by this module).
func TestUserConfig_GetManagedFields(t *testing.T) {
	c := &UserConfig{State: "present"}
	fields := c.GetManagedFields()
	required := map[string]bool{"state": false, "full_name": false, "groups": false, "locked": false}
	for _, f := range fields {
		required[f] = true
	}
	for field, found := range required {
		if !found {
			t.Errorf("GetManagedFields() missing required field %q", field)
		}
	}
	// has_credential must NOT appear in managed fields.
	for _, f := range fields {
		if f == "has_credential" {
			t.Error("GetManagedFields() must not include has_credential (observed-only field)")
		}
	}
}

// TestUserModule_Get_InvalidResourceID verifies Get rejects an empty resource ID.
func TestUserModule_Get_InvalidResourceID(t *testing.T) {
	m := New()
	_, err := m.Get(context.Background(), "")
	if err == nil {
		t.Error("Get() with empty resource ID must return an error")
	}
}

// TestUserModule_Get_InvalidUsername verifies Get rejects unsafe usernames.
func TestUserModule_Get_InvalidUsername(t *testing.T) {
	m := New()
	ctx := context.Background()
	invalidNames := []string{
		"--help",           // flag injection
		"user; rm -rf /",   // command injection
		"user with spaces", // spaces not allowed
		"user\x00null",     // null byte
		"../etc/passwd",    // path traversal
		"",                 // empty
		"user\n",           // newline injection
	}
	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			_, err := m.Get(ctx, name)
			if err == nil {
				t.Errorf("Get(%q) must return an error for invalid username", name)
			}
		})
	}
}

// TestUserModule_Set_InvalidInputs verifies Set rejects empty resource IDs and nil configs.
func TestUserModule_Set_InvalidInputs(t *testing.T) {
	m := New()
	ctx := context.Background()
	validConfig := &UserConfig{State: "present"}

	if err := m.Set(ctx, "", validConfig); err == nil {
		t.Error("Set() with empty resource ID must return an error")
	}
	if err := m.Set(ctx, "alice", nil); err == nil {
		t.Error("Set() with nil config must return an error")
	}
}

// TestUserModule_Set_RejectsNonUserConfig verifies Set returns ErrInvalidInput when
// passed a real ConfigState from a different module (the file module's *FileConfig)
// rather than a *UserConfig. Using a real CFGMS component here — not a stub — exercises
// the type-assertion guard in Set the same way a genuine cross-module misconfiguration would.
func TestUserModule_Set_RejectsNonUserConfig(t *testing.T) {
	m := New()
	foreignConfig := &file.FileConfig{State: "present", AllowedBasePath: t.TempDir()}
	err := m.Set(context.Background(), "alice", foreignConfig)
	if err == nil {
		t.Fatal("Set() must return an error for non-*UserConfig ConfigState")
	}
	if !errors.Is(err, modules.ErrInvalidInput) {
		t.Errorf("Set() error = %v; want errors.Is(err, modules.ErrInvalidInput)", err)
	}
}

// TestUserModule_Set_InvalidUsername verifies Set rejects unsafe usernames.
func TestUserModule_Set_InvalidUsername(t *testing.T) {
	m := New()
	ctx := context.Background()
	validConfig := &UserConfig{State: "present"}
	invalidNames := []string{
		"--user",         // flag injection
		"user && reboot", // shell command chaining
		"user\nother",    // newline injection
	}
	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			err := m.Set(ctx, name, validConfig)
			if err == nil {
				t.Errorf("Set(%q) must return an error for invalid username", name)
			}
		})
	}
}

// TestUserModule_Set_InvalidState verifies Set rejects configs with invalid state values.
func TestUserModule_Set_InvalidState(t *testing.T) {
	m := New()
	ctx := context.Background()
	badConfig := &UserConfig{State: "enabled"}
	if err := m.Set(ctx, "alice", badConfig); err == nil {
		t.Error("Set() with invalid state must return an error")
	}
}

// TestUserModule_Set_InvalidFullName verifies Set rejects full names containing
// control characters or colons (GECOS-field safety, defense-in-depth).
func TestUserModule_Set_InvalidFullName(t *testing.T) {
	m := New()
	ctx := context.Background()
	for _, bad := range []string{"name\nother", "name\r", "name:extra", "name\x00null"} {
		t.Run(bad, func(t *testing.T) {
			cfg := &UserConfig{State: "present", FullName: bad}
			if err := m.Set(ctx, "alice", cfg); err == nil {
				t.Errorf("Set() with full_name %q must return an error", bad)
			}
		})
	}
}

// TestUserModule_Set_InvalidGroupName verifies Set rejects configs with unsafe group names.
func TestUserModule_Set_InvalidGroupName(t *testing.T) {
	m := New()
	ctx := context.Background()
	badConfig := &UserConfig{
		State:  "present",
		Groups: []string{"valid-group", "bad group; rm -rf /"},
	}
	if err := m.Set(ctx, "alice", badConfig); err == nil {
		t.Error("Set() with invalid group name must return an error")
	}
}

// TestValidateUsername verifies the username validation function directly.
func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple lowercase", "alice", false},
		{"with hyphen", "test-user", false},
		{"with underscore", "test_user", false},
		{"with dot", "test.user", false},
		{"starts with underscore", "_daemon", false},
		{"uppercase allowed", "Alice", false},
		{"numeric suffix", "user1", false},
		{"empty", "", true},
		{"starts with digit", "1user", true},
		{"starts with hyphen", "-user", true},
		{"spaces", "user name", true},
		{"semicolon", "user;reboot", true},
		{"ampersand", "user&&evil", true},
		{"null byte", "user\x00", true},
		{"newline", "user\n", true},
		{"path traversal", "../etc/passwd", true},
		{"flag injection", "--help", true},
		{"too long", "a" + string(make([]byte, 32)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUsername(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// TestUserModule_LoggingInjection verifies the module implements LoggingInjectable.
func TestUserModule_LoggingInjection(t *testing.T) {
	m := New()
	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("New() must return a value implementing modules.LoggingInjectable")
	}
	_, injected := injectable.GetLogger()
	if injected {
		t.Error("GetLogger() must return injected=false before SetLogger is called")
	}
	testLogger := logging.ForModule("user-test")
	if err := injectable.SetLogger(testLogger); err != nil {
		t.Fatalf("SetLogger() returned unexpected error: %v", err)
	}
	got, injected := injectable.GetLogger()
	if !injected {
		t.Error("GetLogger() must return injected=true after SetLogger succeeds")
	}
	if got == nil {
		t.Error("GetLogger() must return a non-nil logger after SetLogger")
	}
	if err := injectable.SetLogger(nil); err == nil {
		t.Error("SetLogger(nil) must return an error")
	}
}

// TestUserModule_ConformanceDeterministicGet verifies that Get() produces
// byte-for-byte identical output on consecutive calls (ADR-016 clause 4).
// Uses an existing account (the current user) so no write privileges are needed.
func TestUserModule_ConformanceDeterministicGet(t *testing.T) {
	username := currentTestUser()
	m := New()
	state, err := m.Get(context.Background(), username)
	if err != nil {
		if errors.Is(err, modules.ErrUnsupportedPlatform) {
			t.Skipf("skipping conformance test: Get(%q) unsupported on this platform: %v", username, err)
		}
		t.Fatalf("Get(%q) returned unexpected error: %v", username, err)
	}
	if state == nil {
		t.Fatalf("Get(%q) returned nil state with nil error; Get must return a non-nil ConfigState on success", username)
	}
	conformance.AssertDeterministicGet(t, m, username)
}

// TestUserModule_ConformanceNoEphemeralFields verifies that the UserConfig
// returned by Get() contains no banned ephemeral fields (ADR-016 clause 4).
func TestUserModule_ConformanceNoEphemeralFields(t *testing.T) {
	username := currentTestUser()
	m := New()
	state, err := m.Get(context.Background(), username)
	if err != nil {
		if errors.Is(err, modules.ErrUnsupportedPlatform) {
			t.Skipf("skipping: Get(%q) unsupported on this platform: %v", username, err)
		}
		t.Fatalf("Get(%q) returned unexpected error: %v", username, err)
	}
	if state == nil {
		t.Fatalf("Get(%q) returned nil state with nil error; Get must return a non-nil ConfigState on success", username)
	}
	conformance.AssertNoEphemeralFields(t, state, conformance.DefaultBannedEphemeralFields)
}

// TestUserModule_HasCredential_NotAcceptedBySet verifies that has_credential in a
// config passed to Set() is silently ignored — the module never writes password
// material.
func TestUserModule_HasCredential_NotAcceptedBySet(t *testing.T) {
	// Build a config that has has_credential=true in its AsMap().
	cfg := &UserConfig{
		State:         "absent",
		HasCredential: true,
	}
	// Verify AsMap contains has_credential so this is a real test.
	m := cfg.AsMap()
	if m["has_credential"] != true {
		t.Fatal("test precondition: has_credential must be true in AsMap()")
	}

	// Set() on a module backed by the real executor (which requires root for
	// absent→present, but present→absent of a non-existent user is a no-op)
	// should not error on the has_credential field itself.
	mod := New()
	ctx := context.Background()
	err := mod.Set(ctx, "cfgms-test-noop-user", cfg)
	// We don't assert err==nil here because the executor may error if the user
	// doesn't exist and we're not root. What matters is that the error is NOT
	// about has_credential being supplied.
	if err != nil {
		// Acceptable errors: permission denied, user not found, platform errors.
		// Unacceptable: any error mentioning has_credential as an invalid field.
		errStr := err.Error()
		for _, bad := range []string{"has_credential", "password material", "invalid field password"} {
			if strings.Contains(errStr, bad) {
				t.Errorf("Set() rejected has_credential field with error %q — it must be silently ignored", errStr)
			}
		}
	}
}
