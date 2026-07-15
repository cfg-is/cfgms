// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hostname

import (
	"context"
	"errors"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/conformance"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestHostnameModule_New verifies the module constructor returns a non-nil Module.
func TestHostnameModule_New(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestHostnameConfig_Validate covers valid and invalid configurations.
func TestHostnameConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  HostnameConfig
		wantErr bool
	}{
		{
			name:    "simple hostname is valid",
			config:  HostnameConfig{Hostname: "myhost"},
			wantErr: false,
		},
		{
			name:    "hostname with hyphen is valid",
			config:  HostnameConfig{Hostname: "my-host"},
			wantErr: false,
		},
		{
			name:    "hostname with digits is valid",
			config:  HostnameConfig{Hostname: "host01"},
			wantErr: false,
		},
		{
			name:    "empty hostname is invalid",
			config:  HostnameConfig{Hostname: ""},
			wantErr: true,
		},
		{
			name:    "hostname with leading hyphen is invalid",
			config:  HostnameConfig{Hostname: "-badhost"},
			wantErr: true,
		},
		{
			name:    "hostname with trailing hyphen is invalid",
			config:  HostnameConfig{Hostname: "badhost-"},
			wantErr: true,
		},
		{
			name:    "hostname with space is invalid",
			config:  HostnameConfig{Hostname: "bad host"},
			wantErr: true,
		},
		{
			name:    "hostname with newline injection is invalid",
			config:  HostnameConfig{Hostname: "host\nevil"},
			wantErr: true,
		},
		{
			name:    "valid hostname with workgroup is valid",
			config:  HostnameConfig{Hostname: "myhost", Workgroup: "WORKGROUP"},
			wantErr: false,
		},
		{
			name:    "workgroup with special chars is invalid",
			config:  HostnameConfig{Hostname: "myhost", Workgroup: "WORK GROUP"},
			wantErr: true,
		},
		{
			name:    "workgroup too long is invalid",
			config:  HostnameConfig{Hostname: "myhost", Workgroup: "TOOLONGWORKGROUP"},
			wantErr: true,
		},
		{
			name:    "workgroup with hyphen and underscore is valid",
			config:  HostnameConfig{Hostname: "myhost", Workgroup: "MY_WG-1"},
			wantErr: false,
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

// TestHostnameConfig_AsMap verifies AsMap returns expected keys and values.
func TestHostnameConfig_AsMap(t *testing.T) {
	t.Run("hostname only (no workgroup)", func(t *testing.T) {
		cfg := &HostnameConfig{Hostname: "myhost"}
		m := cfg.AsMap()

		got, ok := m["hostname"]
		if !ok {
			t.Error("AsMap() missing key \"hostname\"")
		} else if got != "myhost" {
			t.Errorf("AsMap()[\"hostname\"] = %v, want \"myhost\"", got)
		}

		if _, ok := m["workgroup"]; ok {
			t.Error("AsMap() must not include \"workgroup\" when empty (Linux/macOS fragment)")
		}
	})

	t.Run("hostname with workgroup (Windows fragment)", func(t *testing.T) {
		cfg := &HostnameConfig{Hostname: "myhost", Workgroup: "WORKGROUP"}
		m := cfg.AsMap()

		if got := m["hostname"]; got != "myhost" {
			t.Errorf("AsMap()[\"hostname\"] = %v, want \"myhost\"", got)
		}
		if got := m["workgroup"]; got != "WORKGROUP" {
			t.Errorf("AsMap()[\"workgroup\"] = %v, want \"WORKGROUP\"", got)
		}
	})
}

// TestHostnameConfig_AsMap_WorkgroupAbsentWhenEmpty verifies the key is
// completely absent (not an empty string) when workgroup is unset — this
// prevents a spurious cross-platform field-presence difference in DNA
// fragments (ADR-016 clause 4).
func TestHostnameConfig_AsMap_WorkgroupAbsentWhenEmpty(t *testing.T) {
	cfg := &HostnameConfig{Hostname: "server01", Workgroup: ""}
	m := cfg.AsMap()
	if _, ok := m["workgroup"]; ok {
		t.Error("AsMap() must not include workgroup key when Workgroup is empty")
	}
}

// TestHostnameConfig_YAMLRoundTrip verifies ToYAML and FromYAML are inverse operations.
func TestHostnameConfig_YAMLRoundTrip(t *testing.T) {
	original := &HostnameConfig{
		Hostname:  "webserver-01",
		Workgroup: "CORP",
	}

	data, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error: %v", err)
	}

	decoded := &HostnameConfig{}
	if err := decoded.FromYAML(data); err != nil {
		t.Fatalf("FromYAML() error: %v", err)
	}

	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname: got %q, want %q", decoded.Hostname, original.Hostname)
	}
	if decoded.Workgroup != original.Workgroup {
		t.Errorf("Workgroup: got %q, want %q", decoded.Workgroup, original.Workgroup)
	}
}

// TestHostnameConfig_GetManagedFields verifies the fields reported as managed.
func TestHostnameConfig_GetManagedFields(t *testing.T) {
	config := &HostnameConfig{Hostname: "myhost"}
	fields := config.GetManagedFields()

	required := map[string]bool{
		"hostname":  false,
		"workgroup": false,
	}
	for _, f := range fields {
		required[f] = true
	}
	for field, found := range required {
		if !found {
			t.Errorf("GetManagedFields() missing required field %q", field)
		}
	}
}

// TestHostnameModule_Get_EmptyResourceID verifies Get rejects an empty resource ID.
func TestHostnameModule_Get_EmptyResourceID(t *testing.T) {
	m := New()
	_, err := m.Get(context.Background(), "")
	if err == nil {
		t.Error("Get() with empty resource ID must return an error")
	}
}

// TestHostnameModule_Set_InvalidInputs verifies Set rejects empty resource IDs and nil configs.
func TestHostnameModule_Set_InvalidInputs(t *testing.T) {
	m := New()
	ctx := context.Background()

	validConfig := &HostnameConfig{Hostname: "myhost"}

	if err := m.Set(ctx, "", validConfig); err == nil {
		t.Error("Set() with empty resource ID must return an error")
	}

	if err := m.Set(ctx, "system", nil); err == nil {
		t.Error("Set() with nil config must return an error")
	}
}

// TestHostnameModule_Set_InvalidHostname verifies Set rejects configs with an empty hostname.
func TestHostnameModule_Set_InvalidHostname(t *testing.T) {
	m := New()
	ctx := context.Background()

	badConfig := &HostnameConfig{Hostname: ""}
	if err := m.Set(ctx, "system", badConfig); err == nil {
		t.Error("Set() with empty hostname must return an error")
	}
}

// TestHostnameModule_Set_WrongConfigType verifies Set rejects configs of the wrong type.
func TestHostnameModule_Set_WrongConfigType(t *testing.T) {
	m := New()
	ctx := context.Background()

	wrongCfg := &wrongConfigType{}
	if err := m.Set(ctx, "system", wrongCfg); err == nil {
		t.Error("Set() with wrong config type must return an error")
	}
}

// wrongConfigType implements modules.ConfigState but is not *HostnameConfig.
type wrongConfigType struct{}

func (w *wrongConfigType) AsMap() map[string]interface{}  { return nil }
func (w *wrongConfigType) ToYAML() ([]byte, error)        { return nil, nil }
func (w *wrongConfigType) FromYAML(_ []byte) error        { return nil }
func (w *wrongConfigType) Validate() error                { return nil }
func (w *wrongConfigType) GetManagedFields() []string     { return nil }

// TestHostnameModule_LoggingInjection verifies the module implements LoggingInjectable.
func TestHostnameModule_LoggingInjection(t *testing.T) {
	m := New()

	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("New() must return a value implementing modules.LoggingInjectable")
	}

	_, injected := injectable.GetLogger()
	if injected {
		t.Error("GetLogger() must return injected=false before SetLogger is called")
	}

	testLogger := logging.ForModule("hostname-test")
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

// TestHostnameModule_ConformanceDeterministicGet verifies that Get produces
// byte-for-byte identical output on consecutive calls (ADR-016 clause 4).
func TestHostnameModule_ConformanceDeterministicGet(t *testing.T) {
	m := New()
	state, err := m.Get(context.Background(), "system")
	if err != nil {
		if errors.Is(err, modules.ErrUnsupportedPlatform) {
			t.Skipf("skipping conformance test: Get unsupported on this platform: %v", err)
		}
		t.Fatalf("Get(\"system\") returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("Get(\"system\") returned nil state with nil error")
	}
	conformance.AssertDeterministicGet(t, m, "system")
}

// TestHostnameModule_ConformanceNoEphemeralFields verifies that HostnameConfig
// returned by Get() contains no banned ephemeral fields (ADR-016 clause 4).
func TestHostnameModule_ConformanceNoEphemeralFields(t *testing.T) {
	m := New()
	state, err := m.Get(context.Background(), "system")
	if err != nil {
		if errors.Is(err, modules.ErrUnsupportedPlatform) {
			t.Skipf("skipping: Get unsupported on this platform: %v", err)
		}
		t.Fatalf("Get(\"system\") returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("Get(\"system\") returned nil state with nil error")
	}
	conformance.AssertNoEphemeralFields(t, state, conformance.DefaultBannedEphemeralFields)
}
