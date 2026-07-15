// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package timemodule

import (
	"context"
	"errors"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/conformance"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestTimeModule_New verifies the module constructor returns a non-nil Module.
func TestTimeModule_New(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestTimeConfig_Validate covers valid and invalid configurations.
func TestTimeConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  TimeConfig
		wantErr bool
	}{
		{
			name:    "UTC timezone is valid",
			config:  TimeConfig{Timezone: "UTC"},
			wantErr: false,
		},
		{
			name:    "IANA timezone is valid",
			config:  TimeConfig{Timezone: "America/Chicago", NTPSyncEnabled: true},
			wantErr: false,
		},
		{
			name:    "with NTP servers is valid",
			config:  TimeConfig{Timezone: "Europe/London", NTPServers: []string{"pool.ntp.org"}, NTPSyncEnabled: true},
			wantErr: false,
		},
		{
			name:    "empty timezone is invalid",
			config:  TimeConfig{Timezone: ""},
			wantErr: true,
		},
		{
			name:    "NTP disabled with no servers is valid",
			config:  TimeConfig{Timezone: "UTC", NTPSyncEnabled: false},
			wantErr: false,
		},
		{
			name:    "timezone with leading dash is invalid",
			config:  TimeConfig{Timezone: "-invalidzone"},
			wantErr: true,
		},
		{
			name:    "timezone with newline injection is invalid",
			config:  TimeConfig{Timezone: "UTC\nmalicious"},
			wantErr: true,
		},
		{
			name:    "NTP server with newline is invalid",
			config:  TimeConfig{Timezone: "UTC", NTPServers: []string{"pool.ntp.org\nevil"}},
			wantErr: true,
		},
		{
			name:    "NTP server with leading dash is invalid",
			config:  TimeConfig{Timezone: "UTC", NTPServers: []string{"-badserver"}},
			wantErr: true,
		},
		{
			name:    "Etc/GMT+5 timezone is valid",
			config:  TimeConfig{Timezone: "Etc/GMT+5"},
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

// TestTimeConfig_AsMap verifies AsMap returns the expected keys and values,
// with NTPServers sorted for determinism.
func TestTimeConfig_AsMap(t *testing.T) {
	tests := []struct {
		name   string
		config TimeConfig
		checks map[string]interface{}
	}{
		{
			name: "basic config",
			config: TimeConfig{
				Timezone:       "UTC",
				NTPServers:     []string{"pool.ntp.org"},
				NTPSyncEnabled: true,
			},
			checks: map[string]interface{}{
				"timezone":         "UTC",
				"ntp_sync_enabled": true,
			},
		},
		{
			name: "servers are sorted",
			config: TimeConfig{
				Timezone:       "America/New_York",
				NTPServers:     []string{"z.pool.ntp.org", "a.pool.ntp.org"},
				NTPSyncEnabled: true,
			},
			checks: map[string]interface{}{
				"timezone":         "America/New_York",
				"ntp_sync_enabled": true,
			},
		},
		{
			name: "ntp disabled",
			config: TimeConfig{
				Timezone:       "UTC",
				NTPSyncEnabled: false,
			},
			checks: map[string]interface{}{
				"timezone":         "UTC",
				"ntp_sync_enabled": false,
			},
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
			// ntp_servers must always be present and be a sorted slice.
			servers, ok := m["ntp_servers"]
			if !ok {
				t.Error("AsMap() missing key \"ntp_servers\"")
			} else {
				sl, ok := servers.([]string)
				if !ok {
					t.Errorf("AsMap()[\"ntp_servers\"] is %T, want []string", servers)
				} else {
					for i := 1; i < len(sl); i++ {
						if sl[i] < sl[i-1] {
							t.Errorf("AsMap()[\"ntp_servers\"] is not sorted: %v", sl)
							break
						}
					}
				}
			}
		})
	}
}

// TestTimeConfig_AsMap_ServerSortingIsDeterministic verifies that AsMap with
// an unsorted input always returns sorted output.
func TestTimeConfig_AsMap_ServerSortingIsDeterministic(t *testing.T) {
	cfg := &TimeConfig{
		Timezone:       "UTC",
		NTPServers:     []string{"z.ntp.org", "a.ntp.org", "m.ntp.org"},
		NTPSyncEnabled: true,
	}
	m1 := cfg.AsMap()
	m2 := cfg.AsMap()

	sl1 := m1["ntp_servers"].([]string)
	sl2 := m2["ntp_servers"].([]string)

	if len(sl1) != len(sl2) {
		t.Fatalf("server list length differs: %d vs %d", len(sl1), len(sl2))
	}
	for i := range sl1 {
		if sl1[i] != sl2[i] {
			t.Errorf("server[%d] differs: %q vs %q", i, sl1[i], sl2[i])
		}
	}
}

// TestTimeConfig_YAMLRoundTrip verifies ToYAML and FromYAML are inverse operations.
func TestTimeConfig_YAMLRoundTrip(t *testing.T) {
	original := &TimeConfig{
		Timezone:       "America/Chicago",
		NTPServers:     []string{"time1.example.com", "time2.example.com"},
		NTPSyncEnabled: true,
	}

	data, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error: %v", err)
	}

	decoded := &TimeConfig{}
	if err := decoded.FromYAML(data); err != nil {
		t.Fatalf("FromYAML() error: %v", err)
	}

	if decoded.Timezone != original.Timezone {
		t.Errorf("Timezone: got %q, want %q", decoded.Timezone, original.Timezone)
	}
	if decoded.NTPSyncEnabled != original.NTPSyncEnabled {
		t.Errorf("NTPSyncEnabled: got %v, want %v", decoded.NTPSyncEnabled, original.NTPSyncEnabled)
	}
	if len(decoded.NTPServers) != len(original.NTPServers) {
		t.Errorf("NTPServers length: got %d, want %d", len(decoded.NTPServers), len(original.NTPServers))
	}
}

// TestTimeConfig_GetManagedFields verifies the fields reported as managed.
func TestTimeConfig_GetManagedFields(t *testing.T) {
	config := &TimeConfig{Timezone: "UTC"}
	fields := config.GetManagedFields()

	required := map[string]bool{
		"timezone":         false,
		"ntp_servers":      false,
		"ntp_sync_enabled": false,
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

// TestTimeModule_Get_EmptyResourceID verifies Get rejects an empty resource ID.
func TestTimeModule_Get_EmptyResourceID(t *testing.T) {
	m := New()
	_, err := m.Get(context.Background(), "")
	if err == nil {
		t.Error("Get() with empty resource ID must return an error")
	}
}

// TestTimeModule_Set_InvalidInputs verifies Set rejects empty resource IDs and nil configs.
func TestTimeModule_Set_InvalidInputs(t *testing.T) {
	m := New()
	ctx := context.Background()

	validConfig := &TimeConfig{Timezone: "UTC", NTPSyncEnabled: true}

	if err := m.Set(ctx, "", validConfig); err == nil {
		t.Error("Set() with empty resource ID must return an error")
	}

	if err := m.Set(ctx, "system", nil); err == nil {
		t.Error("Set() with nil config must return an error")
	}
}

// TestTimeModule_Set_InvalidTimezone verifies Set rejects configs with an empty timezone.
func TestTimeModule_Set_InvalidTimezone(t *testing.T) {
	m := New()
	ctx := context.Background()

	badConfig := &TimeConfig{Timezone: ""}
	if err := m.Set(ctx, "system", badConfig); err == nil {
		t.Error("Set() with empty timezone must return an error")
	}
}

// TestTimeModule_Set_WrongConfigType verifies Set rejects configs of the wrong type.
func TestTimeModule_Set_WrongConfigType(t *testing.T) {
	m := New()
	ctx := context.Background()

	// wrongConfig implements modules.ConfigState but is not *TimeConfig.
	wrongCfg := &wrongConfigType{}
	if err := m.Set(ctx, "system", wrongCfg); err == nil {
		t.Error("Set() with wrong config type must return an error")
	}
}

// wrongConfigType is a stub that implements modules.ConfigState but is not *TimeConfig.
type wrongConfigType struct{}

func (w *wrongConfigType) AsMap() map[string]interface{}  { return nil }
func (w *wrongConfigType) ToYAML() ([]byte, error)        { return nil, nil }
func (w *wrongConfigType) FromYAML(_ []byte) error        { return nil }
func (w *wrongConfigType) Validate() error                { return nil }
func (w *wrongConfigType) GetManagedFields() []string     { return nil }

// TestTimeModule_LoggingInjection verifies the module implements LoggingInjectable.
func TestTimeModule_LoggingInjection(t *testing.T) {
	m := New()

	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("New() must return a value implementing modules.LoggingInjectable")
	}

	_, injected := injectable.GetLogger()
	if injected {
		t.Error("GetLogger() must return injected=false before SetLogger is called")
	}

	testLogger := logging.ForModule("time-test")
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

// TestTimeModule_ConformanceDeterministicGet verifies that Get produces
// byte-for-byte identical output on consecutive calls (ADR-016 clause 4).
func TestTimeModule_ConformanceDeterministicGet(t *testing.T) {
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

// TestTimeModule_ConformanceNoEphemeralFields verifies that TimeConfig returned
// by Get() contains no banned ephemeral fields (ADR-016 clause 4).
func TestTimeModule_ConformanceNoEphemeralFields(t *testing.T) {
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
