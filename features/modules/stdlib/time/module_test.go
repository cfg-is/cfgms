// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package timemodule

import (
	"context"
	"errors"
	"reflect"
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
			name:    "ntp_source domain is valid",
			config:  TimeConfig{Timezone: "UTC", NTPSource: "domain"},
			wantErr: false,
		},
		{
			name:    "ntp_source manual is valid",
			config:  TimeConfig{Timezone: "UTC", NTPSource: "manual"},
			wantErr: false,
		},
		{
			name:    "unknown ntp_source is invalid",
			config:  TimeConfig{Timezone: "UTC", NTPSource: "dns"},
			wantErr: true,
		},
		{
			name:    "ntp_source is case sensitive",
			config:  TimeConfig{Timezone: "UTC", NTPSource: "Domain"},
			wantErr: true,
		},
		{
			name:    "hyperv provider enabled is valid",
			config:  TimeConfig{Timezone: "UTC", HyperVHostTimeProvider: "enabled"},
			wantErr: false,
		},
		{
			name:    "hyperv provider disabled is valid",
			config:  TimeConfig{Timezone: "UTC", HyperVHostTimeProvider: "disabled"},
			wantErr: false,
		},
		{
			name:    "unknown hyperv provider value is invalid",
			config:  TimeConfig{Timezone: "UTC", HyperVHostTimeProvider: "true"},
			wantErr: true,
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
		{
			name: "defaults are reported for unset new fields",
			config: TimeConfig{
				Timezone: "UTC",
			},
			checks: map[string]interface{}{
				"ntp_source":                "manual",
				"ntp_reliable":              false,
				"hyperv_host_time_provider": "",
			},
		},
		{
			name: "explicit new fields are reported",
			config: TimeConfig{
				Timezone:               "UTC",
				NTPSource:              "domain",
				NTPReliable:            true,
				HyperVHostTimeProvider: "disabled",
			},
			checks: map[string]interface{}{
				"ntp_source":                "domain",
				"ntp_reliable":              true,
				"hyperv_host_time_provider": "disabled",
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

		NTPSource:              "domain",
		NTPReliable:            true,
		HyperVHostTimeProvider: "disabled",
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
	if decoded.NTPSource != original.NTPSource || decoded.NTPReliable != original.NTPReliable ||
		decoded.HyperVHostTimeProvider != original.HyperVHostTimeProvider {
		t.Errorf("new fields: got %q/%v/%q, want %q/%v/%q",
			decoded.NTPSource, decoded.NTPReliable, decoded.HyperVHostTimeProvider,
			original.NTPSource, original.NTPReliable, original.HyperVHostTimeProvider)
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

		"ntp_source":                false,
		"ntp_reliable":              false,
		"hyperv_host_time_provider": false,
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

func (w *wrongConfigType) AsMap() map[string]interface{} { return nil }
func (w *wrongConfigType) ToYAML() ([]byte, error)       { return nil, nil }
func (w *wrongConfigType) FromYAML(_ []byte) error       { return nil }
func (w *wrongConfigType) Validate() error               { return nil }
func (w *wrongConfigType) GetManagedFields() []string    { return nil }

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
//
// On a non-admin Windows session, Get returns modules.ErrInsufficientPrivilege
// (Issue #4147): "w32tm /query /configuration" needs an elevated token, which
// the steward always has in production (its Windows service defaults to
// LocalSystem -- see the doc comment on windowsExecutor.getNTPConfig), but a
// developer or CI session running go test as a standard user does not. That
// is asserted here as documented behavior, not skipped: the module correctly
// reports why it cannot answer, and an elevated run below still exercises the
// full conformance path.
func TestTimeModule_ConformanceDeterministicGet(t *testing.T) {
	m := New()
	state, err := m.Get(context.Background(), "system")
	if err != nil {
		if errors.Is(err, modules.ErrUnsupportedPlatform) {
			t.Skipf("skipping conformance test: Get unsupported on this platform: %v", err)
		}
		if errors.Is(err, modules.ErrInsufficientPrivilege) {
			if state != nil {
				t.Errorf("Get(\"system\") returned a non-nil state alongside ErrInsufficientPrivilege: %+v", state)
			}
			t.Logf("Get(\"system\") correctly reported insufficient privilege on this non-elevated session: %v", err)
			return
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
//
// See TestTimeModule_ConformanceDeterministicGet for why a non-elevated
// Windows session asserting modules.ErrInsufficientPrivilege here is
// documented behavior, not a skip.
func TestTimeModule_ConformanceNoEphemeralFields(t *testing.T) {
	m := New()
	state, err := m.Get(context.Background(), "system")
	if err != nil {
		if errors.Is(err, modules.ErrUnsupportedPlatform) {
			t.Skipf("skipping: Get unsupported on this platform: %v", err)
		}
		if errors.Is(err, modules.ErrInsufficientPrivilege) {
			if state != nil {
				t.Errorf("Get(\"system\") returned a non-nil state alongside ErrInsufficientPrivilege: %+v", state)
			}
			t.Logf("Get(\"system\") correctly reported insufficient privilege on this non-elevated session: %v", err)
			return
		}
		t.Fatalf("Get(\"system\") returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("Get(\"system\") returned nil state with nil error")
	}
	conformance.AssertNoEphemeralFields(t, state, conformance.DefaultBannedEphemeralFields)
}

// TestBuildW32tmConfigArgs covers every combination of ntp_sync_enabled,
// ntp_source, ntp_reliable and empty/non-empty ntp_servers.
func TestBuildW32tmConfigArgs(t *testing.T) {
	disabled := [][]string{{"/config", "/syncfromflags:no", "/update"}}
	domain := [][]string{{"/config", "/syncfromflags:domhier", "/reliable:no", "/update"}}
	manual := func(peers, reliable string) [][]string {
		return [][]string{{"/config", "/manualpeerlist:" + peers, "/syncfromflags:manual", reliable, "/update"}}
	}

	servers := []string{"a.example.com", "b.example.com"}
	const joined = "a.example.com b.example.com"

	tests := []struct {
		name    string
		desired timeState
		want    [][]string
	}{
		{"disabled, defaults", timeState{}, disabled},
		{"disabled ignores domain source", timeState{NTPSource: "domain"}, disabled},
		{"disabled ignores reliable", timeState{NTPReliable: true}, disabled},
		{"disabled ignores servers", timeState{NTPServers: servers}, disabled},
		{"disabled ignores everything", timeState{NTPSource: "domain", NTPReliable: true, NTPServers: servers}, disabled},

		{"domain, no servers", timeState{NTPSyncEnabled: true, NTPSource: "domain"}, domain},
		{"domain ignores servers", timeState{NTPSyncEnabled: true, NTPSource: "domain", NTPServers: servers}, domain},
		{"domain never reliable", timeState{NTPSyncEnabled: true, NTPSource: "domain", NTPReliable: true}, domain},
		{"domain never reliable with servers", timeState{NTPSyncEnabled: true, NTPSource: "domain", NTPReliable: true, NTPServers: servers}, domain},

		{"manual, no servers, not reliable", timeState{NTPSyncEnabled: true, NTPSource: "manual"}, manual("time.windows.com,0x9", "/reliable:no")},
		{"manual, no servers, reliable", timeState{NTPSyncEnabled: true, NTPSource: "manual", NTPReliable: true}, manual("time.windows.com,0x9", "/reliable:yes")},
		{"manual, servers, not reliable", timeState{NTPSyncEnabled: true, NTPSource: "manual", NTPServers: servers}, manual(joined, "/reliable:no")},
		{"manual, servers, reliable", timeState{NTPSyncEnabled: true, NTPSource: "manual", NTPReliable: true, NTPServers: servers}, manual(joined, "/reliable:yes")},

		{"empty source means manual, servers only", timeState{NTPSyncEnabled: true, NTPServers: servers}, manual(joined, "/reliable:no")},
		{"empty source means manual, no servers", timeState{NTPSyncEnabled: true}, manual("time.windows.com,0x9", "/reliable:no")},
		{"empty source means manual, reliable", timeState{NTPSyncEnabled: true, NTPReliable: true}, manual("time.windows.com,0x9", "/reliable:yes")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildW32tmConfigArgs(tt.desired)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("buildW32tmConfigArgs(%+v) = %q, want %q", tt.desired, got, tt.want)
			}
		})
	}
}

// TestBuildW32tmConfigArgs_ReliableOnlyWhenRequested guards the regression
// where every Windows host was declared a reliable time source.
func TestBuildW32tmConfigArgs_ReliableOnlyWhenRequested(t *testing.T) {
	for _, source := range []string{"", "manual", "domain"} {
		for _, reliable := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				desired := timeState{NTPSyncEnabled: enabled, NTPSource: source, NTPReliable: reliable}
				wantYes := enabled && reliable && source != "domain"
				gotYes := false
				for _, args := range buildW32tmConfigArgs(desired) {
					for _, a := range args {
						if a == "/reliable:yes" {
							gotYes = true
						}
					}
				}
				if gotYes != wantYes {
					t.Errorf("%+v: /reliable:yes present = %v, want %v", desired, gotYes, wantYes)
				}
			}
		}
	}
}

// TestRejectWindowsOnlyFields verifies the check non-Windows executors use.
func TestRejectWindowsOnlyFields(t *testing.T) {
	ok := []timeState{
		{},
		{NTPSource: "manual"},
		{NTPSyncEnabled: true, NTPServers: []string{"pool.ntp.org"}},
	}
	for _, st := range ok {
		if err := rejectWindowsOnlyFields(st); err != nil {
			t.Errorf("rejectWindowsOnlyFields(%+v) = %v, want nil", st, err)
		}
	}

	bad := []timeState{
		{NTPSource: "domain"},
		{NTPReliable: true},
		{HyperVHostTimeProvider: "disabled"},
		{HyperVHostTimeProvider: "enabled"},
	}
	for _, st := range bad {
		if err := rejectWindowsOnlyFields(st); !errors.Is(err, modules.ErrInvalidInput) {
			t.Errorf("rejectWindowsOnlyFields(%+v) = %v, want ErrInvalidInput", st, err)
		}
	}
}
