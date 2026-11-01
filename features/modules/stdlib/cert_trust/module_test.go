// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert_trust

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/conformance"
	"github.com/cfgis/cfgms/pkg/logging"
)

// phantomFingerprint is a fingerprint that will never exist in any trust store.
// Used for determinism tests where we need a stable "absent" result.
const phantomFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"

// TestCertTrustModule_New verifies the module constructor returns a non-nil Module.
func TestCertTrustModule_New(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

// TestCertTrustConfig_Validate covers the Validate() method for all valid and
// invalid configurations without making any OS calls.
func TestCertTrustConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  CertTrustConfig
		wantErr bool
	}{
		{
			name:    "present with cert_pem is valid",
			config:  CertTrustConfig{State: "present", CertPEM: "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----"},
			wantErr: false,
		},
		{
			name:    "absent is valid",
			config:  CertTrustConfig{State: "absent"},
			wantErr: false,
		},
		{
			name:    "absent with cert_pem is valid (cert_pem ignored for absent)",
			config:  CertTrustConfig{State: "absent", CertPEM: "some-pem"},
			wantErr: false,
		},
		{
			name:    "empty state is invalid",
			config:  CertTrustConfig{State: ""},
			wantErr: true,
		},
		{
			name:    "unknown state is invalid",
			config:  CertTrustConfig{State: "trusted"},
			wantErr: true,
		},
		{
			name:    "present without cert_pem is invalid",
			config:  CertTrustConfig{State: "present", CertPEM: ""},
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

// TestCertTrustConfig_AsMap verifies AsMap returns the expected keys and values
// and never includes cert_pem (install payload, not observable state).
func TestCertTrustConfig_AsMap(t *testing.T) {
	tests := []struct {
		name       string
		config     CertTrustConfig
		wantKeys   map[string]interface{}
		bannedKeys []string
	}{
		{
			name: "present with all fields",
			config: CertTrustConfig{
				Fingerprint: phantomFingerprint,
				Subject:     "CN=Test CA",
				Issuer:      "CN=Test CA",
				NotAfter:    "2030-01-01T00:00:00Z",
				TrustedFor:  "any",
				State:       "present",
				CertPEM:     "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----",
			},
			wantKeys: map[string]interface{}{
				"fingerprint": phantomFingerprint,
				"subject":     "CN=Test CA",
				"state":       "present",
			},
			bannedKeys: []string{"cert_pem"},
		},
		{
			name: "absent with only fingerprint",
			config: CertTrustConfig{
				Fingerprint: phantomFingerprint,
				State:       "absent",
			},
			wantKeys: map[string]interface{}{
				"fingerprint": phantomFingerprint,
				"state":       "absent",
			},
			bannedKeys: []string{"cert_pem", "subject", "issuer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.config.AsMap()
			for k, wantV := range tt.wantKeys {
				got, ok := m[k]
				if !ok {
					t.Errorf("AsMap() missing key %q", k)
					continue
				}
				if got != wantV {
					t.Errorf("AsMap()[%q] = %v, want %v", k, got, wantV)
				}
			}
			for _, banned := range tt.bannedKeys {
				if _, found := m[banned]; found {
					t.Errorf("AsMap() must not include %q", banned)
				}
			}
		})
	}
}

// TestCertTrustConfig_YAMLRoundTrip verifies ToYAML and FromYAML are inverse operations.
func TestCertTrustConfig_YAMLRoundTrip(t *testing.T) {
	original := &CertTrustConfig{
		Fingerprint: phantomFingerprint,
		Subject:     "CN=Test CA,O=Acme Corp",
		Issuer:      "CN=Test CA,O=Acme Corp",
		NotAfter:    "2035-06-01T00:00:00Z",
		TrustedFor:  "any",
		State:       "present",
		CertPEM:     "-----BEGIN CERTIFICATE-----\nMIIA\n-----END CERTIFICATE-----",
	}

	data, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML() error: %v", err)
	}

	decoded := &CertTrustConfig{}
	if err := decoded.FromYAML(data); err != nil {
		t.Fatalf("FromYAML() error: %v", err)
	}

	if decoded.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint: got %q, want %q", decoded.Fingerprint, original.Fingerprint)
	}
	if decoded.State != original.State {
		t.Errorf("State: got %q, want %q", decoded.State, original.State)
	}
	if decoded.CertPEM != original.CertPEM {
		t.Errorf("CertPEM: got %q, want %q", decoded.CertPEM, original.CertPEM)
	}
}

// TestCertTrustConfig_GetManagedFields verifies the fields reported as managed.
func TestCertTrustConfig_GetManagedFields(t *testing.T) {
	config := &CertTrustConfig{Fingerprint: phantomFingerprint, State: "present"}
	fields := config.GetManagedFields()

	required := map[string]bool{"fingerprint": false, "state": false}
	for _, f := range fields {
		required[f] = true
	}
	for field, found := range required {
		if !found {
			t.Errorf("GetManagedFields() missing required field %q", field)
		}
	}
	// cert_pem must NOT be in managed fields (it is install payload, not observable state).
	for _, f := range fields {
		if f == "cert_pem" {
			t.Error("GetManagedFields() must not include cert_pem (install payload, not observable state)")
		}
	}
}

// TestCertTrustModule_Get_InvalidResourceID verifies Get rejects an empty resource ID.
func TestCertTrustModule_Get_InvalidResourceID(t *testing.T) {
	m := New()
	_, err := m.Get(context.Background(), "")
	if err == nil {
		t.Error("Get() with empty resource ID must return an error")
	}
}

// TestCertTrustModule_Get_InvalidFingerprint verifies Get rejects malformed fingerprints.
func TestCertTrustModule_Get_InvalidFingerprint(t *testing.T) {
	m := New()
	ctx := context.Background()

	invalidIDs := []string{
		"not-a-fingerprint",
		"ABCDEF1234",                    // uppercase not allowed
		"abc",                           // too short
		"gg" + string(make([]byte, 62)), // non-hex chars
		"../etc/passwd",
		"--flag-injection",
	}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			_, err := m.Get(ctx, id)
			if err == nil {
				t.Errorf("Get(%q) must return an error for invalid fingerprint", id)
			}
		})
	}
}

// TestCertTrustModule_Set_InvalidInputs verifies Set rejects empty resource IDs and nil configs.
func TestCertTrustModule_Set_InvalidInputs(t *testing.T) {
	m := New()
	ctx := context.Background()

	validConfig := &CertTrustConfig{State: "absent"}

	if err := m.Set(ctx, "", validConfig); err == nil {
		t.Error("Set() with empty resource ID must return an error")
	}

	if err := m.Set(ctx, phantomFingerprint, nil); err == nil {
		t.Error("Set() with nil config must return an error")
	}
}

// TestCertTrustModule_Set_InvalidState verifies Set rejects configs with invalid state values.
func TestCertTrustModule_Set_InvalidState(t *testing.T) {
	m := New()
	ctx := context.Background()

	badConfig := &CertTrustConfig{State: "trusted"}
	if err := m.Set(ctx, phantomFingerprint, badConfig); err == nil {
		t.Error("Set() with invalid state must return an error")
	}
}

// TestCertTrustModule_DeterministicGet verifies Get satisfies ADR-016 clause 4:
// two calls on the same unchanged state produce byte-for-byte identical output.
// Uses a phantom fingerprint so Get returns "absent" without OS interaction.
func TestCertTrustModule_DeterministicGet(t *testing.T) {
	m := New()
	conformance.AssertDeterministicGet(t, m, phantomFingerprint)
}

// TestCertTrustModule_NoEphemeralFields verifies the "absent" ConfigState returned
// by Get contains no ephemeral fields banned by ADR-016 clause 4.
func TestCertTrustModule_NoEphemeralFields(t *testing.T) {
	m := New()
	state, err := m.Get(context.Background(), phantomFingerprint)
	if err != nil {
		t.Fatalf("Get() returned error: %v", err)
	}
	if state == nil {
		t.Fatal("Get() returned nil state for absent cert")
	}
	conformance.AssertNoEphemeralFields(t, state, conformance.DefaultBannedEphemeralFields)
}

// TestCertTrustModule_Get_AbsentCert verifies Get returns state "absent" (not an
// error) for a fingerprint that does not exist in the trust store.
func TestCertTrustModule_Get_AbsentCert(t *testing.T) {
	m := New()
	state, err := m.Get(context.Background(), phantomFingerprint)
	if err != nil {
		t.Fatalf("Get() on absent cert returned unexpected error: %v", err)
	}
	if state == nil {
		t.Fatal("Get() returned nil state for absent cert")
	}

	m2 := state.AsMap()
	if s, ok := m2["state"].(string); !ok || s != "absent" {
		t.Errorf("expected state='absent' for non-existent cert, got %v", m2["state"])
	}
	if fp, ok := m2["fingerprint"].(string); !ok || fp != phantomFingerprint {
		t.Errorf("expected fingerprint=%q in absent state, got %v", phantomFingerprint, m2["fingerprint"])
	}
}

// TestCertTrustModule_LoggingInjection verifies the module implements LoggingInjectable
// and that SetLogger actually stores the logger for use by subsequent operations.
func TestCertTrustModule_LoggingInjection(t *testing.T) {
	m := New()

	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("New() must return a value implementing modules.LoggingInjectable")
	}

	_, injected := injectable.GetLogger()
	if injected {
		t.Error("GetLogger() must return injected=false before SetLogger is called")
	}

	testLogger := logging.ForModule("cert_trust-test")
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

// TestCertTrustModule_FingerprintMismatch verifies Set rejects a cert whose
// fingerprint does not match the resource ID.
func TestCertTrustModule_FingerprintMismatch(t *testing.T) {
	m := New()
	ctx := context.Background()

	// Use a PEM cert generated in-process by generateSelfSignedCA (see below),
	// but pass a mismatched fingerprint as the resource ID.
	certPEM, _ := generateTestCAPEM(t)

	config := &CertTrustConfig{
		State:   "present",
		CertPEM: certPEM,
	}

	// phantomFingerprint will never match any real cert.
	err := m.Set(ctx, phantomFingerprint, config)
	if err == nil {
		t.Error("Set() must return an error when cert fingerprint does not match resource ID")
	}
}

// TestParsePEMCert verifies parsePEMCert accepts valid PEM and rejects non-PEM input.
func TestParsePEMCert(t *testing.T) {
	certPEM, _ := generateTestCAPEM(t)

	der, err := parsePEMCert(certPEM)
	if err != nil {
		t.Fatalf("parsePEMCert() with valid PEM returned error: %v", err)
	}
	if len(der) == 0 {
		t.Error("parsePEMCert() returned empty DER bytes")
	}

	_, err = parsePEMCert("not valid PEM data")
	if err == nil {
		t.Error("parsePEMCert() with invalid PEM must return an error")
	}
}

// TestCertFingerprint verifies certFingerprint returns a 64-character lowercase hex string.
func TestCertFingerprint(t *testing.T) {
	_, certDER := generateTestCAPEM(t)
	fp := certFingerprint(certDER)
	if len(fp) != 64 {
		t.Errorf("certFingerprint() length = %d, want 64", len(fp))
	}
	for _, c := range fp {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("certFingerprint() contains non-lowercase-hex character %q", c)
		}
	}
}
