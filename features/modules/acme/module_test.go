// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

// --- Config Validation Tests ---

func TestACMEConfig_Validate_ValidPresent(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "admin@example.com",
		ChallengeType: "http-01",
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "ec256", cfg.KeyType)
	assert.Equal(t, 30, cfg.RenewalThresholdDays)
	assert.Equal(t, ":80", cfg.HTTPBindAddress)
}

func TestACMEConfig_Validate_ValidAbsent(t *testing.T) {
	cfg := &ACMEConfig{State: "absent"}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestACMEConfig_Validate_DefaultState(t *testing.T) {
	cfg := &ACMEConfig{
		Domains:       []string{"example.com"},
		Email:         "admin@example.com",
		ChallengeType: "http-01",
	}
	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, "present", cfg.State)
}

func TestACMEConfig_Validate_InvalidState(t *testing.T) {
	cfg := &ACMEConfig{State: "invalid"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "state must be")
}

func TestACMEConfig_Validate_NoDomains(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{},
		Email:         "admin@example.com",
		ChallengeType: "http-01",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDomain)
}

func TestACMEConfig_Validate_InvalidDomainIP(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"192.168.1.1"},
		Email:         "admin@example.com",
		ChallengeType: "http-01",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidDomain)
}

func TestACMEConfig_Validate_WildcardDomain(t *testing.T) {
	cfg := &ACMEConfig{
		State:            "present",
		Domains:          []string{"*.example.com"},
		Email:            "admin@example.com",
		ChallengeType:    "dns-01",
		DNSProvider:      "cloudflare",
		DNSCredentialKey: "acme/cf-token",
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestACMEConfig_Validate_InvalidEmail(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "not-an-email",
		ChallengeType: "http-01",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidEmail)
}

func TestACMEConfig_Validate_EmptyEmail(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "",
		ChallengeType: "http-01",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidEmail)
}

func TestACMEConfig_Validate_InvalidChallengeType(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "admin@example.com",
		ChallengeType: "tls-alpn-01",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidChallengeType)
}

func TestACMEConfig_Validate_DNS01_RequiresProvider(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "admin@example.com",
		ChallengeType: "dns-01",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSProviderRequired)
}

func TestACMEConfig_Validate_DNS01_UnsupportedProvider(t *testing.T) {
	cfg := &ACMEConfig{
		State:            "present",
		Domains:          []string{"example.com"},
		Email:            "admin@example.com",
		ChallengeType:    "dns-01",
		DNSProvider:      "godaddy",
		DNSCredentialKey: "key",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedDNSProvider)
}

func TestACMEConfig_Validate_DNS01_RequiresCredentialKey(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "admin@example.com",
		ChallengeType: "dns-01",
		DNSProvider:   "cloudflare",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSCredentialKeyRequired)
}

func TestACMEConfig_Validate_InvalidKeyType(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "admin@example.com",
		ChallengeType: "http-01",
		KeyType:       "rsa1024",
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorContains(t, err, "key_type")
}

func TestACMEConfig_Validate_InvalidRenewalThreshold(t *testing.T) {
	tests := []struct {
		name string
		days int
	}{
		{"too low", -1},
		{"too high", 91},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ACMEConfig{
				State:                "present",
				Domains:              []string{"example.com"},
				Email:                "admin@example.com",
				ChallengeType:        "http-01",
				RenewalThresholdDays: tt.days,
			}
			err := cfg.Validate()
			require.Error(t, err)
			assert.ErrorContains(t, err, "renewal_threshold_days")
		})
	}
}

func TestACMEConfig_Validate_AllKeyTypes(t *testing.T) {
	keyTypes := []string{"rsa2048", "rsa4096", "ec256", "ec384"}
	for _, kt := range keyTypes {
		t.Run(kt, func(t *testing.T) {
			cfg := &ACMEConfig{
				State:         "present",
				Domains:       []string{"example.com"},
				Email:         "admin@example.com",
				ChallengeType: "http-01",
				KeyType:       kt,
			}
			require.NoError(t, cfg.Validate())
		})
	}
}

func TestACMEConfig_Validate_AllDNSProviders(t *testing.T) {
	providers := []string{"cloudflare", "route53", "azure_dns"}
	for _, p := range providers {
		t.Run(p, func(t *testing.T) {
			cfg := &ACMEConfig{
				State:            "present",
				Domains:          []string{"example.com"},
				Email:            "admin@example.com",
				ChallengeType:    "dns-01",
				DNSProvider:      p,
				DNSCredentialKey: "acme/" + p,
			}
			require.NoError(t, cfg.Validate())
		})
	}
}

// --- AsMap / GetManagedFields Tests ---

func TestACMEConfig_AsMap_Present(t *testing.T) {
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"example.com"},
		Email:                "admin@example.com",
		ChallengeType:        "http-01",
		KeyType:              "ec256",
		RenewalThresholdDays: 30,
	}
	m := cfg.AsMap()
	assert.Equal(t, "present", m["state"])
	assert.Equal(t, []string{"example.com"}, m["domains"])
	assert.Equal(t, "admin@example.com", m["email"])
	assert.Equal(t, "http-01", m["challenge_type"])
	assert.Equal(t, "ec256", m["key_type"])
	assert.Equal(t, 30, m["renewal_threshold_days"])
	// CertificateStatus should NOT be in AsMap (read-only)
	_, hasStatus := m["certificate_status"]
	assert.False(t, hasStatus)
}

func TestACMEConfig_AsMap_Absent(t *testing.T) {
	cfg := &ACMEConfig{State: "absent"}
	m := cfg.AsMap()
	assert.Equal(t, "absent", m["state"])
	assert.Len(t, m, 1) // Only state for absent
}

func TestACMEConfig_GetManagedFields_Present(t *testing.T) {
	cfg := &ACMEConfig{
		State:         "present",
		Domains:       []string{"example.com"},
		Email:         "admin@example.com",
		ChallengeType: "http-01",
		DNSProvider:   "cloudflare",
	}
	fields := cfg.GetManagedFields()
	assert.Contains(t, fields, "state")
	assert.Contains(t, fields, "domains")
	assert.Contains(t, fields, "email")
	assert.Contains(t, fields, "challenge_type")
	assert.Contains(t, fields, "dns_provider")
}

func TestACMEConfig_GetManagedFields_Absent(t *testing.T) {
	cfg := &ACMEConfig{State: "absent"}
	fields := cfg.GetManagedFields()
	assert.Equal(t, []string{"state"}, fields)
}

// --- YAML Round-Trip Tests ---

func TestACMEConfig_YAMLRoundTrip(t *testing.T) {
	original := &ACMEConfig{
		State:                "present",
		Domains:              []string{"example.com", "*.example.com"},
		Email:                "admin@example.com",
		ChallengeType:        "dns-01",
		DNSProvider:          "cloudflare",
		DNSCredentialKey:     "acme/cf-token",
		KeyType:              "ec384",
		RenewalThresholdDays: 14,
		Staging:              true,
	}

	yamlData, err := original.ToYAML()
	require.NoError(t, err)

	restored := &ACMEConfig{}
	err = restored.FromYAML(yamlData)
	require.NoError(t, err)

	assert.Equal(t, original.State, restored.State)
	assert.Equal(t, original.Domains, restored.Domains)
	assert.Equal(t, original.Email, restored.Email)
	assert.Equal(t, original.ChallengeType, restored.ChallengeType)
	assert.Equal(t, original.DNSProvider, restored.DNSProvider)
	assert.Equal(t, original.DNSCredentialKey, restored.DNSCredentialKey)
	assert.Equal(t, original.KeyType, restored.KeyType)
	assert.Equal(t, original.RenewalThresholdDays, restored.RenewalThresholdDays)
	assert.Equal(t, original.Staging, restored.Staging)
}

// --- Renewal Decision Tests ---

func TestDetermineAction_NilConfig(t *testing.T) {
	_, err := DetermineAction(nil, nil)
	require.Error(t, err)
}

func TestDetermineAction_StateAbsent(t *testing.T) {
	cfg := &ACMEConfig{State: "absent"}
	decision, err := DetermineAction(cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, DecisionRemove, decision)
}

func TestDetermineAction_NoCert(t *testing.T) {
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"example.com"},
		RenewalThresholdDays: 30,
	}
	decision, err := DetermineAction(cfg, nil)
	require.NoError(t, err)
	assert.Equal(t, DecisionObtain, decision)
}

func TestDetermineAction_CorruptedCert(t *testing.T) {
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"example.com"},
		RenewalThresholdDays: 30,
	}
	decision, err := DetermineAction(cfg, []byte("not a PEM"))
	require.NoError(t, err)
	assert.Equal(t, DecisionObtain, decision)
}

func TestDetermineAction_ExpiredCert(t *testing.T) {
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"example.com"},
		RenewalThresholdDays: 30,
	}
	certPEM := generateTestCert(t, []string{"example.com"}, -48*time.Hour, -24*time.Hour)
	decision, err := DetermineAction(cfg, certPEM)
	require.NoError(t, err)
	assert.Equal(t, DecisionObtain, decision)
}

func TestDetermineAction_DomainMismatch(t *testing.T) {
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"new.example.com"},
		RenewalThresholdDays: 30,
	}
	certPEM := generateTestCert(t, []string{"old.example.com"}, -24*time.Hour, 60*24*time.Hour)
	decision, err := DetermineAction(cfg, certPEM)
	require.NoError(t, err)
	assert.Equal(t, DecisionObtain, decision)
}

func TestDetermineAction_NeedsRenewal(t *testing.T) {
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"example.com"},
		RenewalThresholdDays: 30,
	}
	// Certificate expires in 15 days (within 30-day threshold)
	certPEM := generateTestCert(t, []string{"example.com"}, -24*time.Hour, 15*24*time.Hour)
	decision, err := DetermineAction(cfg, certPEM)
	require.NoError(t, err)
	assert.Equal(t, DecisionRenew, decision)
}

func TestDetermineAction_ValidCert(t *testing.T) {
	cfg := &ACMEConfig{
		State:                "present",
		Domains:              []string{"example.com"},
		RenewalThresholdDays: 30,
	}
	// Certificate expires in 60 days (outside 30-day threshold)
	certPEM := generateTestCert(t, []string{"example.com"}, -24*time.Hour, 60*24*time.Hour)
	decision, err := DetermineAction(cfg, certPEM)
	require.NoError(t, err)
	assert.Equal(t, DecisionNone, decision)
}

func TestRenewalDecision_String(t *testing.T) {
	assert.Equal(t, "none", DecisionNone.String())
	assert.Equal(t, "obtain", DecisionObtain.String())
	assert.Equal(t, "renew", DecisionRenew.String())
	assert.Equal(t, "remove", DecisionRemove.String())
	assert.Equal(t, "unknown", RenewalDecision(99).String())
}

// --- Storage Tests ---

func TestACMECertStore_StorageRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewACMECertStore(tmpDir)
	require.NoError(t, err)

	domain := "test.example.com"
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\ntest key\n-----END EC PRIVATE KEY-----\n")
	issuerPEM := []byte("-----BEGIN CERTIFICATE-----\ntest issuer\n-----END CERTIFICATE-----\n")
	meta := &CertificateMetadata{
		Domain:   domain,
		Email:    "admin@example.com",
		IssuedAt: time.Now(),
		KeyType:  "ec256",
	}

	// Store
	err = store.StoreCertificate(domain, certPEM, keyPEM, issuerPEM, meta)
	require.NoError(t, err)

	// Exists check
	assert.True(t, store.CertificateExists(domain))

	// Load
	loadedCert, loadedKey, err := store.LoadCertificate(domain)
	require.NoError(t, err)
	assert.Equal(t, certPEM, loadedCert)
	assert.Equal(t, keyPEM, loadedKey)

	// Load metadata
	loadedMeta, err := store.LoadCertificateMetadata(domain)
	require.NoError(t, err)
	assert.Equal(t, domain, loadedMeta.Domain)
	assert.Equal(t, "admin@example.com", loadedMeta.Email)

	// Verify key.pem permissions (Unix only)
	keyPath := filepath.Join(tmpDir, "acme", "certificates", domain, "key.pem")
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Delete
	err = store.DeleteCertificate(domain)
	require.NoError(t, err)
	assert.False(t, store.CertificateExists(domain))
}

func TestACMECertStore_AccountRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewACMECertStore(tmpDir)
	require.NoError(t, err)

	email := "admin@example.com"

	// Store account key
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\naccount key\n-----END EC PRIVATE KEY-----\n")
	err = store.StoreAccountKey(email, keyPEM)
	require.NoError(t, err)

	// Store account data
	accountData := &AccountData{
		Email: email,
		URI:   "https://acme-v02.api.letsencrypt.org/acme/acct/123",
	}
	err = store.StoreAccount(email, accountData)
	require.NoError(t, err)

	// Exists
	assert.True(t, store.AccountExists(email))

	// Load key
	loadedKey, err := store.LoadAccountKey(email)
	require.NoError(t, err)
	assert.Equal(t, keyPEM, loadedKey)

	// Load account
	loadedAccount, err := store.LoadAccount(email)
	require.NoError(t, err)
	assert.Equal(t, email, loadedAccount.Email)
	assert.Equal(t, accountData.URI, loadedAccount.URI)
}

func TestACMECertStore_NonexistentCert(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewACMECertStore(tmpDir)
	require.NoError(t, err)

	assert.False(t, store.CertificateExists("nonexistent.com"))

	_, _, err = store.LoadCertificate("nonexistent.com")
	require.Error(t, err)
}

func TestACMECertStore_DefaultPath(t *testing.T) {
	path := defaultCertStorePath()
	assert.NotEmpty(t, path)
}

// --- Domain Validation Tests ---

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{"valid domain", "example.com", false},
		{"valid subdomain", "sub.example.com", false},
		{"valid wildcard", "*.example.com", false},
		{"empty domain", "", true},
		{"single label", "localhost", true},
		{"IP address", "1.2.3.4", true},
		{"IPv6", "::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomain(tt.domain)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- Module Get/Set Tests ---

func TestModule_New(t *testing.T) {
	m := New()
	require.NotNil(t, m)
}

func TestModule_Get_EmptyResourceID(t *testing.T) {
	m := New()
	_, err := m.Get(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, modules.ErrInvalidResourceID)
}

func TestModule_Set_EmptyResourceID(t *testing.T) {
	m := New()
	err := m.Set(context.Background(), "", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, modules.ErrInvalidResourceID)
}

func TestModule_Set_NilConfig(t *testing.T) {
	m := New()
	err := m.Set(context.Background(), "example.com", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, modules.ErrInvalidInput)
}

func TestModule_Set_WrongConfigType(t *testing.T) {
	m := New()
	err := m.Set(context.Background(), "example.com", &wrongConfig{})
	require.Error(t, err)
	assert.ErrorIs(t, err, modules.ErrInvalidInput)
}

// wrongConfig is a test-only ConfigState implementation for type assertion tests
type wrongConfig struct{}

func (w *wrongConfig) AsMap() map[string]interface{} { return nil }
func (w *wrongConfig) ToYAML() ([]byte, error)       { return nil, nil }
func (w *wrongConfig) FromYAML([]byte) error         { return nil }
func (w *wrongConfig) Validate() error               { return nil }
func (w *wrongConfig) GetManagedFields() []string    { return nil }

// --- Client Tests ---

func TestToLegoKeyType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"rsa2048", "2048"},
		{"rsa4096", "4096"},
		{"ec256", "P256"},
		{"ec384", "P384"},
		{"unknown", "P256"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toLegoKeyType(tt.input)
			assert.Contains(t, string(result), tt.expected)
		})
	}
}

func TestACMEUser_Interface(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	user := &ACMEUser{
		Email: "test@example.com",
		key:   key,
	}

	assert.Equal(t, "test@example.com", user.GetEmail())
	assert.Nil(t, user.GetRegistration())
	assert.Equal(t, key, user.GetPrivateKey())
}

func TestMarshalParseECPrivateKey_RoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyPEM, err := marshalECPrivateKey(key)
	require.NoError(t, err)
	require.NotNil(t, keyPEM)

	parsed, err := parseECPrivateKey(keyPEM)
	require.NoError(t, err)
	assert.True(t, key.Equal(parsed))
}

// --- Module Set with Remove ---

func TestModule_Set_RemoveCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Pre-create a certificate in the store
	store, err := NewACMECertStore(tmpDir)
	require.NoError(t, err)

	domain := "remove-me.example.com"
	err = store.StoreCertificate(domain,
		[]byte("cert"), []byte("key"), nil,
		&CertificateMetadata{Domain: domain})
	require.NoError(t, err)
	assert.True(t, store.CertificateExists(domain))

	// Use module to remove it
	m := New()
	cfg := &ACMEConfig{
		State:         "absent",
		CertStorePath: tmpDir,
	}

	err = m.Set(context.Background(), domain, cfg)
	require.NoError(t, err)

	// Verify removed
	assert.False(t, store.CertificateExists(domain))
}

// --- Helper: generate a self-signed test certificate ---

func generateTestCert(t *testing.T, dnsNames []string, notBeforeOffset, notAfterOffset time.Duration) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(notBeforeOffset),
		NotAfter:     now.Add(notAfterOffset),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}
