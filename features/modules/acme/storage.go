// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// #nosec G304 - ACME certificate store requires file system access for certificate management
package acme

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// CertBackend abstracts certificate storage (filesystem PEM vs Windows cert store).
// The filesystem backend stores certificates as PEM files; the Windows backend
// imports certificates into the Windows Certificate Store via CryptoAPI while
// keeping PEM backups for ACME renewal operations.
type CertBackend interface {
	StoreCertificate(domain string, certPEM, keyPEM, issuerPEM []byte, meta *CertificateMetadata) error
	LoadCertificate(domain string) (certPEM, keyPEM []byte, err error)
	LoadCertificateMetadata(domain string) (*CertificateMetadata, error)
	DeleteCertificate(domain string) error
	CertificateExists(domain string) bool
}

// ACMECertStore manages ACME certificates and accounts.
// Certificate operations are delegated to a CertBackend (filesystem PEM or
// Windows cert store). Account operations (keys + registration data) are
// routed through the secret store for encrypted-at-rest storage.
type ACMECertStore struct {
	basePath    string                        // filesystem base for account data (legacy, used for dir structure)
	certBackend CertBackend                   // filesystem or Windows cert store
	secretStore secretsinterfaces.SecretStore // required for account key/data operations
}

// CertificateMetadata stores metadata alongside certificate files
type CertificateMetadata struct {
	Domain     string    `json:"domain"`
	Email      string    `json:"email"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Issuer     string    `json:"issuer"`
	Serial     string    `json:"serial"`
	KeyType    string    `json:"key_type"`
	ACMEServer string    `json:"acme_server,omitempty"`
}

// AccountData stores the ACME account registration
type AccountData struct {
	Email        string `json:"email"`
	Registration []byte `json:"registration"`
	URI          string `json:"uri"`
}

// NewACMECertStore creates a new certificate store at the given path.
// The path determines the certificate backend:
//   - "cert:\..." paths use the Windows Certificate Store (Windows only)
//   - All other paths use filesystem PEM storage
//   - Empty string uses the platform default
func NewACMECertStore(certStorePath string) (*ACMECertStore, error) {
	if certStorePath == "" {
		certStorePath = defaultCertStorePath()
	}

	// Determine account storage path (always filesystem).
	// When using the Windows cert store, accounts go to the platform default filesystem path.
	accountBasePath := certStorePath
	if isCertStorePath(certStorePath) {
		accountBasePath = defaultAccountStorePath()
	}

	// Create cert backend based on path type
	backend, err := newCertBackend(certStorePath)
	if err != nil {
		return nil, err
	}

	store := &ACMECertStore{
		basePath:    accountBasePath,
		certBackend: backend,
	}

	return store, nil
}

// SetSecretStore injects a secret store for encrypted account key/data storage.
func (s *ACMECertStore) SetSecretStore(store secretsinterfaces.SecretStore) {
	s.secretStore = store
}

// emailHash returns the first 16 hex chars of SHA-256(email), used as account identifier.
func (s *ACMECertStore) emailHash(email string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(email)))
	return hash[:16]
}

// accountSecretKey returns the secret store key for an ACME account private key.
func (s *ACMECertStore) accountSecretKey(email string) string {
	return "acme/account-key/" + s.emailHash(email)
}

// accountDataSecretKey returns the secret store key for ACME account registration data.
func (s *ACMECertStore) accountDataSecretKey(email string) string {
	return "acme/account/" + s.emailHash(email)
}

// StoreCertificate writes certificate data to the configured backend
func (s *ACMECertStore) StoreCertificate(domain string, certPEM, keyPEM, issuerPEM []byte, meta *CertificateMetadata) error {
	return s.certBackend.StoreCertificate(domain, certPEM, keyPEM, issuerPEM, meta)
}

// LoadCertificate reads the certificate and key for a domain
func (s *ACMECertStore) LoadCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	return s.certBackend.LoadCertificate(domain)
}

// LoadCertificateMetadata reads the metadata for a domain's certificate
func (s *ACMECertStore) LoadCertificateMetadata(domain string) (*CertificateMetadata, error) {
	return s.certBackend.LoadCertificateMetadata(domain)
}

// DeleteCertificate removes certificate data for a domain
func (s *ACMECertStore) DeleteCertificate(domain string) error {
	return s.certBackend.DeleteCertificate(domain)
}

// CertificateExists checks if a certificate exists for the given domain
func (s *ACMECertStore) CertificateExists(domain string) bool {
	return s.certBackend.CertificateExists(domain)
}

// StoreAccount saves ACME account data via the secret store.
func (s *ACMECertStore) StoreAccount(email string, data *AccountData) error {
	if s.secretStore == nil {
		return fmt.Errorf("secret store not configured: cannot store account data without encryption")
	}

	accountJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal account data: %w", err)
	}

	return s.secretStore.StoreSecret(context.Background(), &secretsinterfaces.SecretRequest{
		Key:         s.accountDataSecretKey(email),
		Value:       string(accountJSON),
		Metadata:    map[string]string{"type": "acme-account-data"},
		Tags:        []string{"acme", "account"},
		CreatedBy:   "acme-module",
		Description: "ACME account registration data",
	})
}

// LoadAccount reads ACME account data from the secret store.
func (s *ACMECertStore) LoadAccount(email string) (*AccountData, error) {
	if s.secretStore == nil {
		return nil, fmt.Errorf("secret store not configured: cannot load account data without encryption")
	}

	secret, err := s.secretStore.GetSecret(context.Background(), s.accountDataSecretKey(email))
	if err != nil {
		return nil, fmt.Errorf("failed to read account data from secret store: %w", err)
	}

	var account AccountData
	if err := json.Unmarshal([]byte(secret.Value), &account); err != nil {
		return nil, fmt.Errorf("failed to parse account data: %w", err)
	}
	return &account, nil
}

// AccountExists checks if an account exists for the given email via the secret store.
func (s *ACMECertStore) AccountExists(email string) bool {
	if s.secretStore == nil {
		return false
	}
	_, err := s.secretStore.GetSecretMetadata(context.Background(), s.accountSecretKey(email))
	return err == nil
}

// StoreAccountKey saves the ACME account private key via the secret store.
func (s *ACMECertStore) StoreAccountKey(email string, keyPEM []byte) error {
	if s.secretStore == nil {
		return fmt.Errorf("secret store not configured: cannot store account key without encryption")
	}
	return s.secretStore.StoreSecret(context.Background(), &secretsinterfaces.SecretRequest{
		Key:         s.accountSecretKey(email),
		Value:       string(keyPEM),
		Metadata:    map[string]string{"type": "acme-account-key"},
		Tags:        []string{"acme", "account-key"},
		CreatedBy:   "acme-module",
		Description: "ACME account private key",
	})
}

// LoadAccountKey reads the ACME account private key from the secret store.
func (s *ACMECertStore) LoadAccountKey(email string) ([]byte, error) {
	if s.secretStore == nil {
		return nil, fmt.Errorf("secret store not configured: cannot load account key without encryption")
	}
	secret, err := s.secretStore.GetSecret(context.Background(), s.accountSecretKey(email))
	if err != nil {
		return nil, fmt.Errorf("failed to read account key from secret store: %w", err)
	}
	return []byte(secret.Value), nil
}

// GetBasePath returns the base storage path
func (s *ACMECertStore) GetBasePath() string {
	return s.basePath
}

// isCertStorePath returns true if the path refers to a Windows Certificate Store.
// Paths starting with "cert:\" (case-insensitive) are routed to the Windows cert store backend.
func isCertStorePath(path string) bool {
	return strings.HasPrefix(strings.ToLower(path), `cert:\`)
}

// parseCertStorePath parses a cert:\ path into location and store name.
// Example: "cert:\LocalMachine\My" → location="LocalMachine", storeName="My"
func parseCertStorePath(path string) (location string, storeName string) {
	// Remove "cert:\" prefix (case-insensitive, 6 characters)
	trimmed := path
	if len(trimmed) >= 6 && strings.EqualFold(trimmed[:6], `cert:\`) {
		trimmed = trimmed[6:]
	}

	// Split on backslash: "LocalMachine\My" → ["LocalMachine", "My"]
	parts := strings.SplitN(trimmed, `\`, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 && parts[0] != "" {
		return parts[0], "My"
	}
	return "LocalMachine", "My"
}

func defaultCertStorePath() string {
	switch runtime.GOOS {
	case "windows":
		return `cert:\LocalMachine\My`
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "cfgms", "certs")
	default: // linux and others
		return "/var/lib/cfgms/certs"
	}
}

// defaultAccountStorePath returns the filesystem path for ACME account data.
// Account data is always stored on the filesystem, even when certificates
// use the Windows Certificate Store.
func defaultAccountStorePath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "cfgms", "certs")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "cfgms", "certs")
	default:
		return "/var/lib/cfgms/certs"
	}
}
