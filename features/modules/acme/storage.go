// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// #nosec G304 - ACME certificate store requires file system access for certificate management
package acme

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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
// Windows cert store). Account operations always use the filesystem.
type ACMECertStore struct {
	basePath    string      // filesystem base for account data (always filesystem)
	certBackend CertBackend // filesystem or Windows cert store
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

	// Ensure account directory exists
	accountDir := filepath.Join(accountBasePath, "acme", "accounts")
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", accountDir, err)
	}

	return store, nil
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

// StoreAccount saves ACME account data
func (s *ACMECertStore) StoreAccount(email string, data *AccountData) error {
	accountDir := s.accountPath(email)
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return fmt.Errorf("failed to create account directory: %w", err)
	}

	accountJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal account data: %w", err)
	}

	if err := os.WriteFile(filepath.Join(accountDir, "account.json"), accountJSON, 0600); err != nil {
		return fmt.Errorf("failed to write account.json: %w", err)
	}

	return nil
}

// LoadAccount reads ACME account data
func (s *ACMECertStore) LoadAccount(email string) (*AccountData, error) {
	accountPath := filepath.Join(s.accountPath(email), "account.json")
	data, err := os.ReadFile(accountPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read account: %w", err)
	}

	var account AccountData
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("failed to parse account: %w", err)
	}
	return &account, nil
}

// AccountExists checks if an account exists for the given email
func (s *ACMECertStore) AccountExists(email string) bool {
	accountPath := filepath.Join(s.accountPath(email), "account.json")
	_, err := os.Stat(accountPath)
	return err == nil
}

// StoreAccountKey saves the ACME account private key
func (s *ACMECertStore) StoreAccountKey(email string, keyPEM []byte) error {
	accountDir := s.accountPath(email)
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return fmt.Errorf("failed to create account directory: %w", err)
	}

	if err := os.WriteFile(filepath.Join(accountDir, "account_key.pem"), keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write account_key.pem: %w", err)
	}
	return nil
}

// LoadAccountKey reads the ACME account private key
func (s *ACMECertStore) LoadAccountKey(email string) ([]byte, error) {
	keyPath := filepath.Join(s.accountPath(email), "account_key.pem")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read account key: %w", err)
	}
	return data, nil
}

// GetBasePath returns the base storage path
func (s *ACMECertStore) GetBasePath() string {
	return s.basePath
}

func (s *ACMECertStore) accountPath(email string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(email)))
	return filepath.Join(s.basePath, "acme", "accounts", hash[:16])
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
