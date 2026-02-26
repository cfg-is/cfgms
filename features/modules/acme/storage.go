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
	"time"
)

// ACMECertStore manages the local filesystem layout for ACME certificates and accounts
type ACMECertStore struct {
	basePath string
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

// NewACMECertStore creates a new certificate store at the given base path
func NewACMECertStore(basePath string) (*ACMECertStore, error) {
	if basePath == "" {
		basePath = defaultCertStorePath()
	}

	store := &ACMECertStore{basePath: basePath}

	// Ensure base directories exist
	dirs := []string{
		filepath.Join(basePath, "acme", "accounts"),
		filepath.Join(basePath, "acme", "certificates"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return store, nil
}

// StoreCertificate writes certificate files to the store
func (s *ACMECertStore) StoreCertificate(domain string, certPEM, keyPEM, issuerPEM []byte, meta *CertificateMetadata) error {
	certDir := s.certPath(domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Write cert.pem (parent directory is 0700, so 0600 is sufficient)
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write cert.pem: %w", err)
	}

	// Write key.pem (owner-only)
	if err := os.WriteFile(filepath.Join(certDir, "key.pem"), keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key.pem: %w", err)
	}

	// Write issuer.pem if provided
	if len(issuerPEM) > 0 {
		if err := os.WriteFile(filepath.Join(certDir, "issuer.pem"), issuerPEM, 0600); err != nil {
			return fmt.Errorf("failed to write issuer.pem: %w", err)
		}
	}

	// Write metadata
	if meta != nil {
		metaJSON, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		if err := os.WriteFile(filepath.Join(certDir, "metadata.json"), metaJSON, 0600); err != nil {
			return fmt.Errorf("failed to write metadata.json: %w", err)
		}
	}

	return nil
}

// LoadCertificate reads the certificate and key for a domain
func (s *ACMECertStore) LoadCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	certDir := s.certPath(domain)

	certPEM, err = os.ReadFile(filepath.Join(certDir, "cert.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cert.pem: %w", err)
	}

	keyPEM, err = os.ReadFile(filepath.Join(certDir, "key.pem"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key.pem: %w", err)
	}

	return certPEM, keyPEM, nil
}

// LoadCertificateMetadata reads the metadata for a domain's certificate
func (s *ACMECertStore) LoadCertificateMetadata(domain string) (*CertificateMetadata, error) {
	metaPath := filepath.Join(s.certPath(domain), "metadata.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var meta CertificateMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}
	return &meta, nil
}

// DeleteCertificate removes all certificate files for a domain
func (s *ACMECertStore) DeleteCertificate(domain string) error {
	certDir := s.certPath(domain)
	if err := os.RemoveAll(certDir); err != nil {
		return fmt.Errorf("failed to delete certificate directory: %w", err)
	}
	return nil
}

// CertificateExists checks if a certificate exists for the given domain
func (s *ACMECertStore) CertificateExists(domain string) bool {
	certPath := filepath.Join(s.certPath(domain), "cert.pem")
	_, err := os.Stat(certPath)
	return err == nil
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

func (s *ACMECertStore) certPath(domain string) string {
	return filepath.Join(s.basePath, "acme", "certificates", domain)
}

func (s *ACMECertStore) accountPath(email string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(email)))
	return filepath.Join(s.basePath, "acme", "accounts", hash[:16])
}

func defaultCertStorePath() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "cfgms", "certs")
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "cfgms", "certs")
	default: // linux and others
		return "/var/lib/cfgms/certs"
	}
}
