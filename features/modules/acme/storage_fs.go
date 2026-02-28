// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// #nosec G304 - ACME certificate store requires file system access for certificate management
package acme

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// fsCertBackend stores certificates as PEM files on the filesystem.
// This backend is used on all platforms for filesystem-based certificate storage.
type fsCertBackend struct {
	certsDir string // e.g. /var/lib/cfgms/certs/acme/certificates
}

// newFsCertBackend creates a new filesystem certificate backend.
func newFsCertBackend(certsDir string) (*fsCertBackend, error) {
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create certificates directory %s: %w", certsDir, err)
	}
	return &fsCertBackend{certsDir: certsDir}, nil
}

func (f *fsCertBackend) StoreCertificate(domain string, certPEM, keyPEM, issuerPEM []byte, meta *CertificateMetadata) error {
	certDir := f.certPath(domain)
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

func (f *fsCertBackend) LoadCertificate(domain string) (certPEM, keyPEM []byte, err error) {
	certDir := f.certPath(domain)

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

func (f *fsCertBackend) LoadCertificateMetadata(domain string) (*CertificateMetadata, error) {
	metaPath := filepath.Join(f.certPath(domain), "metadata.json")
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

func (f *fsCertBackend) DeleteCertificate(domain string) error {
	certDir := f.certPath(domain)
	if err := os.RemoveAll(certDir); err != nil {
		return fmt.Errorf("failed to delete certificate directory: %w", err)
	}
	return nil
}

func (f *fsCertBackend) CertificateExists(domain string) bool {
	certPath := filepath.Join(f.certPath(domain), "cert.pem")
	_, err := os.Stat(certPath)
	return err == nil
}

func (f *fsCertBackend) certPath(domain string) string {
	return filepath.Join(f.certsDir, domain)
}
