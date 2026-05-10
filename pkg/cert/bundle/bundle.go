// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package bundle provides read/write support for the CFGMS admin credential bundle.
//
// The bundle file (admin.bundle.yaml, mode 0600) contains everything the cfg CLI
// needs to authenticate as a CFGMS admin: the mTLS client certificate and key,
// the CA certificate for server verification, the controller URL, an audit subject,
// and identifiers for revocation lookup.
package bundle

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Bundle holds the contents of an admin credential bundle file.
type Bundle struct {
	CertPEM         string `yaml:"cert_pem"`
	KeyPEM          string `yaml:"key_pem"`
	CAPEM           string `yaml:"ca_pem"`
	ControllerURL   string `yaml:"controller_url"`
	AuditSubject    string `yaml:"audit_subject"`
	CertSerial      string `yaml:"cert_serial"`
	CertFingerprint string `yaml:"cert_fingerprint"`
}

// Write serializes b to YAML and atomically writes it to path with mode 0600.
// The caller is responsible for chown on Linux if daemon-user ownership is required.
func Write(path string, b *Bundle) error {
	data, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write bundle temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize bundle file: %w", err)
	}

	return nil
}

// Read parses the YAML bundle at path and returns the Bundle.
func Read(path string) (*Bundle, error) {
	// #nosec G304 -- caller-controlled path; bundle files live under /etc/cfgms (root-owned)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	var b Bundle
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	return &b, nil
}
