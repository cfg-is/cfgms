// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// identityFileName is the name of the on-disk steward identity file,
// stored alongside the cert store in defaultCertStoreDir().
const identityFileName = "steward-identity.json"

// StewardIdentity is the persisted record written after first HTTP registration
// and read on subsequent startups to skip re-registration.
// The client private key is NOT stored here; it lives in the cert store.
// A tampered transport address fails the mTLS server-cert check against the
// stored CA PEM; a tampered steward/tenant ID is overridden by the
// authenticated-CN-wins contract on the controller side.
type StewardIdentity struct {
	StewardID        string `json:"steward_id"`
	TenantID         string `json:"tenant_id"`
	TransportAddress string `json:"transport_address"`
	CACertPEM        string `json:"ca_cert_pem"`
}

// saveIdentity writes id to dir/steward-identity.json with permissions 0600
// (owner read/write only; no group or world access).
// The write is atomic: content goes to a temp file then renamed into place.
func saveIdentity(dir string, id StewardIdentity) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create identity dir: %w", err)
	}
	data, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	path := filepath.Join(dir, identityFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit identity file: %w", err)
	}
	return nil
}

// loadIdentity reads dir/steward-identity.json.
// Returns (nil, nil) when the file does not exist — caller falls through to
// HTTP re-registration (first-run or manually deleted identity).
// Returns (nil, err) on read/parse failure — caller should log and fall through
// to HTTP re-registration; the corrupt file is not fatal.
func loadIdentity(dir string) (*StewardIdentity, error) {
	path := filepath.Join(dir, identityFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	var id StewardIdentity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("identity file corrupt (JSON parse failed): %w", err)
	}
	if id.StewardID == "" || id.TransportAddress == "" {
		return nil, fmt.Errorf("identity file missing required fields (steward_id or transport_address)")
	}
	return &id, nil
}
