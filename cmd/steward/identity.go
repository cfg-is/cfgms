// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// identityFileName is the name of the on-disk steward identity file,
// stored alongside the cert store in defaultCertStoreDir().
// pendingStateFileName is the name of the on-disk pending registration state file.
// Stored alongside the identity file in defaultCertStoreDir() so restarts resume
// the same pending record rather than creating a new one on each restart (Issue #1899).
const pendingStateFileName = "steward-pending.json"

// PendingState holds the pending registration ID issued by the controller when
// registration.workflow is set to "manual". Persisted between restarts so the
// steward resumes polling the same record instead of creating duplicate entries.
type PendingState struct {
	PendingID string `json:"pending_id"`
}

// savePendingState writes state to dir/steward-pending.json with permissions 0600.
// The write is atomic: content goes to a temp file then renamed into place.
func savePendingState(dir string, state PendingState) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create pending state dir: %w", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal pending state: %w", err)
	}
	path := filepath.Join(dir, pendingStateFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write pending state file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit pending state file: %w", err)
	}
	return nil
}

// loadPendingState reads dir/steward-pending.json.
// Returns (nil, nil) when the file does not exist — caller performs fresh registration.
// Returns (nil, err) on read/parse failure.
func loadPendingState(dir string) (*PendingState, error) {
	path := filepath.Join(dir, pendingStateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read pending state file: %w", err)
	}
	var state PendingState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("pending state file corrupt (JSON parse failed): %w", err)
	}
	if state.PendingID == "" {
		return nil, fmt.Errorf("pending state file missing pending_id")
	}
	return &state, nil
}

// clearPendingState removes dir/steward-pending.json if it exists.
// Returns nil when the file does not exist (no-op).
func clearPendingState(dir string) error {
	path := filepath.Join(dir, pendingStateFileName)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear pending state file: %w", err)
	}
	return nil
}

// identityFileName is the name of the on-disk steward identity file,
// stored alongside the cert store in defaultCertStoreDir().
const identityFileName = "steward-identity.json"

// StewardIdentity is the persisted record written after first HTTP registration
// and read on subsequent startups to skip re-registration.
// The client private key is NOT stored here; it lives in the cert store.
// A tampered transport address fails the mTLS server-cert check against the
// stored CA PEM; a tampered steward/tenant ID is overridden by the
// authenticated-CN-wins contract on the controller side.
//
// ServerCertPEM and SigningCertPEMs are the controller's signature-verification
// certificates. They are persisted so the reconnect path can verify signed
// sync_config commands without HTTP re-registration — without them the steward
// reconnects but silently rejects every signed command and stops converging.
//
// SigningCertPEM (singular) is kept for backward-compatible reading of identity
// files written before multi-cert support. loadIdentity migrates it into
// SigningCertPEMs automatically on read.
//
// TrustMode and CAPinFingerprint record the trust anchor established at enrollment
// (ADR-013 §3). The downgrade guard uses these to ensure trust is never silently
// weakened across restarts or re-enrollments.
type StewardIdentity struct {
	StewardID        string     `json:"steward_id"`
	TenantID         string     `json:"tenant_id"`
	TransportAddress string     `json:"transport_address"`
	CACertPEM        string     `json:"ca_cert_pem"`
	ServerCertPEM    string     `json:"server_cert_pem,omitempty"`
	SigningCertPEM   string     `json:"signing_cert_pem,omitempty"`   // backward compat: single cert (legacy)
	SigningCertPEMs  []string   `json:"signing_cert_pems,omitempty"`  // Issue #1816: mutable rotation set
	OverlapExpiresAt *time.Time `json:"overlap_expires_at,omitempty"` // Issue #1816: rotation overlap deadline
	// Device identity fields (Issue #2094): stable across mTLS cert rotations.
	DeviceID       string `json:"device_id,omitempty"`        // 64-char lowercase hex SHA-256 of Ed25519 public key
	IdentityKeyPub string `json:"identity_key_pub,omitempty"` // base64-encoded Ed25519 public key (32 bytes)
	// Trust anchor fields (ADR-013 §3, Issue #1517).
	TrustMode        string `json:"trust_mode,omitempty"`         // "compile-baked", "install-pinned", "tofu"
	CAPinFingerprint string `json:"ca_pin_fingerprint,omitempty"` // SHA-256 hex of pinned CA cert (install-pinned and TOFU)
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
//
// Backward compat: if SigningCertPEMs is empty and SigningCertPEM is set,
// SigningCertPEMs is seeded from the singular cert so callers need not handle
// the legacy field.
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
	// Migrate legacy single-cert field into the mutable slice on read.
	if len(id.SigningCertPEMs) == 0 && id.SigningCertPEM != "" {
		id.SigningCertPEMs = []string{id.SigningCertPEM}
	}
	return &id, nil
}
