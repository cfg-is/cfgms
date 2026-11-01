// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

const signingTrustAckFileName = "signing-trust-acks.json"

// signingTrustAckFile is the on-disk JSON format.
type signingTrustAckFile struct {
	Acks []certinterfaces.SigningTrustAck `json:"acks"`
}

// fileSigningTrustAckStore is the node-local SigningTrustAckStore: a JSON file
// at basePath/signing-trust-acks.json, re-read on every call so a record
// written by another process is visible, and written via temp-rename so a
// crash never leaves a half-written file.
type fileSigningTrustAckStore struct {
	mu       sync.Mutex
	filePath string
}

// NewFileSigningTrustAckStore returns the node-local, file-backed
// SigningTrustAckStore. A clustered controller selects the PostgreSQL-backed
// implementation through pkg/storage instead.
func NewFileSigningTrustAckStore(basePath string) (certinterfaces.SigningTrustAckStore, error) {
	if basePath == "" {
		return nil, fmt.Errorf("signing trust ack store: base path is required")
	}
	if err := os.MkdirAll(basePath, 0750); err != nil {
		return nil, fmt.Errorf("signing trust ack store: failed to create storage directory: %w", err)
	}
	return &fileSigningTrustAckStore{filePath: filepath.Join(basePath, signingTrustAckFileName)}, nil
}

func validateAckKey(stewardID, serial string) error {
	if stewardID == "" {
		return fmt.Errorf("signing trust ack: steward ID cannot be empty")
	}
	if serial == "" {
		return fmt.Errorf("signing trust ack: serial cannot be empty")
	}
	return nil
}

// loadLocked reads the file; a missing file is an empty list. Caller holds mu.
func (s *fileSigningTrustAckStore) loadLocked() ([]certinterfaces.SigningTrustAck, error) {
	// #nosec G304 -- path is controlled: constructed from the cert manager's storage path
	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read signing trust acks: %w", err)
	}
	var f signingTrustAckFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("failed to parse signing trust acks: %w", err)
	}
	return f.Acks, nil
}

// saveLocked writes acks atomically. Caller holds mu.
func (s *fileSigningTrustAckStore) saveLocked(acks []certinterfaces.SigningTrustAck) error {
	data, err := json.MarshalIndent(signingTrustAckFile{Acks: acks}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signing trust acks: %w", err)
	}
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write signing trust acks: %w", err)
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize signing trust acks: %w", err)
	}
	return nil
}

// RecordAck implements certinterfaces.SigningTrustAckStore.RecordAck.
func (s *fileSigningTrustAckStore) RecordAck(_ context.Context, stewardID, serial string) error {
	if err := validateAckKey(stewardID, serial); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acks, err := s.loadLocked()
	if err != nil {
		return err
	}
	for _, a := range acks {
		if a.StewardID == stewardID && a.Serial == serial {
			return nil
		}
	}
	acks = append(acks, certinterfaces.SigningTrustAck{
		StewardID: stewardID, Serial: serial, AcknowledgedAt: time.Now().UTC(),
	})
	return s.saveLocked(acks)
}

// GetAck implements certinterfaces.SigningTrustAckStore.GetAck.
func (s *fileSigningTrustAckStore) GetAck(_ context.Context, stewardID, serial string) (*certinterfaces.SigningTrustAck, error) {
	if err := validateAckKey(stewardID, serial); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acks, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	for _, a := range acks {
		if a.StewardID == stewardID && a.Serial == serial {
			ack := a
			return &ack, nil
		}
	}
	return nil, nil
}

// ListAcked implements certinterfaces.SigningTrustAckStore.ListAcked.
func (s *fileSigningTrustAckStore) ListAcked(_ context.Context, serial string) ([]certinterfaces.SigningTrustAck, error) {
	if serial == "" {
		return nil, fmt.Errorf("signing trust ack: serial cannot be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	acks, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	out := []certinterfaces.SigningTrustAck{}
	for _, a := range acks {
		if a.Serial == serial {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StewardID < out[j].StewardID })
	return out, nil
}
