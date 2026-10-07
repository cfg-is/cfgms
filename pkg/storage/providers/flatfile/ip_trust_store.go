// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.IPTrustStore = (*FlatFileIPTrustStore)(nil)

// FlatFileIPTrustStore implements business.IPTrustStore backed by a single JSON file.
//
// File layout: <root>/ip-trust/ip_trust.json
//
// All entries across all tenants are stored in a flat JSON array. Writes are
// atomic (temp-file + rename). sync.RWMutex serializes goroutine access within
// one process.
type FlatFileIPTrustStore struct {
	root string
	mu   sync.RWMutex
}

// ipTrustEntryJSON is the on-disk representation of an IP trust entry.
type ipTrustEntryJSON struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	CIDR           string     `json:"cidr"`
	PreSeeded      bool       `json:"pre_seeded"`
	TrustedSince   time.Time  `json:"trusted_since"`
	LastActivity   *time.Time `json:"last_activity,omitempty"`
	LastActivityIP string     `json:"last_activity_ip,omitempty"`
	Revoked        bool       `json:"revoked"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

// NewFlatFileIPTrustStore creates a FlatFileIPTrustStore rooted at <root>/ip-trust.
// The directory is created if it does not exist.
func NewFlatFileIPTrustStore(root string) (*FlatFileIPTrustStore, error) {
	dir := filepath.Join(root, "ip-trust")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create ip-trust directory: %w", err)
	}
	return &FlatFileIPTrustStore{root: root}, nil
}

func (s *FlatFileIPTrustStore) dataFilePath() string {
	return filepath.Join(s.root, "ip-trust", "ip_trust.json")
}

// load reads and parses the ip_trust.json file.
// Returns nil slice when the file does not exist.
// Must be called with at least a read lock held.
func (s *FlatFileIPTrustStore) load() ([]ipTrustEntryJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read ip trust file: %w", err)
	}
	var entries []ipTrustEntryJSON
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse ip trust file: %w", err)
	}
	return entries, nil
}

// save atomically writes entries to ip_trust.json.
// Must be called with a write lock held.
func (s *FlatFileIPTrustStore) save(entries []ipTrustEntryJSON) error {
	if entries == nil {
		entries = []ipTrustEntryJSON{}
	}
	raw, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal ip trust entries: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

// normalizeCIDR returns the network-address form of cidr (e.g. "192.168.1.0/24").
func normalizeCIDR(cidr string) (string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	return ipNet.String(), nil
}

// AddTrustedRange implements IPTrustStore.AddTrustedRange.
// CIDR is normalised before storage. A previously revoked entry is re-activated.
func (s *FlatFileIPTrustStore) AddTrustedRange(_ context.Context, tenantID, cidr string, preSeeded bool) error {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}

	for i, e := range entries {
		if e.TenantID == tenantID && e.CIDR == normalized {
			entries[i].PreSeeded = preSeeded
			entries[i].TrustedSince = time.Now().UTC()
			entries[i].Revoked = false
			entries[i].RevokedAt = nil
			return s.save(entries)
		}
	}

	entries = append(entries, ipTrustEntryJSON{
		ID:           uuid.New().String(),
		TenantID:     tenantID,
		CIDR:         normalized,
		PreSeeded:    preSeeded,
		TrustedSince: time.Now().UTC(),
	})
	return s.save(entries)
}

// IsTrusted implements IPTrustStore.IsTrusted.
// Containment is evaluated in Go via net.ParseCIDR + ipNet.Contains.
func (s *FlatFileIPTrustStore) IsTrusted(_ context.Context, tenantID, ip string) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := s.load()
	if err != nil {
		return false, err
	}

	for _, e := range entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		_, ipNet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue // skip malformed stored entries
		}
		if ipNet.Contains(parsedIP) {
			return true, nil
		}
	}
	return false, nil
}

// ListTrustedRanges implements IPTrustStore.ListTrustedRanges.
// Returns all entries for the tenant (including revoked).
func (s *FlatFileIPTrustStore) ListTrustedRanges(_ context.Context, tenantID string) ([]*business.IPTrustEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := s.load()
	if err != nil {
		return nil, err
	}

	var result []*business.IPTrustEntry
	for _, e := range entries {
		if e.TenantID != tenantID {
			continue
		}
		entry := &business.IPTrustEntry{
			ID:           e.ID,
			TenantID:     e.TenantID,
			CIDR:         e.CIDR,
			PreSeeded:    e.PreSeeded,
			TrustedSince: e.TrustedSince,
			Revoked:      e.Revoked,
			RevokedAt:    e.RevokedAt,
		}
		if e.LastActivity != nil {
			entry.LastActivity = *e.LastActivity
		}
		result = append(result, entry)
	}
	return result, nil
}

// RevokeTrustedRange implements IPTrustStore.RevokeTrustedRange.
// Returns ErrIPTrustEntryNotFound if no non-revoked entry exists for (tenantID, cidr).
func (s *FlatFileIPTrustStore) RevokeTrustedRange(_ context.Context, tenantID, cidr string) error {
	normalized, err := normalizeCIDR(cidr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}

	for i, e := range entries {
		if e.TenantID == tenantID && e.CIDR == normalized && !e.Revoked {
			now := time.Now().UTC()
			entries[i].Revoked = true
			entries[i].RevokedAt = &now
			return s.save(entries)
		}
	}
	return business.ErrIPTrustEntryNotFound
}

// RecordHealthySteward implements IPTrustStore.RecordHealthySteward.
// Finds the CIDR entry containing ip and updates last_activity / last_activity_ip.
// No-op if no matching non-revoked entry exists.
func (s *FlatFileIPTrustStore) RecordHealthySteward(_ context.Context, tenantID, ip string, at time.Time) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.load()
	if err != nil {
		return err
	}

	for i, e := range entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		_, ipNet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			t := at.UTC()
			entries[i].LastActivity = &t
			entries[i].LastActivityIP = ip
			return s.save(entries)
		}
	}
	return nil // no matching entry — no-op per spec
}

// GetLastActivity implements IPTrustStore.GetLastActivity.
// Returns nil, nil when no matching entry or no activity has been recorded.
func (s *FlatFileIPTrustStore) GetLastActivity(_ context.Context, tenantID, ip string) (*business.IPTrustActivity, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := s.load()
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if e.TenantID != tenantID || e.Revoked {
			continue
		}
		_, ipNet, err := net.ParseCIDR(e.CIDR)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			if e.LastActivity == nil {
				return nil, nil
			}
			return &business.IPTrustActivity{
				TenantID: tenantID,
				IP:       ip,
				LastSeen: *e.LastActivity,
			}, nil
		}
	}
	return nil, nil
}
