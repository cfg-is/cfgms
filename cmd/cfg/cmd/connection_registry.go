// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ConnectionEntry stores non-secret metadata about a known controller connection.
// Credential and token material is never written to this file.
type ConnectionEntry struct {
	Name          string    `json:"name"`
	ControllerURL string    `json:"controller_url"`
	AdminIdentity string    `json:"admin_identity"`
	LastUsed      time.Time `json:"last_used"`
	UnlockMethod  string    `json:"unlock_method,omitempty"`
}

// ConnectionRegistry manages non-secret connection metadata persisted to connections.json.
type ConnectionRegistry struct {
	path string
}

// newConnectionRegistry creates a ConnectionRegistry backed by the cfgms user config directory.
// The cfgms directory is created at mode 0700 if it does not exist.
func newConnectionRegistry() (*ConnectionRegistry, error) {
	configDir, err := userConfigDirFn()
	if err != nil {
		return nil, fmt.Errorf("cannot determine user config directory: %w", err)
	}
	cfgmsDir := filepath.Join(configDir, "cfgms")
	// #nosec G301 - 0700 is intentional; traversable but private config directory
	if err := os.MkdirAll(cfgmsDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create cfgms config directory: %w", err)
	}
	return &ConnectionRegistry{path: filepath.Join(cfgmsDir, "connections.json")}, nil
}

// load reads existing entries from disk, returning an empty slice when the file does not exist.
func (r *ConnectionRegistry) load() ([]ConnectionEntry, error) {
	// #nosec G304 - path is constructed from userConfigDir + known subpath, never from user input
	data, err := os.ReadFile(r.path)
	if os.IsNotExist(err) {
		return []ConnectionEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read connections file: %w", err)
	}
	var entries []ConnectionEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("cannot parse connections file: %w", err)
	}
	return entries, nil
}

// save writes entries to disk at mode 0600.
func (r *ConnectionRegistry) save(entries []ConnectionEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal connections: %w", err)
	}
	// 0600: owner read/write only — this file sits next to the admin bundle
	if err := os.WriteFile(r.path, data, 0600); err != nil {
		return fmt.Errorf("cannot write connections file: %w", err)
	}
	return nil
}

// Register adds a new entry or overwrites an existing entry with the same name.
func (r *ConnectionRegistry) Register(entry ConnectionEntry) error {
	entries, err := r.load()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.Name == entry.Name {
			entries[i] = entry
			return r.save(entries)
		}
	}
	return r.save(append(entries, entry))
}

// Get returns the entry for the given name, or (nil, nil) when not found.
func (r *ConnectionRegistry) Get(name string) (*ConnectionEntry, error) {
	entries, err := r.load()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Name == name {
			cp := e
			return &cp, nil
		}
	}
	return nil, nil
}

// List returns all registered connection entries.
func (r *ConnectionRegistry) List() ([]ConnectionEntry, error) {
	return r.load()
}

// UpdateLastUsed updates the LastUsed timestamp for a named connection.
func (r *ConnectionRegistry) UpdateLastUsed(name string, t time.Time) error {
	entries, err := r.load()
	if err != nil {
		return err
	}
	for i, e := range entries {
		if e.Name == name {
			entries[i].LastUsed = t
			return r.save(entries)
		}
	}
	return fmt.Errorf("connection %q not found", name)
}

// Delete removes the named connection entry. Returns an error if the name does not exist.
func (r *ConnectionRegistry) Delete(name string) error {
	entries, err := r.load()
	if err != nil {
		return err
	}
	filtered := entries[:0]
	found := false
	for _, e := range entries {
		if e.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !found {
		return fmt.Errorf("connection %q not found", name)
	}
	return r.save(filtered)
}
