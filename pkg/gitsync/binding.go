// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gitsync

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// MinPollingInterval is the minimum allowed polling interval. Bindings that
	// configure a shorter interval are rejected at Add time.
	MinPollingInterval = 60 * time.Second

	bindingsFileName = "bindings.json"
	bindingsDir      = ".gitsync"
)

// ScopeBinding describes a binding from a config scope (tenant path + namespace)
// to an external git origin.
type ScopeBinding struct {
	// TenantPath is the CFGMS tenant path, e.g. "root/msp-a/client-1".
	TenantPath string `json:"tenant_path"`

	// Namespace is the config namespace that the bound origin supplies, e.g.
	// "firewall". All files imported from the origin are stored under this
	// namespace.
	Namespace string `json:"namespace"`

	// OriginURL is the URL of the external git repository (HTTPS or local path).
	OriginURL string `json:"origin_url"`

	// Branch is the branch to track. Defaults to "main" when empty.
	Branch string `json:"branch"`

	// CredentialsRef is the credential reference used to authenticate to the
	// git origin. Accepted formats:
	//   - "" (empty): anonymous access
	//   - "env:<VAR>": read the password from environment variable VAR
	//   - any other string: treat as a file path and read the password from it
	//
	// TODO: migrate to pkg/secrets SecretStore once sub-story H lands.
	CredentialsRef string `json:"credentials_ref,omitempty"`

	// WebhookSecretRef is the credential reference for the HMAC-SHA256 webhook
	// secret. Same resolution rules as CredentialsRef. When empty, HMAC
	// validation is skipped for this binding.
	WebhookSecretRef string `json:"webhook_secret_ref,omitempty"`

	// PollingInterval is how often to poll the origin for changes. Must be
	// >= MinPollingInterval (60 s) when non-zero. Zero disables polling;
	// only webhook-triggered syncs occur.
	PollingInterval time.Duration `json:"polling_interval,omitempty"`

	// LastSyncedSHA is the commit SHA of the last successful sync. This field is
	// managed by the BindingStore; do not set it manually.
	LastSyncedSHA string `json:"last_synced_sha,omitempty"`
}

// key returns a unique string identifier for this binding.
func (b ScopeBinding) key() string {
	return b.TenantPath + "/" + b.Namespace
}

// validate returns an error if the binding is misconfigured.
func (b ScopeBinding) validate() error {
	if b.TenantPath == "" {
		return fmt.Errorf("gitsync: ScopeBinding has empty TenantPath")
	}
	if b.Namespace == "" {
		return fmt.Errorf("gitsync: ScopeBinding has empty Namespace")
	}
	if b.OriginURL == "" {
		return fmt.Errorf("gitsync: ScopeBinding has empty OriginURL")
	}
	if b.PollingInterval != 0 && b.PollingInterval < MinPollingInterval {
		return ErrIntervalTooShort
	}
	return nil
}

// BindingStore manages scope bindings persisted to a JSON file located at
// <configRoot>/.gitsync/bindings.json.
type BindingStore struct {
	mu       sync.RWMutex
	path     string
	bindings map[string]ScopeBinding
}

// NewBindingStore creates or opens the binding store rooted at configRoot.
// The directory is created if it does not already exist.
func NewBindingStore(configRoot string) (*BindingStore, error) {
	dir := filepath.Join(configRoot, bindingsDir)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("gitsync: failed to create bindings directory: %w", err)
	}
	bs := &BindingStore{
		path:     filepath.Join(dir, bindingsFileName),
		bindings: make(map[string]ScopeBinding),
	}
	if err := bs.load(); err != nil {
		return nil, err
	}
	return bs, nil
}

// load reads bindings from disk. Succeeds silently if the file does not yet
// exist.
func (bs *BindingStore) load() error {
	data, err := os.ReadFile(bs.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("gitsync: failed to read bindings file: %w", err)
	}
	var list []ScopeBinding
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("gitsync: failed to parse bindings file: %w", err)
	}
	for _, b := range list {
		bs.bindings[b.key()] = b
	}
	return nil
}

// save writes all bindings to disk atomically (write-then-rename).
// Callers must hold bs.mu.Lock().
func (bs *BindingStore) save() error {
	list := make([]ScopeBinding, 0, len(bs.bindings))
	for _, b := range bs.bindings {
		list = append(list, b)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("gitsync: failed to marshal bindings: %w", err)
	}
	tmp := bs.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return fmt.Errorf("gitsync: failed to write bindings temp file: %w", err)
	}
	if err := os.Rename(tmp, bs.path); err != nil {
		return fmt.Errorf("gitsync: failed to rename bindings file: %w", err)
	}
	return nil
}

// Add adds or replaces a binding and persists it to disk. Returns
// ErrIntervalTooShort when the polling interval is non-zero and below the
// minimum.
func (bs *BindingStore) Add(b ScopeBinding) error {
	if err := b.validate(); err != nil {
		return err
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.bindings[b.key()] = b
	return bs.save()
}

// Remove removes a binding by tenant path and namespace. No-op if the binding
// does not exist.
func (bs *BindingStore) Remove(tenantPath, namespace string) error {
	key := tenantPath + "/" + namespace
	bs.mu.Lock()
	defer bs.mu.Unlock()
	delete(bs.bindings, key)
	return bs.save()
}

// Get returns a binding by tenant path and namespace. Returns false if the
// binding does not exist.
func (bs *BindingStore) Get(tenantPath, namespace string) (ScopeBinding, bool) {
	key := tenantPath + "/" + namespace
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	b, ok := bs.bindings[key]
	return b, ok
}

// List returns all bindings in an unspecified order.
func (bs *BindingStore) List() []ScopeBinding {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]ScopeBinding, 0, len(bs.bindings))
	for _, b := range bs.bindings {
		out = append(out, b)
	}
	return out
}

// UpdateSHA records the last-synced commit SHA for the given binding. Returns an
// error if the binding does not exist.
func (bs *BindingStore) UpdateSHA(tenantPath, namespace, sha string) error {
	key := tenantPath + "/" + namespace
	bs.mu.Lock()
	defer bs.mu.Unlock()
	b, ok := bs.bindings[key]
	if !ok {
		return fmt.Errorf("gitsync: binding not found for %s/%s", tenantPath, namespace)
	}
	b.LastSyncedSHA = sha
	bs.bindings[key] = b
	return bs.save()
}
