// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Package oskeychain implements a cross-platform OS-native secret-store provider
// for CFGMS. It holds the short-lived `cfg` session token in the operating
// system's own credential store so the token is never written to disk as
// cleartext.
//
// Backends (selected at build time):
//   - Windows: Credential Manager (CredRead/CredWrite/CredDelete, CRED_TYPE_GENERIC)
//   - macOS:   Keychain (security add/find/delete-generic-password)
//   - Linux:   Secret Service (libsecret) with a kernel session-keyring (keyctl)
//     fallback for headless hosts with no Secret Service.
//
// The provider stores only the small session token value. Larger credential
// bundles use the machine-bound encrypted-file path (a separate story) because
// a full bundle exceeds Windows Credential Manager's per-entry blob limit.
package oskeychain

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

const (
	providerName    = "oskeychain"
	providerVersion = "1.0.0"

	// serviceName groups CFGMS entries in OS stores that split identity into a
	// service + account pair (macOS Keychain, Secret Service attributes).
	serviceName = "cfgms" //nolint:unused // cross-platform: used by provider_darwin.go and provider_linux.go, invisible to a GOOS=windows lint run

	// maxSecretSize bounds the stored value to a session token. Windows
	// Credential Manager caps a CRED_TYPE_GENERIC blob at 2560 bytes
	// (CRED_MAX_CREDENTIAL_BLOB_SIZE = 5*512); larger bundles use the
	// encrypted-file path (story Out of Scope).
	maxSecretSize = 2560

	// maxKeyLength bounds the namespaced key (e.g. cfgms/session/<connection>).
	maxKeyLength = 256

	// casVersionKeySuffix names the companion OS-keychain entry
	// CompareAndSwapSecret uses to track a key's version, since the underlying
	// backend has no notion of versioning of its own (GetCapabilities reports
	// SupportsVersioning: false; GetSecret always reports Version 1).
	casVersionKeySuffix = "\x00cas-version"
)

// errSecretNotFound is the sentinel a backend returns when a key is absent.
// Store.GetSecret maps it to interfaces.ErrSecretNotFound.
var errSecretNotFound = errors.New("oskeychain: secret not found")

// backend is the platform-specific OS keychain implementation. Each platform
// file (provider_windows.go, provider_darwin.go, provider_linux.go) provides a
// concrete implementation and a platformNewBackend constructor.
type backend interface {
	// set stores value under key, overwriting any existing value.
	set(key string, value []byte) error
	// get returns the value stored under key, or errSecretNotFound.
	get(key string) ([]byte, error)
	// del removes the value stored under key. Absent keys are not an error.
	del(key string) error
	// available reports whether this backend can be used on the current host.
	available() bool
	// name identifies the backend for diagnostics.
	name() string
}

// Provider implements interfaces.SecretProvider using the host OS keychain.
type Provider struct{}

// Name returns the provider name.
func (p *Provider) Name() string { return providerName }

// Description returns a human-readable description.
func (p *Provider) Description() string {
	return "OS-native keychain secret storage (Windows Credential Manager, macOS Keychain, Linux Secret Service/keyring) for short-lived session tokens"
}

// GetVersion returns the provider version.
func (p *Provider) GetVersion() string { return providerVersion }

// GetCapabilities returns the provider's capabilities. The OS store encrypts at
// rest; the provider intentionally does not implement versioning, rotation,
// metadata, or listing (it holds only the session token).
func (p *Provider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsVersioning:     false,
		SupportsRotation:       false,
		SupportsEncryption:     true, // OS keychain encrypts at rest
		SupportsAuditTrail:     false,
		SupportsLeasing:        false,
		SupportsRenewal:        false,
		SupportsRevocation:     true, // DeleteSecret removes immediately
		SupportsMetadata:       false,
		SupportsTags:           false,
		SupportsAccessPolicies: false,
		MaxSecretSize:          maxSecretSize,
		MaxKeyLength:           maxKeyLength,
		EncryptionAlgorithm:    "os-native",
	}
}

// ClusterCapable returns true if this provider can serve as shared state across
// multiple CFGMS controller nodes in cluster mode.
func (p *Provider) ClusterCapable() bool { return false }

// Available reports whether a usable OS keychain backend exists on this host.
// It returns (false, nil) — never an error — when no backend is usable (e.g.
// Linux with neither Secret Service nor a kernel keyring), so callers fall back
// to the one-shot --bundle path rather than failing hard.
func (p *Provider) Available() (bool, error) {
	b, err := platformNewBackend()
	if err != nil {
		return false, nil
	}
	return b.available(), nil
}

// CreateSecretStore creates an OS-keychain-backed secret store. The config map
// is accepted for interface conformance but is unused — the backend is selected
// by platform.
func (p *Provider) CreateSecretStore(_ map[string]interface{}) (interfaces.SecretStore, error) {
	b, err := platformNewBackend()
	if err != nil {
		return nil, fmt.Errorf("oskeychain: no OS keychain backend available: %w", err)
	}
	if !b.available() {
		return nil, errors.New("oskeychain: no OS keychain backend available on this host")
	}
	return newStore(b), nil
}

// Store implements interfaces.SecretStore backed by an OS keychain. Only the
// three core operations are real; the remaining contract methods are
// unsupported (the provider holds a single short-lived token, not a versioned,
// listable secret database).
type Store struct {
	backend backend
	// casMu serializes CompareAndSwapSecret's read-check-write sequence against
	// the version companion entry. This is in-process only — oskeychain is not
	// cluster-capable (ClusterCapable returns false): it holds one local CLI
	// session token, not state shared across controller nodes.
	casMu sync.Mutex
}

// newStore wraps a backend in a Store.
func newStore(b backend) *Store { return &Store{backend: b} }

// StoreSecret persists the session token in the OS keychain.
func (s *Store) StoreSecret(_ context.Context, req *interfaces.SecretRequest) error {
	if req == nil {
		return errors.New("oskeychain: secret request is nil")
	}
	if req.Key == "" {
		return errors.New("oskeychain: secret key cannot be empty")
	}
	if len(req.Key) > maxKeyLength {
		return fmt.Errorf("oskeychain: secret key exceeds maximum length of %d characters", maxKeyLength)
	}
	if req.Value == "" {
		return errors.New("oskeychain: secret value cannot be empty")
	}
	if len(req.Value) > maxSecretSize {
		return fmt.Errorf("oskeychain: secret value exceeds maximum size of %d bytes", maxSecretSize)
	}
	if err := s.backend.set(req.Key, []byte(req.Value)); err != nil {
		return fmt.Errorf("oskeychain: store %q: %w", req.Key, err)
	}
	return nil
}

// GetSecret retrieves the session token from the OS keychain. Only Key and
// Value are populated — the OS store holds the token alone, not metadata.
func (s *Store) GetSecret(_ context.Context, key string) (*interfaces.Secret, error) {
	value, err := s.backend.get(key)
	if err != nil {
		if errors.Is(err, errSecretNotFound) {
			return nil, fmt.Errorf("oskeychain: %q: %w", key, interfaces.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("oskeychain: get %q: %w", key, err)
	}
	now := time.Now()
	return &interfaces.Secret{
		Key:       key,
		Value:     string(value),
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// DeleteSecret removes the session token from the OS keychain.
func (s *Store) DeleteSecret(_ context.Context, key string) error {
	if err := s.backend.del(key); err != nil {
		return fmt.Errorf("oskeychain: delete %q: %w", key, err)
	}
	return nil
}

// CompareAndSwapSecret implements interfaces.SecretStore.CompareAndSwapSecret. The
// backend has no atomic check-and-set primitive of its own, so this tracks a
// version number in a companion OS-keychain entry (key+casVersionKeySuffix) and
// serializes the read-check-write sequence with casMu.
//
// The interface's "an expired secret does not exist" rule needs no code here:
// this provider has no notion of expiry at all — StoreSecret ignores
// SecretRequest.TTL, GetSecret never refuses a record as expired, and nothing
// records an ExpiresAt — so no stored record can ever be in the expired state the
// rule is about. It holds one local CLI session token, not TTL-bounded claims.
func (s *Store) CompareAndSwapSecret(_ context.Context, key string, expectedVersion int, req *interfaces.SecretRequest) (int, bool, error) {
	if req == nil {
		return 0, false, errors.New("oskeychain: secret request is nil")
	}
	if req.Key == "" {
		return 0, false, errors.New("oskeychain: secret key cannot be empty")
	}
	if key == "" {
		return 0, false, errors.New("oskeychain: secret key cannot be empty")
	}
	if len(req.Key) > maxKeyLength {
		return 0, false, fmt.Errorf("oskeychain: secret key exceeds maximum length of %d characters", maxKeyLength)
	}
	if req.Value == "" {
		return 0, false, errors.New("oskeychain: secret value cannot be empty")
	}
	if len(req.Value) > maxSecretSize {
		return 0, false, fmt.Errorf("oskeychain: secret value exceeds maximum size of %d bytes", maxSecretSize)
	}

	s.casMu.Lock()
	defer s.casMu.Unlock()

	versionKey := req.Key + casVersionKeySuffix
	currentVersion := 0
	if raw, err := s.backend.get(versionKey); err == nil {
		if v, convErr := strconv.Atoi(string(raw)); convErr == nil {
			currentVersion = v
		}
	} else if !errors.Is(err, errSecretNotFound) {
		return 0, false, fmt.Errorf("oskeychain: read version for %q: %w", req.Key, err)
	}

	if currentVersion != expectedVersion {
		return 0, false, nil
	}

	if err := s.backend.set(req.Key, []byte(req.Value)); err != nil {
		return 0, false, fmt.Errorf("oskeychain: compare-and-swap %q: %w", req.Key, err)
	}
	newVersion := currentVersion + 1
	if err := s.backend.set(versionKey, []byte(strconv.Itoa(newVersion))); err != nil {
		return 0, false, fmt.Errorf("oskeychain: persist version for %q: %w", req.Key, err)
	}
	return newVersion, true, nil
}

// unsupported wraps errors.ErrUnsupported with the operation name. The OS
// keychain provider deliberately implements only the three core operations.
func unsupported(op string) error {
	return fmt.Errorf("oskeychain: %s not supported by oskeychain provider: %w", op, errors.ErrUnsupported)
}

// ListSecrets is not supported.
func (s *Store) ListSecrets(_ context.Context, _ *interfaces.SecretFilter) ([]*interfaces.SecretMetadata, error) {
	return nil, unsupported("ListSecrets")
}

// GetSecrets is not supported.
func (s *Store) GetSecrets(_ context.Context, _ []string) (map[string]*interfaces.Secret, error) {
	return nil, unsupported("GetSecrets")
}

// StoreSecrets is not supported.
func (s *Store) StoreSecrets(_ context.Context, _ map[string]*interfaces.SecretRequest) error {
	return unsupported("StoreSecrets")
}

// GetSecretVersion is not supported.
func (s *Store) GetSecretVersion(_ context.Context, _ string, _ int) (*interfaces.Secret, error) {
	return nil, unsupported("GetSecretVersion")
}

// ListSecretVersions is not supported.
func (s *Store) ListSecretVersions(_ context.Context, _ string) ([]*interfaces.SecretVersion, error) {
	return nil, unsupported("ListSecretVersions")
}

// GetSecretMetadata is not supported.
func (s *Store) GetSecretMetadata(_ context.Context, _ string) (*interfaces.SecretMetadata, error) {
	return nil, unsupported("GetSecretMetadata")
}

// UpdateSecretMetadata is not supported.
func (s *Store) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return unsupported("UpdateSecretMetadata")
}

// RotateSecret is not supported.
func (s *Store) RotateSecret(_ context.Context, _ string, _ string) error {
	return unsupported("RotateSecret")
}

// ExpireSecret is not supported.
func (s *Store) ExpireSecret(_ context.Context, _ string) error {
	return unsupported("ExpireSecret")
}

// HealthCheck is a no-op — the OS keychain has no connection to verify.
func (s *Store) HealthCheck(_ context.Context) error { return nil }

// Close is a no-op — the OS keychain holds no open handles.
func (s *Store) Close() error { return nil }

// Auto-register this provider (Salt-style).
func init() {
	interfaces.RegisterSecretProvider(&Provider{})
}
