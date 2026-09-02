// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sops implements authenticated envelope-encrypted secret storage.
package sops

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	storageif "github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// SOPSSecretStoreConfig provides configuration for SOPS secret store
type SOPSSecretStoreConfig struct {
	StorageProvider string                 // Storage provider name (default: "flatfile")
	StorageConfig   map[string]interface{} // Storage provider configuration
	CacheEnabled    bool                   // Enable secret caching
	CacheTTL        int                    // Cache TTL in seconds
	CacheMaxSize    int                    // Maximum cache size
	KeyFile         string                 // External 32-byte or base64-encoded AES key file
}

// SOPSSecretStore stores encrypted ConfigEntry objects in a configured
// ConfigStore. The historical provider name is retained for compatibility.
type SOPSSecretStore struct {
	configStore  cfgconfig.ConfigStore // Underlying config store (backend-agnostic, SOPS-encrypted)
	cache        *cache.Cache          // Secret cache
	config       *SOPSSecretStoreConfig
	providerName string
	aead         cipher.AEAD

	// conditionalStore is the backing ConfigStore when it can perform an atomic
	// conditional write itself (PostgreSQL: "UPDATE ... WHERE version = $expected").
	// Non-nil is what makes CompareAndSwapSecret atomic across controller nodes;
	// nil means the file-lock fallback below is in use and the guarantee stops at
	// the boundary of a shared filesystem. Resolved once at construction so the
	// property a caller relies on cannot change per call (Issue #3775).
	conditionalStore cfgconfig.ConditionalConfigStore

	// casLockRoot is the directory CompareAndSwapSecret places lock files in when
	// conditionalStore is nil. Empty means no private lock root could be derived
	// and CompareAndSwapSecret refuses rather than degrading to a shared location;
	// casUnavailableErr carries the reason.
	casLockRoot       string
	casUnavailableErr error
}

type encryptedEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// NewSOPSSecretStore creates a new SOPS-based secret store
// M-AUTH-1: Create an envelope-encrypted store backed by the configured
// ConfigStore. The encryption key must be provisioned separately from data.
func NewSOPSSecretStore(config *SOPSSecretStoreConfig) (*SOPSSecretStore, error) {
	if config == nil {
		return nil, fmt.Errorf("secret store config is required")
	}
	key, err := loadExternalKey(config)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize AES-GCM: %w", err)
	}

	// Create ConfigStore using storage provider
	configStore, err := storageif.CreateConfigStoreFromConfig(config.StorageProvider, config.StorageConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create config store: %w", err)
	}

	store := &SOPSSecretStore{
		configStore:  configStore,
		config:       config,
		providerName: config.StorageProvider,
		aead:         aead,
	}

	// Resolve the compare-and-swap strategy once, here, so that
	// CompareAndSwapIsClusterAtomic reports a stable property of this store rather
	// than something re-derived per call. Preference order is not arbitrary: a
	// backend that can decide the comparison and the write in one storage-layer
	// operation is the only shape whose atomicity survives a second controller node,
	// so it wins whenever it is available (Issue #3775).
	if conditional, ok := configStore.(cfgconfig.ConditionalConfigStore); ok {
		store.conditionalStore = conditional
	} else if lockRoot, lockErr := casLockDir(config); lockErr == nil {
		store.casLockRoot = lockRoot
	} else {
		store.casUnavailableErr = lockErr
	}

	// Initialize cache if enabled
	if config.CacheEnabled {
		cacheConfig := cache.CacheConfig{
			Name:            "sops-secrets",
			DefaultTTL:      time.Duration(config.CacheTTL) * time.Second,
			MaxRuntimeItems: config.CacheMaxSize,
			CleanupInterval: 5 * time.Minute,
		}
		store.cache = cache.NewCache(cacheConfig)
	}

	return store, nil
}

// isSystemdCredentialPath reports whether keyPath is a file systemd's
// LoadCredential= exposed. Such files are always mode 0440 (owner+group read)
// when the unit runs as a non-root User= — access is actually scoped to this
// single unit invocation via a POSIX ACL, not by the raw group-owner bits the
// mode alone implies. Without this exception, the strict permission check
// below would reject every systemd-credential-backed key file, which is the
// documented, intended way to deliver CFGMS_SECRETS_KEY_FILE without ever
// writing the key to a process-accessible path on real disk (see
// tier1-bootstrap.sh / ha-cluster-node-bootstrap.sh's LoadCredential +
// InaccessiblePaths pairing).
func isSystemdCredentialPath(keyPath string) bool {
	return strings.HasPrefix(keyPath, "/run/credentials/")
}

func loadExternalKey(config *SOPSSecretStoreConfig) ([]byte, error) {
	if strings.TrimSpace(config.KeyFile) == "" {
		return nil, fmt.Errorf("external encryption key file is required")
	}

	keyPath, err := filepath.Abs(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("resolve encryption key file: %w", err)
	}
	if root, ok := config.StorageConfig["root"].(string); ok && strings.TrimSpace(root) != "" {
		rootPath, rootErr := filepath.Abs(root)
		if rootErr != nil {
			return nil, fmt.Errorf("resolve secret storage root: %w", rootErr)
		}
		rel, relErr := filepath.Rel(rootPath, keyPath)
		if relErr != nil {
			return nil, fmt.Errorf("compare key and storage paths: %w", relErr)
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
			return nil, fmt.Errorf("encryption key file must be stored separately from secret data")
		}
	}

	info, err := os.Lstat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat encryption key file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("encryption key file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("encryption key file must be a regular file")
	}
	if runtime.GOOS != "windows" && !isSystemdCredentialPath(keyPath) && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("encryption key file permissions must not grant group or other access")
	}

	// #nosec G304 -- keyPath is explicit administrator configuration and has
	// just been lstat-validated as a private regular, non-symlink file.
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read encryption key file: %w", err)
	}
	if len(keyData) != 32 {
		encoded := bytes.TrimSpace(keyData)
		decoded, decodeErr := base64.StdEncoding.DecodeString(string(encoded))
		if decodeErr != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("encryption key file must contain exactly 32 raw bytes or a base64-encoded 32-byte key")
		}
		keyData = decoded
	}
	return keyData, nil
}

func (s *SOPSSecretStore) encrypt(plaintext []byte, tenantID, key string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	aad := []byte(tenantID + "\x00" + key)
	ciphertext := s.aead.Seal(nil, nonce, plaintext, aad)
	return json.Marshal(&encryptedEnvelope{
		Version:    1,
		Algorithm:  "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func (s *SOPSSecretStore) decrypt(encrypted []byte, tenantID, key string) ([]byte, error) {
	var envelope encryptedEnvelope
	if err := json.Unmarshal(encrypted, &envelope); err != nil {
		return nil, fmt.Errorf("secret ciphertext is not a valid encrypted envelope")
	}
	if envelope.Version != 1 || envelope.Algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported secret encryption envelope")
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != s.aead.NonceSize() {
		return nil, fmt.Errorf("invalid secret encryption nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid secret ciphertext encoding")
	}
	aad := []byte(tenantID + "\x00" + key)
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("secret ciphertext authentication failed")
	}
	return plaintext, nil
}

// StoreSecret stores a secret
// M-AUTH-1: Stores an authenticated encrypted envelope as ConfigEntry data.
func (s *SOPSSecretStore) StoreSecret(ctx context.Context, req *secretsif.SecretRequest) error {
	if err := validateSecretRequest(req); err != nil {
		return err
	}
	_, err := s.writeSecretEntry(ctx, req)
	return err
}

// validateSecretRequest applies the validation shared by every write path
// (StoreSecret and CompareAndSwapSecret).
func validateSecretRequest(req *secretsif.SecretRequest) error {
	if req == nil {
		return fmt.Errorf("secret request cannot be nil")
	}
	if req.Key == "" {
		return fmt.Errorf("secret key cannot be empty")
	}
	if len(req.Key) > 256 {
		return fmt.Errorf("secret key exceeds 256 character limit")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}
	if len(req.Value) > 1<<20 {
		return fmt.Errorf("secret value exceeds 1048576 byte limit")
	}
	return nil
}

// buildSecretEntry encrypts req into the authenticated envelope that goes on the
// wire to the ConfigStore, without writing anything. Split out from
// writeSecretEntry so CompareAndSwapSecret can hand the same envelope to a
// conditional write instead of an unconditional StoreConfig (Issue #3775).
func (s *SOPSSecretStore) buildSecretEntry(req *secretsif.SecretRequest) (*secretsif.Secret, *cfgconfig.ConfigEntry, error) {
	secret := &secretsif.Secret{
		Key:         req.Key,
		Value:       req.Value,
		Metadata:    req.Metadata,
		Tags:        req.Tags,
		Version:     1, // placeholder only — never read back; the ConfigStore's own Version is authoritative (see getSecretWithTenant)
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.CreatedBy,
		TenantID:    req.TenantID,
		Description: req.Description,
	}

	// Set expiration if TTL is specified
	if req.TTL > 0 {
		expiresAt := time.Now().Add(req.TTL)
		secret.ExpiresAt = &expiresAt
	}

	// Convert secret to JSON for storage
	secretData, err := json.Marshal(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal secret: %w", err)
	}
	encryptedData, err := s.encrypt(secretData, req.TenantID, req.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Store the encrypted envelope as a ConfigEntry.
	configKey := &cfgconfig.ConfigKey{
		TenantID:  req.TenantID,
		Namespace: "secrets", // Use "secrets" namespace for all secrets
		Name:      req.Key,   // Secret key is the config name
		Scope:     "",        // No scope needed for secrets
	}

	configEntry := &cfgconfig.ConfigEntry{
		Key:       configKey,
		Data:      encryptedData,
		Format:    cfgconfig.ConfigFormatJSON, // Secrets are stored as JSON
		CreatedBy: req.CreatedBy,
		UpdatedBy: req.CreatedBy,
		Tags:      append(req.Tags, "secret"), // Add "secret" tag
	}

	// Add secret type metadata if provided
	if secretType, ok := req.Metadata[secretsif.MetadataKeySecretType]; ok {
		configEntry.Tags = append(configEntry.Tags, fmt.Sprintf("type:%s", secretType))
	}

	return secret, configEntry, nil
}

// cacheSecret refreshes the cache entry for a just-written secret.
func (s *SOPSSecretStore) cacheSecret(req *secretsif.SecretRequest, secret *secretsif.Secret) {
	if s.cache == nil {
		return
	}
	cacheKey := s.getCacheKey(req.TenantID, req.Key)
	cacheTTL := time.Duration(s.config.CacheTTL) * time.Second
	if req.TTL > 0 && req.TTL < cacheTTL {
		cacheTTL = req.TTL // Use shorter TTL if secret expires sooner
	}
	_ = s.cache.Set(cacheKey, secret, cacheTTL)
}

// writeSecretEntry encrypts req and writes it through the configured ConfigStore,
// updating the cache on success. This is an unconditional overwrite: it is the
// StoreSecret path, never the compare-and-swap path.
func (s *SOPSSecretStore) writeSecretEntry(ctx context.Context, req *secretsif.SecretRequest) (*secretsif.Secret, error) {
	secret, configEntry, err := s.buildSecretEntry(req)
	if err != nil {
		return nil, err
	}

	// Store only the authenticated encrypted envelope in the ConfigStore.
	if err := s.configStore.StoreConfig(ctx, configEntry); err != nil {
		return nil, fmt.Errorf("failed to store secret: %w", err)
	}

	s.cacheSecret(req, secret)

	return secret, nil
}

// CompareAndSwapIsClusterAtomic implements
// secretsif.ClusterAtomicCompareAndSwapper. It reports true only when the backing
// ConfigStore performs the version comparison and the write as one atomic
// storage-layer operation — the only arrangement under which two controller nodes
// racing the same state transition cannot both win.
//
// It is false for a file-lock-coordinated backend. That lock is a genuine
// cross-process lock and is correct for two processes on one host sharing a
// directory, but O_CREAT|O_EXCL is not dependably atomic over a network
// filesystem, so it must not be presented to a caller as a cluster guarantee.
// Callers that need the cluster property gate on this rather than assuming it
// (Issue #3775).
func (s *SOPSSecretStore) CompareAndSwapIsClusterAtomic() bool {
	return s.conditionalStore != nil
}

// casCurrentVersion reads the version CompareAndSwapSecret must compare
// expectedVersion against, alongside the version physically stored.
//
// The two differ for an expired secret, and that difference is the whole point.
// A secret past its expiry is invisible to every read path (getSecretWithTenant
// refuses it, ListSecrets skips it), so for comparison purposes it does not
// exist: logical is 0, and a create-if-absent may take it over. stored keeps the
// real version so the takeover can still be written conditionally — the steal
// itself is a compare-and-set against the expired record's actual version, so
// exactly one of several nodes trying to take over the same expired record wins.
//
// Without this, a TTL-bearing claim record whose creator crashed before releasing
// it would block its transition permanently: nothing in this provider ever
// removes an expired record, so the claim's TTL would be a documented fail-safe
// that does not exist (Issue #3775).
func (s *SOPSSecretStore) casCurrentVersion(ctx context.Context, tenantID, key string) (logical int, stored int64, err error) {
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      key,
	}

	existing, err := s.configStore.GetConfig(ctx, configKey)
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("failed to read current secret version: %w", err)
	}

	plaintext, err := s.decrypt(existing.Data, tenantID, key)
	if err != nil {
		// The record exists but cannot be authenticated. Surface it rather than
		// treating an unreadable record as absent, which would let a caller
		// overwrite something it could not verify.
		return 0, 0, fmt.Errorf("failed to decrypt current secret for compare-and-swap: %w", err)
	}
	var secret secretsif.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return 0, 0, fmt.Errorf("failed to unmarshal current secret for compare-and-swap: %w", err)
	}

	if s.isExpired(&secret) {
		return 0, existing.Version, nil
	}
	return int(existing.Version), existing.Version, nil
}

// CompareAndSwapSecret implements interfaces.SecretStore.CompareAndSwapSecret.
//
// ConfigStore.StoreConfig is an unconditional overwrite that derives its new
// version from a preceding read, so building a compare-and-set on it requires
// atomicity from somewhere else. This takes it from one of two places, chosen
// once at construction (NewSOPSSecretStore) and reported by
// CompareAndSwapIsClusterAtomic:
//
//   - The backing ConfigStore's own conditional write
//     (cfgconfig.ConditionalConfigStore — PostgreSQL's "UPDATE ... WHERE version =
//     $expected"). The database decides the comparison and the write together, so
//     two controller nodes racing the same transition cannot both win. This is the
//     cluster-mode shape, where the storage provider is "database".
//   - Otherwise, an OS-visible file lock on the store's own private data root
//     (acquireCASLock), which serializes callers on this host and across processes
//     sharing that root. This is the single-node flatfile shape.
//
// When neither is available — a backend with no conditional-write primitive and no
// private filesystem root — this refuses with an error instead of performing an
// unprotected read-check-write. There is no third, weaker mode: a compare-and-set
// that silently stops being atomic is worse than one that says so, because every
// call site (enrolment-token spend, approved->collected, account revoke, renewal
// claim) mints certificates on the strength of winning it.
func (s *SOPSSecretStore) CompareAndSwapSecret(ctx context.Context, key string, expectedVersion int, req *secretsif.SecretRequest) (int, bool, error) {
	if err := validateSecretRequest(req); err != nil {
		return 0, false, err
	}
	if key == "" {
		return 0, false, fmt.Errorf("secret key cannot be empty")
	}
	if expectedVersion < 0 {
		return 0, false, fmt.Errorf("expected version cannot be negative")
	}

	switch {
	case s.conditionalStore != nil:
		return s.compareAndSwapConditional(ctx, expectedVersion, req)
	case s.casLockRoot != "":
		release, err := acquireCASLock(ctx, s.casLockRoot, req.TenantID, req.Key)
		if err != nil {
			return 0, false, fmt.Errorf("failed to acquire compare-and-swap lock: %w", err)
		}
		defer release()
		return s.compareAndSwapUnderLock(ctx, expectedVersion, req)
	default:
		return 0, false, fmt.Errorf(
			"compare-and-swap is unavailable for storage provider %q: %w; "+
				"configure a backend with a conditional-write primitive (database) or a private storage root (flatfile)",
			s.providerName, s.casUnavailableErr)
	}
}

// compareAndSwapConditional performs the swap using the backing store's own
// conditional write, which is atomic across controller nodes.
//
// The read is advisory: it translates the caller's expectedVersion (in which an
// expired record counts as absent) into the version physically stored, which is
// what the conditional write must be keyed on so that taking an expired record
// over replaces it rather than colliding with it. The write remains the single
// atomic decision — if another node changes the key between the read and the
// write, the write matches nothing and this reports a lost race, exactly as if the
// read had never happened.
func (s *SOPSSecretStore) compareAndSwapConditional(ctx context.Context, expectedVersion int, req *secretsif.SecretRequest) (int, bool, error) {
	logical, stored, err := s.casCurrentVersion(ctx, req.TenantID, req.Key)
	if err != nil {
		return 0, false, err
	}
	if logical != expectedVersion {
		return 0, false, nil
	}

	secret, configEntry, err := s.buildSecretEntry(req)
	if err != nil {
		return 0, false, err
	}

	newVersion, ok, err := s.conditionalStore.CompareAndSwapConfig(ctx, configEntry, stored)
	if err != nil {
		return 0, false, fmt.Errorf("failed to compare-and-swap secret: %w", err)
	}
	if !ok {
		return 0, false, nil
	}

	secret.Version = int(newVersion)
	s.cacheSecret(req, secret)
	return int(newVersion), true, nil
}

// compareAndSwapUnderLock performs the read-check-write sequence for backends with
// no conditional-write primitive. The caller must already hold the
// tenant+key-scoped file lock.
func (s *SOPSSecretStore) compareAndSwapUnderLock(ctx context.Context, expectedVersion int, req *secretsif.SecretRequest) (int, bool, error) {
	logical, _, err := s.casCurrentVersion(ctx, req.TenantID, req.Key)
	if err != nil {
		return 0, false, err
	}
	if logical != expectedVersion {
		return 0, false, nil
	}

	secret, configEntry, err := s.buildSecretEntry(req)
	if err != nil {
		return 0, false, err
	}
	if err := s.configStore.StoreConfig(ctx, configEntry); err != nil {
		return 0, false, fmt.Errorf("failed to store secret: %w", err)
	}

	// Not every ConfigStore stamps the version it assigned back onto the entry it
	// was handed (flatfile writes a copy), so read it back. Still inside the lock,
	// so no other writer can have moved it.
	written, err := s.configStore.GetConfig(ctx, configEntry.Key)
	if err != nil {
		return 0, false, fmt.Errorf("failed to read version after compare-and-swap write: %w", err)
	}

	secret.Version = int(written.Version)
	s.cacheSecret(req, secret)
	return int(written.Version), true, nil
}

// GetSecret retrieves a secret
// M-AUTH-1: Retrieves secret from ConfigStore, automatically decrypted by SOPS
func (s *SOPSSecretStore) GetSecret(ctx context.Context, key string) (*secretsif.Secret, error) {
	return s.getSecretWithTenant(ctx, "", key)
}

// getSecretWithTenant retrieves a secret with explicit tenant ID
func (s *SOPSSecretStore) getSecretWithTenant(ctx context.Context, tenantID, key string) (*secretsif.Secret, error) {
	// Try cache first if enabled
	if s.cache != nil {
		cacheKey := s.getCacheKey(tenantID, key)
		if cached, found := s.cache.Get(cacheKey); found {
			if secret, ok := cached.(*secretsif.Secret); ok {
				// Check expiration
				if !s.isExpired(secret) {
					return secret, nil
				}
				// Secret expired, remove from cache
				s.cache.Delete(cacheKey)
			}
		}
	}

	// Extract tenant ID from key if not provided (format: tenant_id/secret_key)
	if tenantID == "" {
		parts := strings.SplitN(key, "/", 2)
		if len(parts) == 2 {
			tenantID = parts[0]
			key = parts[1]
		} else {
			return nil, fmt.Errorf("secret key must be in format 'tenant_id/key' or tenant ID must be provided")
		}
	}

	// Retrieve from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      key,
	}

	configEntry, err := s.configStore.GetConfig(ctx, configKey)
	if err != nil {
		if err == cfgconfig.ErrConfigNotFound {
			return nil, fmt.Errorf("secret not found: %s: %w", key, secretsif.ErrSecretNotFound)
		}
		return nil, fmt.Errorf("failed to retrieve secret: %w", err)
	}

	plaintext, err := s.decrypt(configEntry.Data, tenantID, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Parse the authenticated plaintext only after decryption succeeds.
	var secret secretsif.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}
	// The encrypted payload's own Version field is stamped once at write time and
	// never updated on subsequent writes (writeSecretEntry always marshals
	// Version: 1) — it is not a reliable version number. The ConfigStore's own
	// auto-incrementing Version is authoritative and is what CompareAndSwapSecret
	// keys on, so every read path must report it, not the stale payload value
	// (Issue #3775).
	secret.Version = int(configEntry.Version)

	// Check expiration
	if s.isExpired(&secret) {
		return nil, fmt.Errorf("secret expired: %s", key)
	}

	// Update cache if enabled
	if s.cache != nil {
		cacheKey := s.getCacheKey(tenantID, key)
		cacheTTL := time.Duration(s.config.CacheTTL) * time.Second
		if secret.ExpiresAt != nil {
			remainingTTL := time.Until(*secret.ExpiresAt)
			if remainingTTL < cacheTTL {
				cacheTTL = remainingTTL
			}
		}
		_ = s.cache.Set(cacheKey, &secret, cacheTTL)
	}

	return &secret, nil
}

// DeleteSecret deletes a secret
// M-AUTH-1: Deletes secret from ConfigStore
func (s *SOPSSecretStore) DeleteSecret(ctx context.Context, key string) error {
	// Extract tenant ID from key (format: tenant_id/secret_key)
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("secret key must be in format 'tenant_id/key'")
	}
	tenantID := parts[0]
	secretKey := parts[1]

	// Delete from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      secretKey,
	}

	if err := s.configStore.DeleteConfig(ctx, configKey); err != nil {
		if err == cfgconfig.ErrConfigNotFound {
			return fmt.Errorf("secret not found: %s", key)
		}
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	// Remove from cache if enabled
	if s.cache != nil {
		cacheKey := s.getCacheKey(tenantID, secretKey)
		s.cache.Delete(cacheKey)
	}

	return nil
}

// ListSecrets lists secrets matching the filter
// M-AUTH-1: Lists secrets from ConfigStore
func (s *SOPSSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	// Convert secret filter to config filter
	configFilter := &cfgconfig.ConfigFilter{
		TenantID:  filter.TenantID,
		Namespace: "secrets",
		Tags:      append(filter.Tags, "secret"), // Must have "secret" tag
		Limit:     filter.Limit,
		Offset:    filter.Offset,
	}

	// Note: ConfigStore doesn't have prefix filtering, so we filter after retrieval (see loop below)
	// This is inefficient but works for MVP

	// List configs from ConfigStore
	configs, err := s.configStore.ListConfigs(ctx, configFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Convert to secret metadata
	var metadata []*secretsif.SecretMetadata
	for _, config := range configs {
		if config.Key == nil {
			continue
		}
		plaintext, decryptErr := s.decrypt(config.Data, config.Key.TenantID, config.Key.Name)
		if decryptErr != nil {
			return nil, fmt.Errorf("failed to decrypt secret metadata: %w", decryptErr)
		}
		// Parse secret to get metadata
		var secret secretsif.Secret
		if err := json.Unmarshal(plaintext, &secret); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret metadata: %w", err)
		}

		// Apply additional filters
		if filter.KeyPrefix != "" && !strings.HasPrefix(secret.Key, filter.KeyPrefix) {
			continue
		}

		if filter.CreatedBy != "" && secret.CreatedBy != filter.CreatedBy {
			continue
		}

		// Skip expired secrets unless IncludeExpired is true
		if !filter.IncludeExpired && s.isExpired(&secret) {
			continue
		}

		// Check metadata filters
		if len(filter.Metadata) > 0 {
			match := true
			for k, v := range filter.Metadata {
				if secret.Metadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		metadata = append(metadata, &secretsif.SecretMetadata{
			Key:      secret.Key,
			Metadata: secret.Metadata,
			Tags:     secret.Tags,
			// config.Version (the ConfigStore's own auto-incrementing version) is
			// authoritative — secret.Version is stamped once at write time and never
			// updated on subsequent writes; see getSecretWithTenant's identical fix
			// (Issue #3775).
			Version:     int(config.Version),
			CreatedAt:   secret.CreatedAt,
			UpdatedAt:   secret.UpdatedAt,
			ExpiresAt:   secret.ExpiresAt,
			CreatedBy:   secret.CreatedBy,
			UpdatedBy:   secret.UpdatedBy,
			TenantID:    secret.TenantID,
			Description: secret.Description,
		})
	}

	return metadata, nil
}

// GetSecrets retrieves multiple secrets
// M-AUTH-1: Bulk secret retrieval
func (s *SOPSSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*secretsif.Secret, error) {
	result := make(map[string]*secretsif.Secret)

	for _, key := range keys {
		secret, err := s.GetSecret(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve secret %s: %w", key, err)
		}
		result[key] = secret
	}

	return result, nil
}

// StoreSecrets stores multiple secrets
// M-AUTH-1: Bulk secret storage
func (s *SOPSSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsif.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return fmt.Errorf("failed to store secret %s: %w", req.Key, err)
		}
	}
	return nil
}

// GetSecretVersion retrieves a specific version of a secret
// M-AUTH-1: Version retrieval using git history
func (s *SOPSSecretStore) GetSecretVersion(ctx context.Context, key string, version int) (*secretsif.Secret, error) {
	// Extract tenant ID from key
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("secret key must be in format 'tenant_id/key'")
	}
	tenantID := parts[0]
	secretKey := parts[1]

	// Get version from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      secretKey,
	}

	configEntry, err := s.configStore.GetConfigVersion(ctx, configKey, int64(version))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve secret version: %w", err)
	}

	plaintext, err := s.decrypt(configEntry.Data, tenantID, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret version: %w", err)
	}

	// Parse secret from JSON
	var secret secretsif.Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	return &secret, nil
}

// ListSecretVersions lists all versions of a secret
// M-AUTH-1: Version history using git log
func (s *SOPSSecretStore) ListSecretVersions(ctx context.Context, key string) ([]*secretsif.SecretVersion, error) {
	// Extract tenant ID from key
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("secret key must be in format 'tenant_id/key'")
	}
	tenantID := parts[0]
	secretKey := parts[1]

	// Get version history from ConfigStore
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "secrets",
		Name:      secretKey,
	}

	history, err := s.configStore.GetConfigHistory(ctx, configKey, 100) // Get last 100 versions
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve version history: %w", err)
	}

	// Convert to secret versions
	var versions []*secretsif.SecretVersion
	for _, config := range history {
		plaintext, decryptErr := s.decrypt(config.Data, tenantID, secretKey)
		if decryptErr != nil {
			return nil, fmt.Errorf("failed to decrypt secret version history: %w", decryptErr)
		}
		// Parse secret to get created info
		var secret secretsif.Secret
		if err := json.Unmarshal(plaintext, &secret); err != nil {
			return nil, fmt.Errorf("failed to unmarshal secret version history: %w", err)
		}

		versions = append(versions, &secretsif.SecretVersion{
			Version:   int(config.Version),
			CreatedAt: config.CreatedAt,
			CreatedBy: config.CreatedBy,
		})
	}

	return versions, nil
}

// GetSecretMetadata retrieves metadata about a secret without the value
// M-AUTH-1: Metadata-only retrieval for listing
func (s *SOPSSecretStore) GetSecretMetadata(ctx context.Context, key string) (*secretsif.SecretMetadata, error) {
	secret, err := s.GetSecret(ctx, key)
	if err != nil {
		return nil, err
	}

	return &secretsif.SecretMetadata{
		Key:         secret.Key,
		Metadata:    secret.Metadata,
		Tags:        secret.Tags,
		Version:     secret.Version,
		CreatedAt:   secret.CreatedAt,
		UpdatedAt:   secret.UpdatedAt,
		ExpiresAt:   secret.ExpiresAt,
		CreatedBy:   secret.CreatedBy,
		UpdatedBy:   secret.UpdatedBy,
		TenantID:    secret.TenantID,
		Description: secret.Description,
	}, nil
}

// UpdateSecretMetadata updates secret metadata without changing the value
// M-AUTH-1: Metadata-only updates
func (s *SOPSSecretStore) UpdateSecretMetadata(ctx context.Context, key string, metadata map[string]string) error {
	// Get current secret
	secret, err := s.GetSecret(ctx, key)
	if err != nil {
		return err
	}

	// Update metadata
	if secret.Metadata == nil {
		secret.Metadata = make(map[string]string)
	}
	for k, v := range metadata {
		secret.Metadata[k] = v
	}
	secret.UpdatedAt = time.Now()

	// Store updated secret
	req := &secretsif.SecretRequest{
		Key:         secret.Key,
		Value:       secret.Value,
		Metadata:    secret.Metadata,
		Tags:        secret.Tags,
		CreatedBy:   secret.UpdatedBy,
		TenantID:    secret.TenantID,
		Description: secret.Description,
	}

	return s.StoreSecret(ctx, req)
}

// RotateSecret rotates a secret with a new value
// M-AUTH-1: Secret rotation with version tracking
func (s *SOPSSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	// Get current secret to preserve metadata
	secret, err := s.GetSecret(ctx, key)
	if err != nil {
		return err
	}

	// Update rotation metadata
	if secret.Metadata == nil {
		secret.Metadata = make(map[string]string)
	}
	secret.Metadata[secretsif.MetadataKeyLastRotated] = time.Now().Format(time.RFC3339)

	// Store rotated secret
	req := &secretsif.SecretRequest{
		Key:         secret.Key,
		Value:       newValue, // New value
		Metadata:    secret.Metadata,
		Tags:        secret.Tags,
		CreatedBy:   secret.UpdatedBy,
		TenantID:    secret.TenantID,
		Description: secret.Description,
	}

	return s.StoreSecret(ctx, req)
}

// ExpireSecret marks a secret as expired
// M-AUTH-1: Immediate secret expiration
func (s *SOPSSecretStore) ExpireSecret(ctx context.Context, key string) error {
	// Design decision: SOPS secrets have no TTL mechanism; expiration is implemented as deletion. Time-based expiry requires a separate scheduled cleanup process.
	return s.DeleteSecret(ctx, key)
}

// HealthCheck checks if the secret store is healthy
// M-AUTH-1: Health monitoring
func (s *SOPSSecretStore) HealthCheck(ctx context.Context) error {
	// Check if ConfigStore is accessible
	// Try to list configs to verify connectivity
	_, err := s.configStore.GetConfigStats(ctx)
	if err != nil {
		return fmt.Errorf("secret store unhealthy: %w", err)
	}
	return nil
}

// Close closes the secret store
// M-AUTH-1: Cleanup resources
func (s *SOPSSecretStore) Close() error {
	// Close cache if enabled
	if s.cache != nil {
		s.cache.Close()
	}
	return nil
}

// Helper methods

// getCacheKey generates a cache key for a secret
func (s *SOPSSecretStore) getCacheKey(tenantID, key string) string {
	return fmt.Sprintf("%s/%s", tenantID, key)
}

// isExpired checks if a secret is expired
func (s *SOPSSecretStore) isExpired(secret *secretsif.Secret) bool {
	if secret.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*secret.ExpiresAt)
}
