// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package openbao — OpenBaoSecretStore implements interfaces.SecretStore against
// an OpenBao KV v2 engine.
// M-AUTH-1: Full CRUD, versioning, rotation, metadata, and health for OpenBao KV v2.
package openbao

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	openbao "github.com/openbao/openbao/api/v2"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// OpenBaoSecretStore implements interfaces.SecretStore using OpenBao KV v2.
type OpenBaoSecretStore struct {
	client    *openbao.Client
	mountPath string
}

// newOpenBaoSecretStore creates a ready-to-use store from the parsed config.
func newOpenBaoSecretStore(cfg *OpenBaoConfig) (*OpenBaoSecretStore, error) {
	client, err := newOpenBaoClient(cfg)
	if err != nil {
		return nil, err
	}

	return &OpenBaoSecretStore{
		client:    client,
		mountPath: cfg.MountPath,
	}, nil
}

// kvPath returns the KV v2 data path for a tenant/key pair.
// Format: <tenantID>/<key>
func (s *OpenBaoSecretStore) kvPath(tenantID, key string) string {
	return tenantID + "/" + key
}

// StoreSecret writes a secret to OpenBao KV v2.
// M-AUTH-1: TenantID is required; empty TenantID returns ErrTenantRequired.
func (s *OpenBaoSecretStore) StoreSecret(ctx context.Context, req *interfaces.SecretRequest) error {
	if err := validateSecretRequest(req); err != nil {
		return err
	}

	path := s.kvPath(req.TenantID, req.Key)
	_, err := s.client.KVv2(s.mountPath).Put(ctx, logging.SanitizeLogValue(path), kvData(req))
	if err != nil {
		return fmt.Errorf("failed to store secret %s: %w",
			logging.SanitizeLogValue(req.Key), err)
	}

	return nil
}

// CompareAndSwapSecret implements interfaces.SecretStore.CompareAndSwapSecret using
// OpenBao KV v2's native check-and-set option — a real server-side atomic write, so
// this is correct across any number of controller nodes concurrently writing the
// same key (OpenBao is this codebase's one ClusterCapable SecretStore provider).
// expectedVersion 0 uses OpenBao's own "must not already exist" CAS semantics.
func (s *OpenBaoSecretStore) CompareAndSwapSecret(ctx context.Context, key string, expectedVersion int, req *interfaces.SecretRequest) (int, bool, error) {
	if err := validateSecretRequest(req); err != nil {
		return 0, false, err
	}
	if key == "" {
		return 0, false, fmt.Errorf("secret key cannot be empty")
	}
	if expectedVersion < 0 {
		return 0, false, fmt.Errorf("expected version cannot be negative")
	}

	logical, stored, err := s.casCurrentVersion(ctx, req.TenantID, req.Key)
	if err != nil {
		return 0, false, err
	}
	if logical != expectedVersion {
		return 0, false, nil
	}

	// The read above is advisory: it only translates the caller's expectedVersion
	// (in which an expired record counts as absent) into the version OpenBao
	// actually holds. The check-and-set below is still the single atomic decision,
	// evaluated by the OpenBao server, so a concurrent write from another node
	// between the two makes this report a lost race rather than clobber anything.
	return s.putWithCheckAndSet(ctx, req, stored)
}

// casCurrentVersion reports the version CompareAndSwapSecret must compare
// expectedVersion against, alongside the version OpenBao physically holds.
//
// The two differ for a record past the application-level expires_at this provider
// writes. The interface requires an expired record to be treated as absent, so
// logical is 0 for one while stored keeps the real KV version — which is what lets
// a create-if-absent take an abandoned TTL-bounded claim over with a check-and-set
// rather than be blocked by it forever (Issue #3775). OpenBao does not evaluate
// expires_at itself, so this provider must.
func (s *OpenBaoSecretStore) casCurrentVersion(ctx context.Context, tenantID, key string) (logical, stored int, err error) {
	path := s.kvPath(tenantID, key)
	kvSecret, err := s.client.KVv2(s.mountPath).Get(ctx, logging.SanitizeLogValue(path))
	if err != nil {
		if isNotFound(err) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("failed to read current secret %s for compare-and-swap: %w",
			logging.SanitizeLogValue(key), err)
	}
	if kvSecret == nil || kvSecret.VersionMetadata == nil {
		return 0, 0, nil
	}

	current := kvSecretToSecret(tenantID, key, kvSecret)
	if current.ExpiresAt != nil && time.Now().After(*current.ExpiresAt) {
		return 0, current.Version, nil
	}
	return current.Version, current.Version, nil
}

// putWithCheckAndSet performs one KV v2 check-and-set write, translating a
// check-and-set mismatch into the interface's ok=false/nil-error lost-race result
// and leaving every other failure as a genuine error.
func (s *OpenBaoSecretStore) putWithCheckAndSet(ctx context.Context, req *interfaces.SecretRequest, expectedVersion int) (int, bool, error) {
	path := s.kvPath(req.TenantID, req.Key)
	kvSecret, err := s.client.KVv2(s.mountPath).Put(ctx, logging.SanitizeLogValue(path), kvData(req),
		openbao.WithCheckAndSet(expectedVersion))
	if err != nil {
		if isCheckAndSetMismatch(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("failed to compare-and-swap secret %s: %w",
			logging.SanitizeLogValue(req.Key), err)
	}

	newVersion := 0
	if kvSecret != nil && kvSecret.VersionMetadata != nil {
		newVersion = kvSecret.VersionMetadata.Version
	}
	return newVersion, true, nil
}

// CompareAndSwapIsClusterAtomic implements
// interfaces.ClusterAtomicCompareAndSwapper. OpenBao KV v2's check-and-set is
// evaluated by the OpenBao server, so the guarantee holds for any number of
// controller nodes writing the same key concurrently.
func (s *OpenBaoSecretStore) CompareAndSwapIsClusterAtomic() bool { return true }

// validateSecretRequest applies the validation shared by every write path.
func validateSecretRequest(req *interfaces.SecretRequest) error {
	if req == nil {
		return fmt.Errorf("secret request cannot be nil")
	}
	if req.Key == "" {
		return fmt.Errorf("secret key cannot be empty")
	}
	if req.TenantID == "" {
		return fmt.Errorf("TenantID is required: %w", cfgconfig.ErrTenantRequired)
	}
	return nil
}

// kvData builds the KV v2 data payload shared by StoreSecret and CompareAndSwapSecret.
func kvData(req *interfaces.SecretRequest) map[string]interface{} {
	data := map[string]interface{}{
		"value":       req.Value,
		"created_by":  req.CreatedBy,
		"description": req.Description,
	}
	if len(req.Tags) > 0 {
		data["tags"] = strings.Join(req.Tags, ",")
	}
	if len(req.Metadata) > 0 {
		for k, v := range req.Metadata {
			data["meta_"+k] = v
		}
	}
	if req.TTL > 0 {
		data["expires_at"] = time.Now().Add(req.TTL).Format(time.RFC3339)
	}
	return data
}

// isCheckAndSetMismatch reports whether err is OpenBao's response to a failed
// check-and-set write (HTTP 400, "check-and-set parameter did not match the
// current version" / "check-and-set parameter required for this call") rather than
// an infrastructure failure. CompareAndSwapSecret's contract requires this to be a
// non-error, ok=false result — a genuine store failure must not be mistaken for a
// lost race, and vice versa.
func isCheckAndSetMismatch(err error) bool {
	var respErr *openbao.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	if respErr.StatusCode != http.StatusBadRequest {
		return false
	}
	return strings.Contains(strings.ToLower(respErr.Error()), "check-and-set")
}

// GetSecret retrieves the current version of a secret.
// The key must be in the format "tenantID/keyName".
func (s *OpenBaoSecretStore) GetSecret(ctx context.Context, key string) (*interfaces.Secret, error) {
	tenantID, keyName, err := splitKey(key)
	if err != nil {
		return nil, err
	}

	path := s.kvPath(tenantID, keyName)
	kvSecret, err := s.client.KVv2(s.mountPath).Get(ctx, logging.SanitizeLogValue(path))
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("secret not found: %s", logging.SanitizeLogValue(key))
		}
		return nil, fmt.Errorf("failed to get secret %s: %w",
			logging.SanitizeLogValue(key), err)
	}
	if kvSecret == nil {
		return nil, fmt.Errorf("secret not found: %s", logging.SanitizeLogValue(key))
	}

	return kvSecretToSecret(tenantID, keyName, kvSecret), nil
}

// DeleteSecret permanently deletes all versions of a secret.
// Key must be in the format "tenantID/keyName".
func (s *OpenBaoSecretStore) DeleteSecret(ctx context.Context, key string) error {
	tenantID, keyName, err := splitKey(key)
	if err != nil {
		return err
	}

	path := s.kvPath(tenantID, keyName)
	// DeleteMetadata removes all versions and the metadata entry.
	if err := s.client.KVv2(s.mountPath).DeleteMetadata(ctx, logging.SanitizeLogValue(path)); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("secret not found: %s", logging.SanitizeLogValue(key))
		}
		return fmt.Errorf("failed to delete secret %s: %w",
			logging.SanitizeLogValue(key), err)
	}

	return nil
}

// ListSecrets returns metadata for secrets matching the filter.
// TenantID in the filter is required for multi-tenant isolation.
func (s *OpenBaoSecretStore) ListSecrets(ctx context.Context, filter *interfaces.SecretFilter) ([]*interfaces.SecretMetadata, error) {
	if filter == nil {
		filter = &interfaces.SecretFilter{}
	}

	tenantID := filter.TenantID
	listPath := s.mountPath + "/metadata/" + logging.SanitizeLogValue(tenantID)

	logicalSecret, err := s.client.Logical().ListWithContext(ctx, listPath)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to list secrets for tenant %s: %w",
			logging.SanitizeLogValue(tenantID), err)
	}
	if logicalSecret == nil || logicalSecret.Data == nil {
		return nil, nil
	}

	keysRaw, ok := logicalSecret.Data["keys"]
	if !ok {
		return nil, nil
	}

	keys, ok := keysRaw.([]interface{})
	if !ok {
		return nil, nil
	}

	var results []*interfaces.SecretMetadata
	for _, rawKey := range keys {
		k, ok := rawKey.(string)
		if !ok {
			continue
		}

		// Skip directories (keys ending with "/").
		if strings.HasSuffix(k, "/") {
			continue
		}

		// Apply key prefix filter.
		if filter.KeyPrefix != "" && !strings.HasPrefix(k, filter.KeyPrefix) {
			continue
		}

		// Fetch full metadata to support additional filtering.
		meta, err := s.GetSecretMetadata(ctx, tenantID+"/"+k)
		if err != nil {
			continue
		}

		// Apply creator filter.
		if filter.CreatedBy != "" && meta.CreatedBy != filter.CreatedBy {
			continue
		}

		// Apply tag filter (AND logic — all filter tags must be present).
		if len(filter.Tags) > 0 && !hasAllTags(meta.Tags, filter.Tags) {
			continue
		}

		// Apply metadata filter (AND logic).
		if len(filter.Metadata) > 0 {
			match := true
			for fk, fv := range filter.Metadata {
				if meta.Metadata[fk] != fv {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		// Skip expired secrets unless explicitly requested.
		if !filter.IncludeExpired && isExpiredMeta(meta) {
			continue
		}

		results = append(results, meta)

		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}

	return results, nil
}

// GetSecrets retrieves multiple secrets by key.
// Returns the successfully-fetched secrets and a combined error listing any keys that failed.
func (s *OpenBaoSecretStore) GetSecrets(ctx context.Context, keys []string) (map[string]*interfaces.Secret, error) {
	result := make(map[string]*interfaces.Secret, len(keys))
	var firstErr error
	for _, key := range keys {
		sec, err := s.GetSecret(ctx, key)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("one or more secrets could not be retrieved (first error for %s): %w",
					logging.SanitizeLogValue(key), err)
			}
			continue
		}
		result[key] = sec
	}
	return result, firstErr
}

// StoreSecrets stores multiple secrets. Returns on first error.
func (s *OpenBaoSecretStore) StoreSecrets(ctx context.Context, secrets map[string]*interfaces.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return fmt.Errorf("failed to store secret %s: %w",
				logging.SanitizeLogValue(req.Key), err)
		}
	}
	return nil
}

// GetSecretVersion retrieves a specific version of a secret.
// Key must be "tenantID/keyName".
func (s *OpenBaoSecretStore) GetSecretVersion(ctx context.Context, key string, version int) (*interfaces.Secret, error) {
	tenantID, keyName, err := splitKey(key)
	if err != nil {
		return nil, err
	}

	path := s.kvPath(tenantID, keyName)
	kvSecret, err := s.client.KVv2(s.mountPath).GetVersion(ctx, logging.SanitizeLogValue(path), version)
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("secret version %d not found: %s",
				version, logging.SanitizeLogValue(key))
		}
		return nil, fmt.Errorf("failed to get secret version %d for %s: %w",
			version, logging.SanitizeLogValue(key), err)
	}
	if kvSecret == nil {
		return nil, fmt.Errorf("secret version %d not found: %s",
			version, logging.SanitizeLogValue(key))
	}

	secret := kvSecretToSecret(tenantID, keyName, kvSecret)
	secret.Version = version
	return secret, nil
}

// ListSecretVersions returns the version history for a secret.
// Key must be "tenantID/keyName".
func (s *OpenBaoSecretStore) ListSecretVersions(ctx context.Context, key string) ([]*interfaces.SecretVersion, error) {
	tenantID, keyName, err := splitKey(key)
	if err != nil {
		return nil, err
	}

	path := s.kvPath(tenantID, keyName)
	versionMetas, err := s.client.KVv2(s.mountPath).GetVersionsAsList(ctx, logging.SanitizeLogValue(path))
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("secret not found: %s", logging.SanitizeLogValue(key))
		}
		return nil, fmt.Errorf("failed to list versions for %s: %w",
			logging.SanitizeLogValue(key), err)
	}

	versions := make([]*interfaces.SecretVersion, 0, len(versionMetas))
	for _, vm := range versionMetas {
		sv := &interfaces.SecretVersion{
			Version:   vm.Version,
			CreatedAt: vm.CreatedTime,
		}
		if !vm.DeletionTime.IsZero() {
			t := vm.DeletionTime
			sv.DeletedAt = &t
		}
		versions = append(versions, sv)
	}

	return versions, nil
}

// GetSecretMetadata retrieves metadata for a secret without its value.
// Key must be "tenantID/keyName".
func (s *OpenBaoSecretStore) GetSecretMetadata(ctx context.Context, key string) (*interfaces.SecretMetadata, error) {
	tenantID, keyName, err := splitKey(key)
	if err != nil {
		return nil, err
	}

	path := s.kvPath(tenantID, keyName)
	kvMeta, err := s.client.KVv2(s.mountPath).GetMetadata(ctx, logging.SanitizeLogValue(path))
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("secret not found: %s", logging.SanitizeLogValue(key))
		}
		return nil, fmt.Errorf("failed to get metadata for %s: %w",
			logging.SanitizeLogValue(key), err)
	}
	if kvMeta == nil {
		return nil, fmt.Errorf("secret not found: %s", logging.SanitizeLogValue(key))
	}

	meta := &interfaces.SecretMetadata{
		Key:      keyName,
		TenantID: tenantID,
		Version:  kvMeta.CurrentVersion,
	}

	// Populate custom metadata from OpenBao KV v2 custom_metadata.
	if kvMeta.CustomMetadata != nil {
		m := make(map[string]string, len(kvMeta.CustomMetadata))
		for k, v := range kvMeta.CustomMetadata {
			if s, ok := v.(string); ok {
				m[k] = s
			}
		}
		if len(m) > 0 {
			meta.Metadata = m
			// Populate Policy from the openbao_policies key if present.
			if policies, ok := m["openbao_policies"]; ok && policies != "" {
				meta.Policy = map[string]string{"openbao_policies": policies}
			}
		}
	}

	// Timestamps.
	meta.CreatedAt = kvMeta.CreatedTime
	meta.UpdatedAt = kvMeta.UpdatedTime

	// Populate tags and creator from the current version data if available.
	if kvMeta.CurrentVersion > 0 {
		if sec, err := s.GetSecret(ctx, key); err == nil {
			meta.Tags = sec.Tags
			meta.CreatedBy = sec.CreatedBy
			meta.UpdatedBy = sec.UpdatedBy
			meta.Description = sec.Description
			if sec.ExpiresAt != nil {
				meta.ExpiresAt = sec.ExpiresAt
			}
		}
	}

	return meta, nil
}

// UpdateSecretMetadata updates KV v2 custom metadata for a secret without changing the value.
// Key must be "tenantID/keyName".
func (s *OpenBaoSecretStore) UpdateSecretMetadata(ctx context.Context, key string, metadata map[string]string) error {
	tenantID, keyName, err := splitKey(key)
	if err != nil {
		return err
	}

	path := s.kvPath(tenantID, keyName)

	// Convert map[string]string to map[string]interface{} for the API.
	customMeta := make(map[string]interface{}, len(metadata))
	for k, v := range metadata {
		customMeta[k] = v
	}

	patch := openbao.KVMetadataPatchInput{
		CustomMetadata: customMeta,
	}

	if err := s.client.KVv2(s.mountPath).PatchMetadata(ctx, logging.SanitizeLogValue(path), patch); err != nil {
		return fmt.Errorf("failed to update metadata for %s: %w",
			logging.SanitizeLogValue(key), err)
	}

	return nil
}

// RotateSecret writes a new version of the secret with newValue.
// The old versions remain accessible via GetSecretVersion.
func (s *OpenBaoSecretStore) RotateSecret(ctx context.Context, key string, newValue string) error {
	tenantID, keyName, err := splitKey(key)
	if err != nil {
		return err
	}

	// Preserve existing secret metadata.
	current, err := s.GetSecret(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to read current secret for rotation: %w", err)
	}

	meta := current.Metadata
	if meta == nil {
		meta = make(map[string]string)
	}
	meta[interfaces.MetadataKeyLastRotated] = time.Now().Format(time.RFC3339)

	return s.StoreSecret(ctx, &interfaces.SecretRequest{
		Key:         keyName,
		Value:       newValue,
		Metadata:    meta,
		Tags:        current.Tags,
		CreatedBy:   current.UpdatedBy,
		TenantID:    tenantID,
		Description: current.Description,
	})
}

// ExpireSecret marks a secret as expired by deleting the current version.
func (s *OpenBaoSecretStore) ExpireSecret(ctx context.Context, key string) error {
	return s.DeleteSecret(ctx, key)
}

// HealthCheck verifies connectivity to the OpenBao instance.
func (s *OpenBaoSecretStore) HealthCheck(ctx context.Context) error {
	health, err := s.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("OpenBao health check failed: %w", err)
	}
	if !health.Initialized {
		return fmt.Errorf("OpenBao is not initialized")
	}
	if health.Sealed {
		return fmt.Errorf("OpenBao is sealed")
	}
	return nil
}

// Close is a no-op for the HTTP-based OpenBao client.
func (s *OpenBaoSecretStore) Close() error {
	return nil
}

// ---- helpers ----

// splitKey splits a "tenantID/keyName" string into its components.
//
// The second result is deliberately named keyName, not secretKey: it holds a
// secret's *name*, never its value. CodeQL's go/clear-text-logging query picks
// its sources by identifier name (`.*secret.*`), so a variable called secretKey
// was treated as secret material and its taint followed the returned
// Secret/SecretMetadata struct field-insensitively into every caller — surfacing
// as clear-text-logging alerts on sanitized tenant-ID log lines in
// features/controller/api/handlers_web_accounts.go. Do not rename this back.
func splitKey(key string) (tenantID, keyName string, err error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("secret key must be in format 'tenantID/key', got: %s",
			logging.SanitizeLogValue(key))
	}
	return parts[0], parts[1], nil
}

// kvSecretToSecret converts an OpenBao KVSecret to a CFGMS Secret.
func kvSecretToSecret(tenantID, keyName string, kv *openbao.KVSecret) *interfaces.Secret {
	secret := &interfaces.Secret{
		Key:      keyName,
		TenantID: tenantID,
	}

	if kv.Data != nil {
		if v, ok := kv.Data["value"].(string); ok {
			secret.Value = v
		}
		if v, ok := kv.Data["created_by"].(string); ok {
			secret.CreatedBy = v
			secret.UpdatedBy = v
		}
		if v, ok := kv.Data["description"].(string); ok {
			secret.Description = v
		}
		if v, ok := kv.Data["tags"].(string); ok && v != "" {
			secret.Tags = strings.Split(v, ",")
		}
		if v, ok := kv.Data["expires_at"].(string); ok && v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				secret.ExpiresAt = &t
			}
		}

		// Reconstruct metadata from meta_* keys.
		metadata := make(map[string]string)
		for k, v := range kv.Data {
			if strings.HasPrefix(k, "meta_") {
				if sv, ok := v.(string); ok {
					metadata[strings.TrimPrefix(k, "meta_")] = sv
				}
			}
		}
		if len(metadata) > 0 {
			secret.Metadata = metadata
		}
	}

	if kv.VersionMetadata != nil {
		secret.Version = kv.VersionMetadata.Version
		secret.CreatedAt = kv.VersionMetadata.CreatedTime
		secret.UpdatedAt = kv.VersionMetadata.CreatedTime
	}

	return secret
}

// isNotFound returns true for HTTP 404-style errors from the OpenBao client.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return err == openbao.ErrSecretNotFound ||
		strings.Contains(err.Error(), "404") ||
		strings.Contains(err.Error(), "not found")
}

// hasAllTags returns true if secret tags contain all filter tags.
func hasAllTags(secretTags, filterTags []string) bool {
	tagSet := make(map[string]struct{}, len(secretTags))
	for _, t := range secretTags {
		tagSet[t] = struct{}{}
	}
	for _, ft := range filterTags {
		if _, ok := tagSet[ft]; !ok {
			return false
		}
	}
	return true
}

// isExpiredMeta returns true if the metadata indicates the secret has expired.
func isExpiredMeta(meta *interfaces.SecretMetadata) bool {
	if meta.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*meta.ExpiresAt)
}
