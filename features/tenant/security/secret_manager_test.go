// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTestSecretStore creates a steward-backed SecretStore for tests.
// Skips the test if /etc/machine-id is absent (required for platform key derivation on Linux).
func newTestSecretStore(t *testing.T) secretsif.SecretStore {
	t.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}
	provider := &steward.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestTenantSecretManager_StoreSecret(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}

	isolationEngine.isolationRules["550e8400-e29b-41d4-a716-446655440000"] = &IsolationRule{
		TenantID: "550e8400-e29b-41d4-a716-446655440000",
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: true,
		},
	}

	secretStore := newTestSecretStore(t)
	tsm := NewTenantSecretManager(isolationEngine, nil, secretStore)
	ctx := context.Background()

	tests := []struct {
		name    string
		request *SecretRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid secret storage",
			request: &SecretRequest{
				TenantID:   "550e8400-e29b-41d4-a716-446655440000",
				Name:       "api-key-1",
				SecretType: SecretTypeAPIKey,
				Data:       []byte("super-secret-api-key"),
				Metadata: map[string]string{
					"environment": "production",
					"service":     "payment-gateway",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid tenant ID",
			request: &SecretRequest{
				TenantID:   "invalid-tenant",
				Name:       "api-key-1",
				SecretType: SecretTypeAPIKey,
				Data:       []byte("super-secret-api-key"),
			},
			wantErr: true,
			errMsg:  "validation failed",
		},
		{
			name: "empty secret name",
			request: &SecretRequest{
				TenantID:   "550e8400-e29b-41d4-a716-446655440000",
				Name:       "",
				SecretType: SecretTypeAPIKey,
				Data:       []byte("super-secret-api-key"),
			},
			wantErr: true,
			errMsg:  "validation failed",
		},
		{
			name: "invalid secret type",
			request: &SecretRequest{
				TenantID:   "550e8400-e29b-41d4-a716-446655440000",
				Name:       "api-key-1",
				SecretType: "invalid-type",
				Data:       []byte("super-secret-api-key"),
			},
			wantErr: true,
			errMsg:  "validation failed",
		},
		{
			name: "empty secret data",
			request: &SecretRequest{
				TenantID:   "550e8400-e29b-41d4-a716-446655440000",
				Name:       "api-key-1",
				SecretType: SecretTypeAPIKey,
				Data:       []byte{},
			},
			wantErr: true,
			errMsg:  "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := tsm.StoreSecret(ctx, tt.request)

			if tt.wantErr {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.NotEmpty(t, response.Error)
				assert.Contains(t, response.Error, tt.errMsg)
				assert.Nil(t, response.Secret)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Empty(t, response.Error)
				require.NotNil(t, response.Secret)

				secret := response.Secret
				assert.NotEmpty(t, secret.ID)
				assert.Equal(t, tt.request.TenantID, secret.TenantID)
				assert.Equal(t, tt.request.Name, secret.Name)
				assert.Equal(t, tt.request.SecretType, secret.SecretType)
				assert.NotEmpty(t, secret.EncryptedData)
				assert.NotEmpty(t, secret.KeyID)
				assert.Equal(t, 1, secret.KeyVersion)
				assert.False(t, secret.CreatedAt.IsZero())
				assert.False(t, secret.UpdatedAt.IsZero())
			}
		})
	}
}

// TestTenantSecretManager_StoreAndRetrieve verifies round-trip persistence:
// storing a secret and then retrieving it returns the original payload byte-for-byte.
func TestTenantSecretManager_StoreAndRetrieve(t *testing.T) {
	secretStore := newTestSecretStore(t)

	tenantID := "550e8400-e29b-41d4-a716-446655440000"
	isolationEngine := &TenantIsolationEngine{
		isolationRules: map[string]*IsolationRule{
			tenantID: {
				TenantID: tenantID,
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: true,
				},
			},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, secretStore)
	ctx := context.Background()

	originalData := []byte("my-super-secret-password-abc123")
	storeResp, err := tsm.StoreSecret(ctx, &SecretRequest{
		TenantID:   tenantID,
		Name:       "roundtrip-test",
		SecretType: SecretTypePassword,
		Data:       originalData,
	})
	require.NoError(t, err)
	require.Empty(t, storeResp.Error)
	require.NotNil(t, storeResp.Secret)
	secretID := storeResp.Secret.ID

	retrieveResp, err := tsm.RetrieveSecret(ctx, tenantID, secretID)
	require.NoError(t, err)
	require.NotNil(t, retrieveResp)
	assert.Empty(t, retrieveResp.Error)
	require.NotNil(t, retrieveResp.Secret)

	assert.Equal(t, originalData, retrieveResp.Data, "retrieved data must match stored data byte-for-byte")
	assert.Equal(t, tenantID, retrieveResp.Secret.TenantID)
	assert.Equal(t, secretID, retrieveResp.Secret.ID)
	assert.True(t, retrieveResp.Secret.AccessCount > 0)
	assert.NotNil(t, retrieveResp.Secret.LastAccess)
}

// TestTenantSecretManager_RetrieveUnknownSecret verifies that retrieving a secretID
// that was never stored returns an error wrapping secretsif.ErrSecretNotFound.
func TestTenantSecretManager_RetrieveUnknownSecret(t *testing.T) {
	secretStore := newTestSecretStore(t)

	tenantID := "550e8400-e29b-41d4-a716-446655440000"
	isolationEngine := &TenantIsolationEngine{
		isolationRules: map[string]*IsolationRule{
			tenantID: {
				TenantID: tenantID,
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: true,
				},
			},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, secretStore)
	ctx := context.Background()

	resp, err := tsm.RetrieveSecret(ctx, tenantID, "nonexistent-secret-id-xyz")
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.True(t, errors.Is(err, secretsif.ErrSecretNotFound),
		"expected errors.Is(err, secretsif.ErrSecretNotFound) to be true, got: %v", err)
}

// TestTenantSecretManager_RetrieveNilSecretStore verifies that RetrieveSecret returns
// (nil, error) — not a SecretResponse with Error field — when no secretStore is configured.
func TestTenantSecretManager_RetrieveNilSecretStore(t *testing.T) {
	tenantID := "550e8400-e29b-41d4-a716-446655440000"
	isolationEngine := &TenantIsolationEngine{
		isolationRules: map[string]*IsolationRule{
			tenantID: {
				TenantID: tenantID,
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: true,
				},
			},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	resp, err := tsm.RetrieveSecret(ctx, tenantID, "any-secret-id")
	assert.Nil(t, resp, "RetrieveSecret with nil store must return nil SecretResponse")
	require.Error(t, err, "RetrieveSecret with nil store must return an error")
	assert.Contains(t, err.Error(), "secret store not configured")
}

// TestTenantSecretManager_AccessControlGatesBeforeStore verifies that access control
// is enforced before the store is consulted — a denied tenant gets no store hit.
func TestTenantSecretManager_AccessControlGatesBeforeStore(t *testing.T) {
	secretStore := newTestSecretStore(t)

	tenantID := "550e8400-e29b-41d4-a716-446655440000"
	isolationEngine := &TenantIsolationEngine{
		isolationRules: map[string]*IsolationRule{
			tenantID: {
				TenantID: tenantID,
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: true,
				},
			},
			"unauthorized-tenant": {
				TenantID: "unauthorized-tenant",
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: false,
					RestrictedResources:  []string{"secrets"},
				},
			},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, secretStore)
	ctx := context.Background()

	// Store a secret under the valid tenant.
	storeResp, err := tsm.StoreSecret(ctx, &SecretRequest{
		TenantID:   tenantID,
		Name:       "access-control-test",
		SecretType: SecretTypeAPIKey,
		Data:       []byte("secret-value"),
	})
	require.NoError(t, err)
	require.Empty(t, storeResp.Error)
	secretID := storeResp.Secret.ID

	// An unauthorized tenant must be denied before the store is consulted.
	resp, err := tsm.RetrieveSecret(ctx, "unauthorized-tenant", secretID)
	require.NoError(t, err) // access denial returns a response, not an error
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Error)
	assert.Contains(t, resp.Error, "tenant access denied")
	assert.Nil(t, resp.Secret)
}

// TestTenantSecretManager_AccessCountPersisted verifies that AccessCount is incremented
// on the stored metadata (not on a transient object), so successive retrievals increment it.
func TestTenantSecretManager_AccessCountPersisted(t *testing.T) {
	secretStore := newTestSecretStore(t)

	tenantID := "550e8400-e29b-41d4-a716-446655440000"
	isolationEngine := &TenantIsolationEngine{
		isolationRules: map[string]*IsolationRule{
			tenantID: {
				TenantID: tenantID,
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: true,
				},
			},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, secretStore)
	ctx := context.Background()

	storeResp, err := tsm.StoreSecret(ctx, &SecretRequest{
		TenantID:   tenantID,
		Name:       "count-test",
		SecretType: SecretTypeToken,
		Data:       []byte("count-test-value"),
	})
	require.NoError(t, err)
	require.Empty(t, storeResp.Error)
	secretID := storeResp.Secret.ID

	r1, err := tsm.RetrieveSecret(ctx, tenantID, secretID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), r1.Secret.AccessCount)

	r2, err := tsm.RetrieveSecret(ctx, tenantID, secretID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), r2.Secret.AccessCount)
}

func TestTenantSecretManager_RetrieveSecret(t *testing.T) {
	secretStore := newTestSecretStore(t)

	validTenantID := "550e8400-e29b-41d4-a716-446655440000"
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}
	isolationEngine.isolationRules[validTenantID] = &IsolationRule{
		TenantID: validTenantID,
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: true,
		},
	}
	isolationEngine.isolationRules["unauthorized-tenant"] = &IsolationRule{
		TenantID: "unauthorized-tenant",
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: false,
			RestrictedResources:  []string{"secrets"},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, secretStore)
	ctx := context.Background()

	// Pre-store a secret so the valid-retrieval test case has something to find.
	storeResp, err := tsm.StoreSecret(ctx, &SecretRequest{
		TenantID:   validTenantID,
		Name:       "retrieve-test-key",
		SecretType: SecretTypeAPIKey,
		Data:       []byte("retrieve-test-value"),
	})
	require.NoError(t, err)
	require.Empty(t, storeResp.Error)
	storedSecretID := storeResp.Secret.ID

	tests := []struct {
		name     string
		tenantID string
		secretID string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid secret retrieval",
			tenantID: validTenantID,
			secretID: storedSecretID,
			wantErr:  false,
		},
		{
			name:     "unauthorized tenant access",
			tenantID: "unauthorized-tenant",
			secretID: storedSecretID,
			wantErr:  true,
			errMsg:   "tenant access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := tsm.RetrieveSecret(ctx, tt.tenantID, tt.secretID)

			if tt.wantErr {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.NotEmpty(t, response.Error)
				assert.Contains(t, response.Error, tt.errMsg)
				assert.Nil(t, response.Secret)
			} else {
				require.NoError(t, err)
				require.NotNil(t, response)
				assert.Empty(t, response.Error)
				require.NotNil(t, response.Secret)
				assert.NotNil(t, response.Data)

				secret := response.Secret
				assert.Equal(t, tt.tenantID, secret.TenantID)
				assert.Equal(t, tt.secretID, secret.ID)
				assert.True(t, secret.AccessCount > 0)
				assert.NotNil(t, secret.LastAccess)
			}
		})
	}
}

func TestTenantSecretManager_EncryptDecryptCycle(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}
	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	originalData := []byte("this-is-a-very-secret-password-123")
	tenantID := "test-tenant-123"

	key, err := tsm.getTenantEncryptionKey(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.Equal(t, tenantID, key.TenantID)
	assert.Len(t, key.KeyData, 32)
	assert.NotEmpty(t, key.KeyID)

	encryptedData, err := tsm.encryptData(originalData, key)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)
	assert.NotEqual(t, string(originalData), encryptedData)

	decryptedData, err := tsm.decryptData(encryptedData, key)
	require.NoError(t, err)
	assert.Equal(t, originalData, decryptedData)
}

func TestTenantSecretManager_KeyRotation(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}

	isolationEngine.isolationRules["test-tenant-id"] = &IsolationRule{
		TenantID: "test-tenant-id",
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: true,
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	tenantID := "test-tenant-id"
	secretID := "secret-123"
	newData := []byte("rotated-secret-data")

	_, err := tsm.getTenantEncryptionKey(ctx, tenantID)
	require.NoError(t, err)

	response, err := tsm.RotateSecret(ctx, tenantID, secretID, newData)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Empty(t, response.Error)
	require.NotNil(t, response.Secret)

	secret := response.Secret
	assert.Equal(t, tenantID, secret.TenantID)
	assert.Equal(t, secretID, secret.ID)
	assert.NotEmpty(t, secret.EncryptedData)
	assert.NotEmpty(t, secret.KeyID)
	assert.Equal(t, 2, secret.KeyVersion)
}

func TestTenantSecretManager_KeyRotationNeeded(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}
	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	tenantID := "test-tenant-123"

	needed, err := tsm.CheckKeyRotationNeeded(ctx, tenantID)
	require.NoError(t, err)
	assert.False(t, needed)

	key, err := tsm.getTenantEncryptionKey(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, key)

	needed, err = tsm.CheckKeyRotationNeeded(ctx, tenantID)
	require.NoError(t, err)
	assert.False(t, needed)

	key.ExpiresAt = time.Now().Add(15 * 24 * time.Hour)
	tsm.keyCache[tenantID] = key

	needed, err = tsm.CheckKeyRotationNeeded(ctx, tenantID)
	require.NoError(t, err)
	assert.True(t, needed)
}

func TestTenantSecretManager_DeleteSecret(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}

	isolationEngine.isolationRules["test-tenant-id"] = &IsolationRule{
		TenantID: "test-tenant-id",
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: true,
		},
	}

	isolationEngine.isolationRules["unauthorized-tenant"] = &IsolationRule{
		TenantID: "unauthorized-tenant",
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: false,
			RestrictedResources:  []string{"secrets"},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	tests := []struct {
		name     string
		tenantID string
		secretID string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid secret deletion",
			tenantID: "test-tenant-id",
			secretID: "secret-123",
			wantErr:  false,
		},
		{
			name:     "unauthorized tenant access",
			tenantID: "unauthorized-tenant",
			secretID: "secret-123",
			wantErr:  true,
			errMsg:   "tenant access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tsm.DeleteSecret(ctx, tt.tenantID, tt.secretID)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTenantSecretManager_ListSecrets(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}

	isolationEngine.isolationRules["test-tenant-id"] = &IsolationRule{
		TenantID: "test-tenant-id",
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: true,
		},
	}

	isolationEngine.isolationRules["unauthorized-tenant"] = &IsolationRule{
		TenantID: "unauthorized-tenant",
		ResourceIsolation: ResourceRule{
			IsolatedStorage:      true,
			AllowResourceSharing: false,
			RestrictedResources:  []string{"secrets"},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	tests := []struct {
		name     string
		tenantID string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid secret listing",
			tenantID: "test-tenant-id",
			wantErr:  false,
		},
		{
			name:     "unauthorized tenant access",
			tenantID: "unauthorized-tenant",
			wantErr:  true,
			errMsg:   "tenant access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := tsm.ListSecrets(ctx, tt.tenantID)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, secrets)
			} else {
				require.NoError(t, err)
				require.NotNil(t, secrets)
				assert.Len(t, secrets, 0)
			}
		})
	}
}

func TestSecretType_Constants(t *testing.T) {
	expectedTypes := []SecretType{
		SecretTypeAPIKey,
		SecretTypePassword,
		SecretTypeCertificate,
		SecretTypePrivateKey,
		SecretTypeToken,
		SecretTypeConnectionString,
		SecretTypeOAuth,
		SecretTypeEncryptionKey,
	}

	for _, secretType := range expectedTypes {
		assert.NotEmpty(t, string(secretType))
	}
}

func TestTenantSecretManager_ValidateSecretRequest(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}
	tsm := NewTenantSecretManager(isolationEngine, nil, nil)

	tests := []struct {
		name    string
		request *SecretRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: &SecretRequest{
				TenantID:   "550e8400-e29b-41d4-a716-446655440000",
				Name:       "valid-secret-name",
				SecretType: SecretTypeAPIKey,
				Data:       []byte("secret-data"),
				Metadata: map[string]string{
					"env": "prod",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid tenant ID format",
			request: &SecretRequest{
				TenantID:   "invalid-uuid",
				Name:       "valid-secret-name",
				SecretType: SecretTypeAPIKey,
				Data:       []byte("secret-data"),
			},
			wantErr: true,
		},
		{
			name: "invalid secret name with special characters",
			request: &SecretRequest{
				TenantID:   "550e8400-e29b-41d4-a716-446655440000",
				Name:       "invalid/secret*name",
				SecretType: SecretTypeAPIKey,
				Data:       []byte("secret-data"),
			},
			wantErr: true,
		},
		{
			name: "very large secret data",
			request: &SecretRequest{
				TenantID:   "550e8400-e29b-41d4-a716-446655440000",
				Name:       "large-secret",
				SecretType: SecretTypeAPIKey,
				Data:       make([]byte, 2*1024*1024), // 2MB
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tsm.validateSecretRequest(tt.request)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTenantSecretManager_GenerateSecretID(t *testing.T) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}
	tsm := NewTenantSecretManager(isolationEngine, nil, nil)

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := tsm.generateSecretID()
		assert.NotEmpty(t, id)
		assert.True(t, len(id) > 10)
		assert.False(t, ids[id], "Generated duplicate ID: %s", id)
		ids[id] = true
	}
}

// Benchmark tests for performance validation
func BenchmarkTenantSecretManager_EncryptData(b *testing.B) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}
	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	key, err := tsm.getTenantEncryptionKey(ctx, "bench-tenant")
	if err != nil {
		b.Fatal(err)
	}
	data := []byte("benchmark-secret-data-for-encryption-testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := tsm.encryptData(data, key)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

func BenchmarkTenantSecretManager_DecryptData(b *testing.B) {
	isolationEngine := &TenantIsolationEngine{
		isolationRules: make(map[string]*IsolationRule),
	}
	tsm := NewTenantSecretManager(isolationEngine, nil, nil)
	ctx := context.Background()

	key, err := tsm.getTenantEncryptionKey(ctx, "bench-tenant")
	if err != nil {
		b.Fatal(err)
	}
	data := []byte("benchmark-secret-data-for-decryption-testing")
	encryptedData, err := tsm.encryptData(data, key)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := tsm.decryptData(encryptedData, key)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

// TestTenantSecretManager_AuditIntegration verifies that secret operations produce
// durable audit entries in the central pkg/audit.Manager store.
func TestTenantSecretManager_AuditIntegration(t *testing.T) {
	secretStore := newTestSecretStore(t)

	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "tenant_secret_manager")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = auditMgr.Stop(ctx)
	})

	tenantID := "550e8400-e29b-41d4-a716-446655440000"
	isolationEngine := &TenantIsolationEngine{
		isolationRules: map[string]*IsolationRule{
			tenantID: {
				TenantID: tenantID,
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: true,
				},
			},
			"unauthorized-tenant": {
				TenantID: "unauthorized-tenant",
				ResourceIsolation: ResourceRule{
					IsolatedStorage:      true,
					AllowResourceSharing: false,
					RestrictedResources:  []string{"secrets"},
				},
			},
		},
	}

	tsm := NewTenantSecretManager(isolationEngine, auditMgr, secretStore)
	ctx := context.Background()

	flushAudit := func(t *testing.T) {
		t.Helper()
		fCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		require.NoError(t, auditMgr.Flush(fCtx))
	}

	t.Run("StoreSecret produces audit entry with correct fields", func(t *testing.T) {
		resp, err := tsm.StoreSecret(ctx, &SecretRequest{
			TenantID:   tenantID,
			Name:       "audit-test-key",
			SecretType: SecretTypeAPIKey,
			Data:       []byte("super-secret-value"),
		})
		require.NoError(t, err)
		require.Empty(t, resp.Error)
		secretID := resp.Secret.ID

		flushAudit(t)
		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      tenantID,
			Actions:       []string{"secret.store"},
			ResourceTypes: []string{"secret"},
			ResourceIDs:   []string{secretID},
			Limit:         10,
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)

		e := entries[0]
		assert.Equal(t, tenantID, e.TenantID)
		assert.Equal(t, "secret.store", e.Action)
		assert.Equal(t, "secret", e.ResourceType)
		assert.Equal(t, secretID, e.ResourceID)
		assert.Equal(t, business.AuditResultSuccess, e.Result)
		assert.Equal(t, "tenant_secret_manager", e.Source)
	})

	t.Run("RetrieveSecret produces audit entry with correct fields", func(t *testing.T) {
		// Pre-store so retrieve can succeed and produce a success audit entry.
		preResp, preErr := tsm.StoreSecret(ctx, &SecretRequest{
			TenantID:   tenantID,
			Name:       "retrieve-audit-prereq",
			SecretType: SecretTypeToken,
			Data:       []byte("retrieve-audit-value"),
		})
		require.NoError(t, preErr)
		require.Empty(t, preResp.Error)
		secretID := preResp.Secret.ID

		_, err := tsm.RetrieveSecret(ctx, tenantID, secretID)
		require.NoError(t, err)

		flushAudit(t)
		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      tenantID,
			Actions:       []string{"secret.retrieve"},
			ResourceTypes: []string{"secret"},
			ResourceIDs:   []string{secretID},
			Limit:         10,
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)

		e := entries[0]
		assert.Equal(t, tenantID, e.TenantID)
		assert.Equal(t, "secret.retrieve", e.Action)
		assert.Equal(t, "secret", e.ResourceType)
		assert.Equal(t, secretID, e.ResourceID)
		assert.Equal(t, business.AuditResultSuccess, e.Result)
	})

	t.Run("RotateSecret produces audit entry with correct fields", func(t *testing.T) {
		secretID := "rotate-audit-test"
		_, err := tsm.RotateSecret(ctx, tenantID, secretID, []byte("new-rotated-value"))
		require.NoError(t, err)

		flushAudit(t)
		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      tenantID,
			Actions:       []string{"secret.rotate"},
			ResourceTypes: []string{"secret"},
			ResourceIDs:   []string{secretID},
			Limit:         10,
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)

		e := entries[0]
		assert.Equal(t, tenantID, e.TenantID)
		assert.Equal(t, "secret.rotate", e.Action)
		assert.Equal(t, "secret", e.ResourceType)
		assert.Equal(t, secretID, e.ResourceID)
		assert.Equal(t, business.AuditResultSuccess, e.Result)
	})

	t.Run("Failed RetrieveSecret produces error audit entry", func(t *testing.T) {
		secretID := "denied-retrieve-test"
		resp, err := tsm.RetrieveSecret(ctx, "unauthorized-tenant", secretID)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Error)

		flushAudit(t)
		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      "unauthorized-tenant",
			Actions:       []string{"secret.retrieve"},
			ResourceTypes: []string{"secret"},
			ResourceIDs:   []string{secretID},
			Results:       []business.AuditResult{business.AuditResultError},
			Limit:         10,
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)

		e := entries[0]
		assert.Equal(t, "unauthorized-tenant", e.TenantID)
		assert.Equal(t, business.AuditResultError, e.Result)
		assert.Equal(t, "SECRET_OP_FAILED", e.ErrorCode)
	})

	t.Run("DeleteSecret produces audit entry with correct fields", func(t *testing.T) {
		secretID := "delete-audit-test"
		err := tsm.DeleteSecret(ctx, tenantID, secretID)
		require.NoError(t, err)

		flushAudit(t)
		entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
			TenantID:      tenantID,
			Actions:       []string{"secret.delete"},
			ResourceTypes: []string{"secret"},
			ResourceIDs:   []string{secretID},
			Limit:         10,
		})
		require.NoError(t, err)
		require.Len(t, entries, 1)

		e := entries[0]
		assert.Equal(t, tenantID, e.TenantID)
		assert.Equal(t, "secret.delete", e.Action)
		assert.Equal(t, "secret", e.ResourceType)
		assert.Equal(t, secretID, e.ResourceID)
		assert.Equal(t, business.AuditResultSuccess, e.Result)
	})
}
