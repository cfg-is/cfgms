// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
	pkgsecurity "github.com/cfgis/cfgms/pkg/security"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TenantSecretManager provides encrypted storage and management of tenant-specific secrets
type TenantSecretManager struct {
	isolationEngine *TenantIsolationEngine
	keyCache        map[string]*tenantEncryptionKey
	keyMutex        sync.RWMutex
	validator       *pkgsecurity.Validator
	auditManager    *audit.Manager
	logger          *slog.Logger
}

// tenantEncryptionKey represents an encryption key for a specific tenant
type tenantEncryptionKey struct {
	TenantID    string    `json:"tenant_id"`
	KeyData     []byte    `json:"-"` // Never serialize the actual key
	KeyID       string    `json:"key_id"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RotationDue bool      `json:"rotation_due"`
	Version     int       `json:"version"`
}

// EncryptedSecret represents an encrypted secret with metadata
type EncryptedSecret struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	Name          string            `json:"name"`
	SecretType    SecretType        `json:"secret_type"`
	EncryptedData string            `json:"encrypted_data"`
	KeyID         string            `json:"key_id"`
	KeyVersion    int               `json:"key_version"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	ExpiresAt     *time.Time        `json:"expires_at,omitempty"`
	AccessCount   int64             `json:"access_count"`
	LastAccess    *time.Time        `json:"last_access,omitempty"`
}

// SecretType represents the type of secret being stored
type SecretType string

const (
	SecretTypeAPIKey           SecretType = "api_key"
	SecretTypePassword         SecretType = "password"
	SecretTypeCertificate      SecretType = "certificate"
	SecretTypePrivateKey       SecretType = "private_key"
	SecretTypeToken            SecretType = "token"
	SecretTypeConnectionString SecretType = "connection_string"
	SecretTypeOAuth            SecretType = "oauth_credentials"
	SecretTypeEncryptionKey    SecretType = "encryption_key"
)

// SecretRequest represents a request to store or retrieve a secret
type SecretRequest struct {
	TenantID   string            `json:"tenant_id"`
	Name       string            `json:"name"`
	SecretType SecretType        `json:"secret_type"`
	Data       []byte            `json:"data"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`
}

// SecretResponse represents the response from secret operations
type SecretResponse struct {
	Secret *EncryptedSecret `json:"secret,omitempty"`
	Data   []byte           `json:"data,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// TenantSecretAuditEntry represents an audit entry for secret operations
type TenantSecretAuditEntry struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	SecretID  string    `json:"secret_id"`
	Operation string    `json:"operation"`
	UserID    string    `json:"user_id,omitempty"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	RemoteIP  string    `json:"remote_ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// NewTenantSecretManager creates a new tenant secret manager.
// auditManager may be nil, in which case secret operations are not persisted
// to the durable audit store (observable via a log warning on each operation).
func NewTenantSecretManager(isolationEngine *TenantIsolationEngine, auditManager *audit.Manager) *TenantSecretManager {
	return &TenantSecretManager{
		isolationEngine: isolationEngine,
		keyCache:        make(map[string]*tenantEncryptionKey),
		keyMutex:        sync.RWMutex{},
		validator:       pkgsecurity.NewValidator(),
		auditManager:    auditManager,
		logger:          slog.Default().With("component", "tenant_secret_manager"),
	}
}

// StoreSecret encrypts and stores a secret for a specific tenant
func (tsm *TenantSecretManager) StoreSecret(ctx context.Context, request *SecretRequest) (*SecretResponse, error) {
	// Validate the request
	if err := tsm.validateSecretRequest(request); err != nil {
		return &SecretResponse{Error: fmt.Sprintf("validation failed: %v", err)}, nil
	}

	// Verify tenant isolation
	if !tsm.isolationEngine.ValidateTenantResourceAccess(request.TenantID, "secrets", "write") {
		return &SecretResponse{Error: "tenant access denied for secret storage"}, nil
	}

	// Get or create tenant encryption key
	key, err := tsm.getTenantEncryptionKey(ctx, request.TenantID)
	if err != nil {
		return &SecretResponse{Error: fmt.Sprintf("failed to get encryption key: %v", err)}, nil
	}

	// Encrypt the secret data
	encryptedData, err := tsm.encryptData(request.Data, key)
	if err != nil {
		return &SecretResponse{Error: fmt.Sprintf("encryption failed: %v", err)}, nil
	}

	// Create the encrypted secret record
	secret := &EncryptedSecret{
		ID:            tsm.generateSecretID(),
		TenantID:      request.TenantID,
		Name:          request.Name,
		SecretType:    request.SecretType,
		EncryptedData: encryptedData,
		KeyID:         key.KeyID,
		KeyVersion:    key.Version,
		Metadata:      request.Metadata,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     request.ExpiresAt,
	}

	// Log the operation
	tsm.auditSecretOperation(ctx, secret.TenantID, secret.ID, "store", true, "")

	return &SecretResponse{Secret: secret}, nil
}

// RetrieveSecret decrypts and retrieves a secret for a specific tenant
func (tsm *TenantSecretManager) RetrieveSecret(ctx context.Context, tenantID, secretID string) (*SecretResponse, error) {
	// Validate tenant access
	if !tsm.isolationEngine.ValidateTenantResourceAccess(tenantID, "secrets", "read") {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "retrieve", false, "tenant access denied")
		return &SecretResponse{Error: "tenant access denied for secret retrieval"}, nil
	}

	// This would typically retrieve from storage - for now we'll simulate
	// In a real implementation, this would query the storage backend
	testData := []byte("test-secret-data")
	key, err := tsm.getTenantEncryptionKey(ctx, tenantID)
	if err != nil {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "retrieve", false, fmt.Sprintf("key retrieval failed: %v", err))
		return &SecretResponse{Error: fmt.Sprintf("failed to get encryption key: %v", err)}, nil
	}

	encryptedData, err := tsm.encryptData(testData, key)
	if err != nil {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "retrieve", false, fmt.Sprintf("encryption failed: %v", err))
		return &SecretResponse{Error: fmt.Sprintf("encryption failed: %v", err)}, nil
	}

	secret := &EncryptedSecret{
		TenantID:      tenantID,
		ID:            secretID,
		EncryptedData: encryptedData,
		KeyID:         key.KeyID,
		KeyVersion:    key.Version,
	}

	// Decrypt the secret data
	decryptedData, err := tsm.decryptData(secret.EncryptedData, key)
	if err != nil {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "retrieve", false, fmt.Sprintf("decryption failed: %v", err))
		return &SecretResponse{Error: fmt.Sprintf("decryption failed: %v", err)}, nil
	}

	// Update access tracking
	secret.AccessCount++
	now := time.Now()
	secret.LastAccess = &now

	// Log successful operation
	tsm.auditSecretOperation(ctx, tenantID, secretID, "retrieve", true, "")

	return &SecretResponse{Secret: secret, Data: decryptedData}, nil
}

// RotateSecret creates a new encrypted version of an existing secret
func (tsm *TenantSecretManager) RotateSecret(ctx context.Context, tenantID, secretID string, newData []byte) (*SecretResponse, error) {
	// Validate tenant access
	if !tsm.isolationEngine.ValidateTenantResourceAccess(tenantID, "secrets", "write") {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "rotate", false, "tenant access denied")
		return &SecretResponse{Error: "tenant access denied for secret rotation"}, nil
	}

	// Get current secret (in real implementation, retrieve from storage)
	currentSecret := &EncryptedSecret{
		TenantID: tenantID,
		ID:       secretID,
	}

	// Generate new encryption key if needed
	key, err := tsm.rotateTenantEncryptionKey(ctx, tenantID)
	if err != nil {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "rotate", false, fmt.Sprintf("key rotation failed: %v", err))
		return &SecretResponse{Error: fmt.Sprintf("key rotation failed: %v", err)}, nil
	}

	// Encrypt with new key
	encryptedData, err := tsm.encryptData(newData, key)
	if err != nil {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "rotate", false, fmt.Sprintf("encryption failed: %v", err))
		return &SecretResponse{Error: fmt.Sprintf("encryption failed: %v", err)}, nil
	}

	// Update secret
	currentSecret.EncryptedData = encryptedData
	currentSecret.KeyID = key.KeyID
	currentSecret.KeyVersion = key.Version
	currentSecret.UpdatedAt = time.Now()

	// Log successful operation
	tsm.auditSecretOperation(ctx, tenantID, secretID, "rotate", true, "")

	return &SecretResponse{Secret: currentSecret}, nil
}

// DeleteSecret securely removes a secret for a specific tenant
func (tsm *TenantSecretManager) DeleteSecret(ctx context.Context, tenantID, secretID string) error {
	// Validate tenant access
	if !tsm.isolationEngine.ValidateTenantResourceAccess(tenantID, "secrets", "delete") {
		tsm.auditSecretOperation(ctx, tenantID, secretID, "delete", false, "tenant access denied")
		return fmt.Errorf("tenant access denied for secret deletion")
	}

	// In real implementation, securely delete from storage
	// This should include secure memory clearing

	// Log the operation
	tsm.auditSecretOperation(ctx, tenantID, secretID, "delete", true, "")

	return nil
}

// getTenantEncryptionKey retrieves or creates an encryption key for a tenant
func (tsm *TenantSecretManager) getTenantEncryptionKey(ctx context.Context, tenantID string) (*tenantEncryptionKey, error) {
	tsm.keyMutex.RLock()
	if key, exists := tsm.keyCache[tenantID]; exists && !key.RotationDue {
		tsm.keyMutex.RUnlock()
		return key, nil
	}
	tsm.keyMutex.RUnlock()

	tsm.keyMutex.Lock()
	defer tsm.keyMutex.Unlock()

	// Double-check pattern
	if key, exists := tsm.keyCache[tenantID]; exists && !key.RotationDue {
		return key, nil
	}

	// Generate new key
	keyData := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	key := &tenantEncryptionKey{
		TenantID:    tenantID,
		KeyData:     keyData,
		KeyID:       fmt.Sprintf("tenant_key_%s_%d", tenantID, time.Now().Unix()),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(90 * 24 * time.Hour), // 90 days
		RotationDue: false,
		Version:     1,
	}

	// In real implementation, this would be stored securely
	tsm.keyCache[tenantID] = key

	return key, nil
}

// rotateTenantEncryptionKey creates a new encryption key for a tenant
func (tsm *TenantSecretManager) rotateTenantEncryptionKey(ctx context.Context, tenantID string) (*tenantEncryptionKey, error) {
	tsm.keyMutex.Lock()
	defer tsm.keyMutex.Unlock()

	// Get current key version
	currentVersion := 1
	if existingKey, exists := tsm.keyCache[tenantID]; exists {
		currentVersion = existingKey.Version + 1
		// Mark old key as requiring rotation
		existingKey.RotationDue = true
	}

	// Generate new key
	keyData := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, keyData); err != nil {
		return nil, fmt.Errorf("failed to generate new encryption key: %w", err)
	}

	key := &tenantEncryptionKey{
		TenantID:    tenantID,
		KeyData:     keyData,
		KeyID:       fmt.Sprintf("tenant_key_%s_%d", tenantID, time.Now().Unix()),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(90 * 24 * time.Hour),
		RotationDue: false,
		Version:     currentVersion,
	}

	tsm.keyCache[tenantID] = key

	return key, nil
}

// encryptData encrypts data using AES-GCM with the tenant's key
func (tsm *TenantSecretManager) encryptData(data []byte, key *tenantEncryptionKey) (string, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key.KeyData)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// Base64 encode for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptData decrypts data using AES-GCM with the tenant's key
func (tsm *TenantSecretManager) decryptData(encryptedData string, key *tenantEncryptionKey) ([]byte, error) {
	// Base64 decode
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// validateSecretRequest validates a secret storage request
func (tsm *TenantSecretManager) validateSecretRequest(request *SecretRequest) error {
	result := &pkgsecurity.ValidationResult{Valid: true}

	// Validate tenant ID
	tsm.validator.ValidateString(result, "tenant_id", request.TenantID, "required", "uuid")

	// Validate secret name
	tsm.validator.ValidateString(result, "name", request.Name, "required", "charset:alphanumeric_dash", "max_length:128")

	// Validate secret type
	validSecretTypes := []string{
		string(SecretTypeAPIKey),
		string(SecretTypePassword),
		string(SecretTypeCertificate),
		string(SecretTypePrivateKey),
		string(SecretTypeToken),
		string(SecretTypeConnectionString),
		string(SecretTypeOAuth),
		string(SecretTypeEncryptionKey),
	}

	found := false
	for _, validType := range validSecretTypes {
		if string(request.SecretType) == validType {
			found = true
			break
		}
	}
	if !found {
		result.AddError("secret_type", string(request.SecretType), "enum", "invalid secret type")
	}

	// Validate data length
	if len(request.Data) == 0 {
		result.AddError("data", "", "required", "secret data cannot be empty")
	}
	if len(request.Data) > 1024*1024 { // 1MB max
		result.AddError("data", "", "max_length", "secret data too large (max 1MB)")
	}

	// Validate metadata
	for key, value := range request.Metadata {
		tsm.validator.ValidateString(result, "metadata."+key, key, "charset:alphanumeric_dash", "max_length:64")
		tsm.validator.ValidateString(result, "metadata."+key, value, "charset:safe_text", "max_length:256")
	}

	if !result.Valid {
		return fmt.Errorf("validation failed: %s", result.Errors[0].Message)
	}

	return nil
}

// generateSecretID generates a unique identifier for a secret
func (tsm *TenantSecretManager) generateSecretID() string {
	// Generate cryptographically secure random ID
	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("secret_%d", time.Now().UnixNano())
	}

	hash := sha256.Sum256(randBytes)
	return fmt.Sprintf("secret_%x", hash[:16])
}

// auditSecretOperation routes secret management operations through the central audit manager.
// Audit failures are logged but never propagate to the caller — secret operations must not
// be blocked by a slow or unavailable audit store.
func (tsm *TenantSecretManager) auditSecretOperation(ctx context.Context, tenantID, secretID, operation string, success bool, errorMsg string) {
	if tsm.auditManager == nil {
		tsm.logger.Warn("audit manager not configured; secret operation not persisted to audit store",
			"tenant_id", tenantID,
			"operation", operation,
		)
		return
	}

	eventType := business.AuditEventDataModification
	if operation == "retrieve" {
		eventType = business.AuditEventDataAccess
	}

	event := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(eventType).
		Action("secret."+operation).
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("secret", secretID, "").
		Severity(business.AuditSeverityHigh)

	if !success && errorMsg != "" {
		event = event.Error("SECRET_OP_FAILED", errorMsg)
	}

	if err := tsm.auditManager.RecordEvent(ctx, event); err != nil {
		tsm.logger.Warn("failed to record secret operation audit event",
			"error", err,
			"tenant_id", tenantID,
			"operation", operation,
			"secret_id", secretID,
		)
	}
}

// ListSecrets returns a list of secrets for a tenant (metadata only, no secret data)
func (tsm *TenantSecretManager) ListSecrets(ctx context.Context, tenantID string) ([]*EncryptedSecret, error) {
	// Validate tenant access
	if !tsm.isolationEngine.ValidateTenantResourceAccess(tenantID, "secrets", "list") {
		return nil, fmt.Errorf("tenant access denied for secret listing")
	}

	// In real implementation, this would query the storage backend
	// Return empty list for now
	return []*EncryptedSecret{}, nil
}

// CheckKeyRotationNeeded determines if tenant encryption keys need rotation
func (tsm *TenantSecretManager) CheckKeyRotationNeeded(ctx context.Context, tenantID string) (bool, error) {
	tsm.keyMutex.RLock()
	defer tsm.keyMutex.RUnlock()

	key, exists := tsm.keyCache[tenantID]
	if !exists {
		return false, nil // No key exists yet
	}

	// Check if key is approaching expiration (30 days before expiry)
	rotationThreshold := key.ExpiresAt.Add(-30 * 24 * time.Hour)
	return time.Now().After(rotationThreshold), nil
}
