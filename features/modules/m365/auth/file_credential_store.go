// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// #nosec G304 - M365 authentication requires file access for secure credential storage
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

// FileCredentialStore implements the CredentialStore interface using encrypted local files
type FileCredentialStore struct {
	// basePath is the directory where credentials are stored
	basePath string

	// passphrase is the passphrase used for deriving encryption keys (M-CRYPTO-2)
	passphrase string

	// Mutex for thread-safe operations
	mutex sync.RWMutex
}

// StoredCredentials represents the structure of data stored in credential files
type StoredCredentials struct {
	Tokens          map[string]*AccessToken  `json:"tokens"`
	DelegatedTokens map[string]*AccessToken  `json:"delegated_tokens,omitempty"`
	UserContexts    map[string]*UserContext  `json:"user_contexts,omitempty"`
	Configs         map[string]*OAuth2Config `json:"configs"`
}

// NewFileCredentialStore creates a new file-based credential store
func NewFileCredentialStore(basePath, passphrase string) (*FileCredentialStore, error) {
	// Ensure the base path exists
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create credential store directory: %w", err)
	}

	// M-CRYPTO-2: Store passphrase for per-credential key derivation instead of single global key
	// Each credential file will use a unique salt with PBKDF2 for defense-in-depth
	store := &FileCredentialStore{
		basePath:   basePath,
		passphrase: passphrase,
	}

	return store, nil
}

// StoreToken securely stores an access token for a tenant
func (s *FileCredentialStore) StoreToken(tenantID string, token *AccessToken) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load existing credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		// If file doesn't exist, create new credentials
		creds = &StoredCredentials{
			Tokens:          make(map[string]*AccessToken),
			DelegatedTokens: make(map[string]*AccessToken),
			UserContexts:    make(map[string]*UserContext),
			Configs:         make(map[string]*OAuth2Config),
		}
	}

	// Store the token
	creds.Tokens["access_token"] = token

	// Save credentials back to file
	return s.saveCredentials(tenantID, creds)
}

// GetToken retrieves a stored access token for a tenant
func (s *FileCredentialStore) GetToken(tenantID string) (*AccessToken, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Load credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	// Get the token
	token, exists := creds.Tokens["access_token"]
	if !exists {
		return nil, fmt.Errorf("no access token found for tenant %s", tenantID)
	}

	return token, nil
}

// DeleteToken removes a stored access token for a tenant
func (s *FileCredentialStore) DeleteToken(tenantID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load existing credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		// If file doesn't exist, consider it already deleted
		return nil
	}

	// Delete the token
	delete(creds.Tokens, "access_token")

	// If no more tokens or configs, delete the entire file
	if len(creds.Tokens) == 0 && len(creds.Configs) == 0 {
		credPath := s.getCredentialPath(tenantID)
		return os.Remove(credPath)
	}

	// Otherwise, save the updated credentials
	return s.saveCredentials(tenantID, creds)
}

// StoreConfig securely stores OAuth2 configuration for a tenant
func (s *FileCredentialStore) StoreConfig(tenantID string, config *OAuth2Config) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load existing credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		// If file doesn't exist, create new credentials
		creds = &StoredCredentials{
			Tokens:          make(map[string]*AccessToken),
			DelegatedTokens: make(map[string]*AccessToken),
			UserContexts:    make(map[string]*UserContext),
			Configs:         make(map[string]*OAuth2Config),
		}
	}

	// Store the config
	creds.Configs["oauth2_config"] = config

	// Save credentials back to file
	return s.saveCredentials(tenantID, creds)
}

// GetConfig retrieves stored OAuth2 configuration for a tenant
func (s *FileCredentialStore) GetConfig(tenantID string) (*OAuth2Config, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Load credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	// Get the config
	config, exists := creds.Configs["oauth2_config"]
	if !exists {
		return nil, fmt.Errorf("no OAuth2 configuration found for tenant %s", tenantID)
	}

	return config, nil
}

// IsAvailable checks if the credential store is available
func (s *FileCredentialStore) IsAvailable() bool {
	// Check if we can write to the base path
	testFile := filepath.Join(s.basePath, ".test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return false
	}
	_ = os.Remove(testFile) // Ignore error - we tested write access successfully
	return true
}

// ListTenants returns a list of all tenant IDs that have stored credentials
func (s *FileCredentialStore) ListTenants() ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential store directory: %w", err)
	}

	var tenants []string
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) == ".cred" {
			// Remove .cred extension to get tenant ID
			tenantID := name[:len(name)-5]
			tenants = append(tenants, tenantID)
		}
	}

	return tenants, nil
}

// ClearAll removes all stored credentials
func (s *FileCredentialStore) ClearAll() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return fmt.Errorf("failed to read credential store directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}

		if filepath.Ext(entry.Name()) == ".cred" {
			credPath := filepath.Join(s.basePath, entry.Name())
			if err := os.Remove(credPath); err != nil {
				return fmt.Errorf("failed to remove credential file %s: %w", credPath, err)
			}
		}
	}

	return nil
}

// loadCredentials loads and decrypts credentials from disk
func (s *FileCredentialStore) loadCredentials(tenantID string) (*StoredCredentials, error) {
	credPath := s.getCredentialPath(tenantID)

	// Read encrypted file
	encryptedData, err := os.ReadFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credential file: %w", err)
	}

	// Decrypt data
	decryptedData, err := s.decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	// Parse JSON
	var creds StoredCredentials
	if err := json.Unmarshal(decryptedData, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	// Ensure backward compatibility by initializing new fields if they don't exist
	if creds.DelegatedTokens == nil {
		creds.DelegatedTokens = make(map[string]*AccessToken)
	}
	if creds.UserContexts == nil {
		creds.UserContexts = make(map[string]*UserContext)
	}
	if creds.Tokens == nil {
		creds.Tokens = make(map[string]*AccessToken)
	}
	if creds.Configs == nil {
		creds.Configs = make(map[string]*OAuth2Config)
	}

	return &creds, nil
}

// saveCredentials encrypts and saves credentials to disk
func (s *FileCredentialStore) saveCredentials(tenantID string, creds *StoredCredentials) error {
	credPath := s.getCredentialPath(tenantID)

	// Marshal to JSON
	jsonData, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Encrypt data
	encryptedData, err := s.encrypt(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Write to file with secure permissions
	if err := os.WriteFile(credPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write credential file: %w", err)
	}

	return nil
}

// getCredentialPath returns the file path for a tenant's credentials
func (s *FileCredentialStore) getCredentialPath(tenantID string) string {
	// Sanitize tenant ID for use as filename
	sanitized := filepath.Base(tenantID)
	return filepath.Join(s.basePath, fmt.Sprintf("%s.cred", sanitized))
}

// encrypt encrypts data using AES-GCM with per-credential salt
// M-CRYPTO-1 & M-CRYPTO-2: Use PBKDF2 with 310,000 iterations and unique salt per credential
func (s *FileCredentialStore) encrypt(plaintext []byte) ([]byte, error) {
	// M-CRYPTO-2: Generate unique 32-byte salt for this credential file
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// M-CRYPTO-1: Derive encryption key using PBKDF2 with 310,000 iterations (OWASP 2023 recommendation)
	// Previously: 10,000 iterations with global salt "cfgms-saas-salt" (insufficient)
	// Now: 310,000 iterations with unique per-credential salt for defense-in-depth
	encryptionKey := pbkdf2.Key([]byte(s.passphrase), salt, 310000, 32, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and seal
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// M-CRYPTO-2: Prepend salt to ciphertext for per-credential key derivation
	// Format: [32-byte salt][encrypted data]
	result := append(salt, ciphertext...)
	return result, nil
}

// decrypt decrypts data using AES-GCM with per-credential salt
// M-CRYPTO-2: Supports both new format (with salt prefix) and old format (migration)
func (s *FileCredentialStore) decrypt(data []byte) ([]byte, error) {
	const saltSize = 32

	// M-CRYPTO-2: Check if data has salt prefix (new format) or is legacy format
	if len(data) > saltSize {
		// Try new format first: [32-byte salt][encrypted data]
		salt := data[:saltSize]
		ciphertext := data[saltSize:]

		// M-CRYPTO-1: Derive key with 310,000 iterations and per-credential salt
		encryptionKey := pbkdf2.Key([]byte(s.passphrase), salt, 310000, 32, sha256.New)

		// Try to decrypt with new format
		plaintext, err := s.decryptWithKey(ciphertext, encryptionKey)
		if err == nil {
			return plaintext, nil
		}

		// If new format failed, fall back to legacy format for backward compatibility
	}

	// M-CRYPTO-2: Legacy format migration - use old global salt and 10,000 iterations
	// This maintains backward compatibility with existing credential files
	legacyKey := pbkdf2.Key([]byte(s.passphrase), []byte("cfgms-saas-salt"), 10000, 32, sha256.New)
	plaintext, err := s.decryptWithKey(data, legacyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with both new and legacy formats: %w", err)
	}

	// Successfully decrypted with legacy format
	// Note: Will be automatically migrated to new format on next save
	return plaintext, nil
}

// decryptWithKey performs AES-GCM decryption with the provided key
func (s *FileCredentialStore) decryptWithKey(ciphertext []byte, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GetStorePath returns the base path where credentials are stored
func (s *FileCredentialStore) GetStorePath() string {
	return s.basePath
}

// BackupCredentials creates a backup of all credentials
func (s *FileCredentialStore) BackupCredentials(backupPath string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Ensure backup directory exists
	if err := os.MkdirAll(backupPath, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Get list of credential files
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return fmt.Errorf("failed to read credential store directory: %w", err)
	}

	// Copy each credential file
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}

		if filepath.Ext(entry.Name()) == ".cred" {
			srcPath := filepath.Join(s.basePath, entry.Name())
			dstPath := filepath.Join(backupPath, entry.Name())

			if err := s.copyFile(srcPath, dstPath); err != nil {
				return fmt.Errorf("failed to backup credential file %s: %w", entry.Name(), err)
			}
		}
	}

	return nil
}

// RestoreCredentials restores credentials from a backup
func (s *FileCredentialStore) RestoreCredentials(backupPath string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Get list of backup files
	entries, err := os.ReadDir(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	// Copy each backup file
	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}

		if filepath.Ext(entry.Name()) == ".cred" {
			srcPath := filepath.Join(backupPath, entry.Name())
			dstPath := filepath.Join(s.basePath, entry.Name())

			if err := s.copyFile(srcPath, dstPath); err != nil {
				return fmt.Errorf("failed to restore credential file %s: %w", entry.Name(), err)
			}
		}
	}

	return nil
}

// copyFile copies a file from src to dst
func (s *FileCredentialStore) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := srcFile.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if err := dstFile.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	// Set secure permissions
	if err := dstFile.Chmod(0600); err != nil {
		return err
	}

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// StoreDelegatedToken securely stores a delegated access token for a specific user
func (s *FileCredentialStore) StoreDelegatedToken(tenantID string, userID string, token *AccessToken) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load existing credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		// If file doesn't exist, create new credentials
		creds = &StoredCredentials{
			Tokens:          make(map[string]*AccessToken),
			DelegatedTokens: make(map[string]*AccessToken),
			UserContexts:    make(map[string]*UserContext),
			Configs:         make(map[string]*OAuth2Config),
		}
	}

	// Ensure maps are initialized
	if creds.DelegatedTokens == nil {
		creds.DelegatedTokens = make(map[string]*AccessToken)
	}

	// Store the delegated token with user-specific key
	tokenKey := fmt.Sprintf("delegated_%s", userID)
	creds.DelegatedTokens[tokenKey] = token

	// Save credentials back to file
	return s.saveCredentials(tenantID, creds)
}

// GetDelegatedToken retrieves a stored delegated access token for a specific user
func (s *FileCredentialStore) GetDelegatedToken(tenantID string, userID string) (*AccessToken, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Load credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	// Ensure maps are initialized
	if creds.DelegatedTokens == nil {
		return nil, fmt.Errorf("no delegated tokens found for tenant %s", tenantID)
	}

	// Get the delegated token
	tokenKey := fmt.Sprintf("delegated_%s", userID)
	token, exists := creds.DelegatedTokens[tokenKey]
	if !exists {
		return nil, fmt.Errorf("no delegated token found for user %s in tenant %s", userID, tenantID)
	}

	return token, nil
}

// DeleteDelegatedToken removes a stored delegated access token for a specific user
func (s *FileCredentialStore) DeleteDelegatedToken(tenantID string, userID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load existing credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		// If file doesn't exist, consider it already deleted
		return nil
	}

	// Ensure maps are initialized
	if creds.DelegatedTokens == nil {
		return nil
	}

	// Delete the delegated token
	tokenKey := fmt.Sprintf("delegated_%s", userID)
	delete(creds.DelegatedTokens, tokenKey)

	// If no more tokens or configs, delete the entire file
	if len(creds.Tokens) == 0 && len(creds.DelegatedTokens) == 0 && len(creds.Configs) == 0 {
		credPath := s.getCredentialPath(tenantID)
		return os.Remove(credPath)
	}

	// Otherwise, save the updated credentials
	return s.saveCredentials(tenantID, creds)
}

// StoreUserContext securely stores user context information
func (s *FileCredentialStore) StoreUserContext(tenantID string, userID string, context *UserContext) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load existing credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		// If file doesn't exist, create new credentials
		creds = &StoredCredentials{
			Tokens:          make(map[string]*AccessToken),
			DelegatedTokens: make(map[string]*AccessToken),
			UserContexts:    make(map[string]*UserContext),
			Configs:         make(map[string]*OAuth2Config),
		}
	}

	// Ensure maps are initialized
	if creds.UserContexts == nil {
		creds.UserContexts = make(map[string]*UserContext)
	}

	// Store the user context
	contextKey := fmt.Sprintf("user_%s", userID)
	creds.UserContexts[contextKey] = context

	// Save credentials back to file
	return s.saveCredentials(tenantID, creds)
}

// GetUserContext retrieves stored user context information
func (s *FileCredentialStore) GetUserContext(tenantID string, userID string) (*UserContext, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Load credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	// Ensure maps are initialized
	if creds.UserContexts == nil {
		return nil, fmt.Errorf("no user contexts found for tenant %s", tenantID)
	}

	// Get the user context
	contextKey := fmt.Sprintf("user_%s", userID)
	context, exists := creds.UserContexts[contextKey]
	if !exists {
		return nil, fmt.Errorf("no user context found for user %s in tenant %s", userID, tenantID)
	}

	return context, nil
}

// DeleteUserContext removes stored user context information
func (s *FileCredentialStore) DeleteUserContext(tenantID string, userID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Load existing credentials
	creds, err := s.loadCredentials(tenantID)
	if err != nil {
		// If file doesn't exist, consider it already deleted
		return nil
	}

	// Ensure maps are initialized
	if creds.UserContexts == nil {
		return nil
	}

	// Delete the user context
	contextKey := fmt.Sprintf("user_%s", userID)
	delete(creds.UserContexts, contextKey)

	// If no more tokens or configs, delete the entire file
	if len(creds.Tokens) == 0 && len(creds.DelegatedTokens) == 0 && len(creds.UserContexts) == 0 && len(creds.Configs) == 0 {
		credPath := s.getCredentialPath(tenantID)
		return os.Remove(credPath)
	}

	// Otherwise, save the updated credentials
	return s.saveCredentials(tenantID, creds)
}
