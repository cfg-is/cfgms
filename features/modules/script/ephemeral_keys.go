// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package script

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// EphemeralAPIKey represents a time-limited API key for script callbacks
type EphemeralAPIKey struct {
	Key         string    `json:"key"`                   // The API key
	ScriptID    string    `json:"script_id"`             // Associated script ID
	ExecutionID string    `json:"execution_id"`          // Associated execution ID
	TenantID    string    `json:"tenant_id"`             // Tenant ID
	DeviceID    string    `json:"device_id"`             // Device ID
	CreatedAt   time.Time `json:"created_at"`            // Creation timestamp
	ExpiresAt   time.Time `json:"expires_at"`            // Expiration timestamp
	Permissions []string  `json:"permissions,omitempty"` // Allowed API permissions
	UsageCount  int       `json:"usage_count"`           // Number of times used
	MaxUsage    int       `json:"max_usage"`             // Maximum allowed usage (0 = unlimited)
}

// IsValid checks if the API key is still valid
func (k *EphemeralAPIKey) IsValid() bool {
	if time.Now().After(k.ExpiresAt) {
		return false
	}
	if k.MaxUsage > 0 && k.UsageCount >= k.MaxUsage {
		return false
	}
	return true
}

// IncrementUsage increments the usage counter
func (k *EphemeralAPIKey) IncrementUsage() {
	k.UsageCount++
}

// HasPermission checks if the key has a specific permission
func (k *EphemeralAPIKey) HasPermission(permission string) bool {
	if len(k.Permissions) == 0 {
		return true // No restrictions if permissions are empty
	}
	for _, p := range k.Permissions {
		if p == permission || p == "*" {
			return true
		}
	}
	return false
}

// EphemeralKeyManager manages ephemeral API keys
type EphemeralKeyManager struct {
	keys            map[string]*EphemeralAPIKey
	mu              sync.RWMutex
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// NewEphemeralKeyManager creates a new ephemeral key manager
func NewEphemeralKeyManager() *EphemeralKeyManager {
	manager := &EphemeralKeyManager{
		keys:            make(map[string]*EphemeralAPIKey),
		cleanupInterval: 1 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go manager.cleanupExpiredKeys()

	return manager
}

// GenerateKey creates a new ephemeral API key
func (m *EphemeralKeyManager) GenerateKey(scriptID, executionID, tenantID, deviceID string, ttl time.Duration, permissions []string, maxUsage int) (*EphemeralAPIKey, error) {
	// Generate random key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	key := base64.URLEncoding.EncodeToString(keyBytes)

	now := time.Now()
	apiKey := &EphemeralAPIKey{
		Key:         key,
		ScriptID:    scriptID,
		ExecutionID: executionID,
		TenantID:    tenantID,
		DeviceID:    deviceID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		Permissions: permissions,
		UsageCount:  0,
		MaxUsage:    maxUsage,
	}

	m.mu.Lock()
	m.keys[key] = apiKey
	m.mu.Unlock()

	return apiKey, nil
}

// ValidateKey validates an API key and returns its details if valid
func (m *EphemeralKeyManager) ValidateKey(key string) (*EphemeralAPIKey, error) {
	m.mu.RLock()
	apiKey, exists := m.keys[key]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid API key")
	}

	if !apiKey.IsValid() {
		// Remove expired key
		m.mu.Lock()
		delete(m.keys, key)
		m.mu.Unlock()
		return nil, fmt.Errorf("API key expired or usage limit exceeded")
	}

	return apiKey, nil
}

// UseKey validates and increments usage count for a key
func (m *EphemeralKeyManager) UseKey(key string, requiredPermission string) (*EphemeralAPIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	apiKey, exists := m.keys[key]
	if !exists {
		return nil, fmt.Errorf("invalid API key")
	}

	if !apiKey.IsValid() {
		delete(m.keys, key)
		return nil, fmt.Errorf("API key expired or usage limit exceeded")
	}

	if !apiKey.HasPermission(requiredPermission) {
		return nil, fmt.Errorf("insufficient permissions for operation: %s", requiredPermission)
	}

	apiKey.IncrementUsage()

	// Remove key if max usage reached
	if apiKey.MaxUsage > 0 && apiKey.UsageCount >= apiKey.MaxUsage {
		delete(m.keys, key)
	}

	return apiKey, nil
}

// RevokeKey revokes an API key
func (m *EphemeralKeyManager) RevokeKey(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[key]; !exists {
		return fmt.Errorf("API key not found")
	}

	delete(m.keys, key)
	return nil
}

// RevokeExecutionKeys revokes all keys associated with an execution
func (m *EphemeralKeyManager) RevokeExecutionKeys(executionID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for key, apiKey := range m.keys {
		if apiKey.ExecutionID == executionID {
			delete(m.keys, key)
			count++
		}
	}
	return count
}

// RevokeTenantKeys revokes all keys associated with a tenant
func (m *EphemeralKeyManager) RevokeTenantKeys(tenantID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for key, apiKey := range m.keys {
		if apiKey.TenantID == tenantID {
			delete(m.keys, key)
			count++
		}
	}
	return count
}

// GetKeyCount returns the number of active keys
func (m *EphemeralKeyManager) GetKeyCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.keys)
}

// GetExecutionKeys returns all keys associated with an execution
func (m *EphemeralKeyManager) GetExecutionKeys(executionID string) []*EphemeralAPIKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*EphemeralAPIKey, 0)
	for _, apiKey := range m.keys {
		if apiKey.ExecutionID == executionID {
			keys = append(keys, apiKey)
		}
	}
	return keys
}

// cleanupExpiredKeys periodically removes expired keys
func (m *EphemeralKeyManager) cleanupExpiredKeys() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performCleanup()
		case <-m.stopCleanup:
			return
		}
	}
}

// performCleanup removes expired keys
func (m *EphemeralKeyManager) performCleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, apiKey := range m.keys {
		if now.After(apiKey.ExpiresAt) || (apiKey.MaxUsage > 0 && apiKey.UsageCount >= apiKey.MaxUsage) {
			delete(m.keys, key)
		}
	}
}

// Stop stops the cleanup goroutine
func (m *EphemeralKeyManager) Stop() {
	close(m.stopCleanup)
}

// KeyGenerationOptions provides options for key generation
type KeyGenerationOptions struct {
	TTL         time.Duration // Time to live (default: 1 hour)
	Permissions []string      // Allowed permissions (empty = all)
	MaxUsage    int           // Maximum usage count (0 = unlimited)
}

// DefaultKeyOptions returns default key generation options
func DefaultKeyOptions() *KeyGenerationOptions {
	return &KeyGenerationOptions{
		TTL:         1 * time.Hour,
		Permissions: []string{"script:callback", "script:status", "script:log"},
		MaxUsage:    0, // Unlimited
	}
}

// ScriptCallbackPermissions returns permissions for script callback operations
func ScriptCallbackPermissions() []string {
	return []string{
		"script:callback", // Call back to controller
		"script:status",   // Update execution status
		"script:log",      // Send log messages
		"script:result",   // Send execution result
		"device:dna:read", // Read device DNA
		"config:read",     // Read configuration
	}
}

// LimitedCallbackPermissions returns limited permissions for restricted callbacks
func LimitedCallbackPermissions() []string {
	return []string{
		"script:status", // Update status only
		"script:log",    // Send logs only
	}
}
