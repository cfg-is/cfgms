// Package session provides factory functions for creating session managers
package session

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// NewSessionManagerWithGlobalStorage creates a session manager using the global storage manager
// Epic 6 Compliant: Blindly uses the global storage provider without any provider-specific logic
func NewSessionManagerWithGlobalStorage(storageManager *interfaces.StorageManager, config *Config, logger logging.Logger) (SessionManager, error) {
	if storageManager == nil {
		return nil, fmt.Errorf("global storage manager is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Epic 6 Compliance: Blindly use the global storage provider
	// The session manager has NO knowledge of which provider it is using
	globalRuntimeStore := storageManager.GetRuntimeStore()
	
	// Create inline memory store for ephemeral sessions (always needed for performance)
	// Epic 6 Compliance: No external memory provider dependency
	ephemeralStore := &EphemeralRuntimeStore{
		sessions:     make(map[string]*interfaces.Session),
		runtimeState: make(map[string]interface{}),
		mutex:        &sync.RWMutex{},
	}

	// Use default config if none provided
	if config == nil {
		config = DefaultConfig()
	}

	// Epic 6: Use global provider for persistent sessions, memory for ephemeral
	// If global provider doesn't support runtime storage, CreateRuntimeStore will fail
	// and the system configuration is invalid (user must fix config)
	return NewUnifiedSessionManager(ephemeralStore, globalRuntimeStore, config, logger)
}

// NewSessionManagerWithStorage creates a unified session manager with the specified storage backends
// DEPRECATED: Use NewSessionManagerWithGlobalStorage for Epic 6 compliance
func NewSessionManagerWithStorage(config *SessionManagerConfig, logger logging.Logger) (SessionManager, error) {
	if config == nil {
		return nil, fmt.Errorf("session manager config is required")
	}

	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Create ephemeral store (required)
	ephemeralStore, err := interfaces.CreateRuntimeStoreFromConfig(
		config.EphemeralProviderName, 
		config.StorageConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ephemeral store: %w", err)
	}

	// Create persistent store (optional)
	var persistentStore interfaces.RuntimeStore
	if config.PersistentProviderName != "" {
		persistentStore, err = interfaces.CreateRuntimeStoreFromConfig(
			config.PersistentProviderName,
			config.StorageConfig,
		)
		if err != nil {
			logger.Warn("Failed to create persistent store, continuing with ephemeral only", 
				"provider", config.PersistentProviderName, 
				"error", err)
		}
	}

	// Use default config if none provided
	sessionConfig := config.SessionConfig
	if sessionConfig == nil {
		sessionConfig = DefaultConfig()
	}

	return NewUnifiedSessionManager(ephemeralStore, persistentStore, sessionConfig, logger)
}

// NewEphemeralSessionManager creates a session manager with only ephemeral storage
// DEPRECATED: Memory provider has been eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage instead.
func NewEphemeralSessionManager(config *Config, logger logging.Logger) (SessionManager, error) {
	return nil, fmt.Errorf("NewEphemeralSessionManager is deprecated: memory provider eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage with global storage manager instead")
}

// NewProductionSessionManager creates a session manager suitable for production with both storage types
// DEPRECATED: Memory provider has been eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage instead.
func NewProductionSessionManager(databaseConfig map[string]interface{}, config *Config, logger logging.Logger) (SessionManager, error) {
	return nil, fmt.Errorf("NewProductionSessionManager is deprecated: memory provider eliminated in Epic 6. Use NewSessionManagerWithGlobalStorage with global storage manager instead")
}

// NewHybridSessionManager creates a session manager with custom storage backend configuration
// Allows full control over which providers to use for ephemeral vs persistent storage
func NewHybridSessionManager(
	ephemeralProvider string,
	persistentProvider string, 
	storageConfig map[string]interface{}, 
	config *Config, 
	logger logging.Logger,
) (SessionManager, error) {
	
	sessionManagerConfig := &SessionManagerConfig{
		EphemeralProviderName:  ephemeralProvider,
		PersistentProviderName: persistentProvider,
		StorageConfig:          storageConfig,
		SessionConfig:          config,
	}

	return NewSessionManagerWithStorage(sessionManagerConfig, logger)
}

// SessionManagerBuilder provides a fluent interface for building session managers
type SessionManagerBuilder struct {
	ephemeralProvider  string
	persistentProvider string
	storageConfig      map[string]interface{}
	sessionConfig      *Config
	logger             logging.Logger
}

// NewSessionManagerBuilder creates a new session manager builder
func NewSessionManagerBuilder() *SessionManagerBuilder {
	return &SessionManagerBuilder{
		storageConfig: make(map[string]interface{}),
	}
}

// WithEphemeralProvider sets the ephemeral storage provider
func (b *SessionManagerBuilder) WithEphemeralProvider(provider string) *SessionManagerBuilder {
	b.ephemeralProvider = provider
	return b
}

// WithPersistentProvider sets the persistent storage provider
func (b *SessionManagerBuilder) WithPersistentProvider(provider string) *SessionManagerBuilder {
	b.persistentProvider = provider
	return b
}

// WithStorageConfig sets the storage configuration
func (b *SessionManagerBuilder) WithStorageConfig(config map[string]interface{}) *SessionManagerBuilder {
	b.storageConfig = config
	return b
}

// WithSessionConfig sets the session configuration
func (b *SessionManagerBuilder) WithSessionConfig(config *Config) *SessionManagerBuilder {
	b.sessionConfig = config
	return b
}

// WithLogger sets the logger
func (b *SessionManagerBuilder) WithLogger(logger logging.Logger) *SessionManagerBuilder {
	b.logger = logger
	return b
}

// Build creates the session manager
func (b *SessionManagerBuilder) Build() (SessionManager, error) {
	if b.ephemeralProvider == "" {
		return nil, fmt.Errorf("ephemeral provider is required: memory provider eliminated in Epic 6, use WithEphemeralProvider() to specify provider")
	}

	if b.logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	sessionManagerConfig := &SessionManagerConfig{
		EphemeralProviderName:  b.ephemeralProvider,
		PersistentProviderName: b.persistentProvider,
		StorageConfig:          b.storageConfig,
		SessionConfig:          b.sessionConfig,
	}

	return NewSessionManagerWithStorage(sessionManagerConfig, b.logger)
}

// Example usage functions - Epic 6 Compliant

// ExampleControllerIntegration shows how to integrate session management with controller
// This is the correct Epic 6 pattern - use the global storage manager
func ExampleControllerIntegration(storageManager *interfaces.StorageManager, logger logging.Logger) (SessionManager, error) {
	// Epic 6 Compliant: Use global storage manager (same as RBAC, Audit, Config)
	config := DefaultConfig()
	config.MaxSessions = 10000
	config.DefaultSessionTimeout = 1 * time.Hour
	
	return NewSessionManagerWithGlobalStorage(storageManager, config, logger)
}

// ExampleDevelopmentSetup shows development setup using global storage (Epic 6 compliant)
func ExampleDevelopmentSetup(storageManager *interfaces.StorageManager, logger logging.Logger) (SessionManager, error) {
	// Development: Uses whatever storage provider is configured globally
	// Epic 6: Memory provider eliminated - use git/database for development
	// All storage providers support both ephemeral and persistent sessions
	return NewSessionManagerWithGlobalStorage(storageManager, DefaultConfig(), logger)
}

// ExampleProductionSetup shows production setup using global storage (Epic 6 compliant)  
func ExampleProductionSetup(storageManager *interfaces.StorageManager, logger logging.Logger) (SessionManager, error) {
	// Production: Uses global storage provider (typically database)
	config := DefaultConfig()
	config.MaxSessions = 50000         // High limit for production
	config.DefaultSessionTimeout = 2 * time.Hour  // Longer sessions
	config.CleanupInterval = 1 * time.Minute      // Frequent cleanup
	
	// Epic 6 Compliance: Uses same provider as RBAC/Audit/Config
	return NewSessionManagerWithGlobalStorage(storageManager, config, logger)
}

// Legacy examples (DEPRECATED - not Epic 6 compliant)

// ExampleCustomSetup shows how to set up session management with custom providers
// DEPRECATED: Use ExampleControllerIntegration for Epic 6 compliance
func ExampleCustomSetup(logger logging.Logger) (SessionManager, error) {
	return nil, fmt.Errorf("ExampleCustomSetup is deprecated: memory provider eliminated in Epic 6. Use ExampleControllerIntegration with global storage manager instead")
}


// EphemeralRuntimeStore provides in-memory runtime storage for session factory
// Epic 6 Compliance: No external memory provider dependencies
type EphemeralRuntimeStore struct {
	sessions     map[string]*interfaces.Session
	runtimeState map[string]interface{}
	mutex        *sync.RWMutex
}
// EphemeralRuntimeStore implementation
// Provides ephemeral runtime storage for sessions and runtime state

// CreateSession creates a new session
func (s *EphemeralRuntimeStore) CreateSession(ctx context.Context, session *interfaces.Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	if err := session.Validate(); err != nil {
		return fmt.Errorf("invalid session: %w", err)
	}
	
	if _, exists := s.sessions[session.SessionID]; exists {
		return fmt.Errorf("session already exists: %s", session.SessionID)
	}
	
	s.sessions[session.SessionID] = session
	return nil
}

// GetSession retrieves a session by ID
func (s *EphemeralRuntimeStore) GetSession(ctx context.Context, sessionID string) (*interfaces.Session, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	
	return session, nil
}

// UpdateSession updates an existing session
func (s *EphemeralRuntimeStore) UpdateSession(ctx context.Context, sessionID string, session *interfaces.Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	if err := session.Validate(); err != nil {
		return fmt.Errorf("invalid session: %w", err)
	}
	
	if _, exists := s.sessions[sessionID]; !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	s.sessions[sessionID] = session
	return nil
}

// DeleteSession removes a session
func (s *EphemeralRuntimeStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if _, exists := s.sessions[sessionID]; !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	delete(s.sessions, sessionID)
	return nil
}

// ListSessions returns sessions matching the filter
func (s *EphemeralRuntimeStore) ListSessions(ctx context.Context, filters *interfaces.SessionFilter) ([]*interfaces.Session, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	var result []*interfaces.Session
	
	for _, session := range s.sessions {
		if s.matchesFilter(session, filters) {
			result = append(result, session)
		}
	}
	
	return result, nil
}

// SetSessionTTL sets session TTL
func (s *EphemeralRuntimeStore) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	session.ExpiresAt = time.Now().Add(ttl)
	return nil
}

// CleanupExpiredSessions removes expired sessions
func (s *EphemeralRuntimeStore) CleanupExpiredSessions(ctx context.Context) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	now := time.Now()
	count := 0
	
	for id, session := range s.sessions {
		if session.ExpiresAt.Before(now) {
			delete(s.sessions, id)
			count++
		}
	}
	
	return count, nil
}

// ListExpiredSessions returns IDs of expired sessions
func (s *EphemeralRuntimeStore) ListExpiredSessions(ctx context.Context, cutoff time.Time) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	var result []string
	
	for id, session := range s.sessions {
		if session.ExpiresAt.Before(cutoff) {
			result = append(result, id)
		}
	}
	
	return result, nil
}

// Runtime state methods
func (s *EphemeralRuntimeStore) SetRuntimeState(ctx context.Context, key string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	s.runtimeState[key] = value
	return nil
}

func (s *EphemeralRuntimeStore) GetRuntimeState(ctx context.Context, key string) (interface{}, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	value, exists := s.runtimeState[key]
	if !exists {
		return nil, fmt.Errorf("runtime state key not found: %s", key)
	}
	
	return value, nil
}

func (s *EphemeralRuntimeStore) DeleteRuntimeState(ctx context.Context, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	delete(s.runtimeState, key)
	return nil
}

func (s *EphemeralRuntimeStore) ListRuntimeKeys(ctx context.Context, prefix string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	var result []string
	
	for key := range s.runtimeState {
		if strings.HasPrefix(key, prefix) {
			result = append(result, key)
		}
	}
	
	return result, nil
}

// Batch operations
func (s *EphemeralRuntimeStore) CreateSessionsBatch(ctx context.Context, sessions []*interfaces.Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	for _, session := range sessions {
		if session == nil {
			return fmt.Errorf("session cannot be nil")
		}
		
		if err := session.Validate(); err != nil {
			return fmt.Errorf("invalid session: %w", err)
		}
		
		if _, exists := s.sessions[session.SessionID]; exists {
			return fmt.Errorf("session already exists: %s", session.SessionID)
		}
		
		s.sessions[session.SessionID] = session
	}
	
	return nil
}

func (s *EphemeralRuntimeStore) DeleteSessionsBatch(ctx context.Context, sessionIDs []string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	for _, id := range sessionIDs {
		delete(s.sessions, id)
	}
	
	return nil
}

// Query methods
func (s *EphemeralRuntimeStore) GetSessionsByUser(ctx context.Context, userID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{UserID: userID}
	return s.ListSessions(ctx, filter)
}

func (s *EphemeralRuntimeStore) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{TenantID: tenantID}
	return s.ListSessions(ctx, filter)
}

func (s *EphemeralRuntimeStore) GetSessionsByType(ctx context.Context, sessionType interfaces.SessionType) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{Type: sessionType}
	return s.ListSessions(ctx, filter)
}

func (s *EphemeralRuntimeStore) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	count := int64(0)
	for _, session := range s.sessions {
		if session.IsActive() {
			count++
		}
	}
	
	return count, nil
}

// Health and maintenance
func (s *EphemeralRuntimeStore) HealthCheck(ctx context.Context) error {
	return nil // Always healthy for in-memory
}

func (s *EphemeralRuntimeStore) GetStats(ctx context.Context) (*interfaces.RuntimeStoreStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	stats := &interfaces.RuntimeStoreStats{
		TotalSessions:    int64(len(s.sessions)),
		ActiveSessions:   0,
		ExpiredSessions:  0,
		SessionsByType:   make(map[string]int64),
		SessionsByStatus: make(map[string]int64),
		RuntimeStateKeys: int64(len(s.runtimeState)),
		StorageSize:      0, // Not calculated for in-memory
	}
	
	for _, session := range s.sessions {
		if session.IsActive() {
			stats.ActiveSessions++
		}
		if session.IsExpired() {
			stats.ExpiredSessions++
		}
		
		stats.SessionsByType[string(session.SessionType)]++
		stats.SessionsByStatus[string(session.Status)]++
	}
	
	return stats, nil
}

func (s *EphemeralRuntimeStore) Vacuum(ctx context.Context) error {
	_, err := s.CleanupExpiredSessions(ctx)
	return err
}

// Helper method for filtering
func (s *EphemeralRuntimeStore) matchesFilter(session *interfaces.Session, filter *interfaces.SessionFilter) bool {
	if filter == nil {
		return true
	}
	
	if filter.UserID != "" && session.UserID != filter.UserID {
		return false
	}
	if filter.TenantID != "" && session.TenantID != filter.TenantID {
		return false
	}
	if filter.Type != "" && session.SessionType != filter.Type {
		return false
	}
	if filter.Status != "" && session.Status != filter.Status {
		return false
	}
	
	return true
}