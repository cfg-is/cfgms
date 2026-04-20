// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package audit provides a unified audit system for all CFGMS components
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// SystemTenantID is the sentinel tenant ID used for controller-internal system events.
// TODO(#751): controller identity as a real tenant — replace with proper tenant identity.
const SystemTenantID = "system"

// SystemUserID is the sentinel user ID used for system-originated audit events.
// TODO(#751): controller identity as a real tenant — replace with proper user identity.
const SystemUserID = "system"

// defaultQueueCapacity is the bounded capacity of the internal write queue.
// When the queue is full, RecordEvent logs a warning and drops the entry rather
// than blocking the caller — audit must not stall application code.
const defaultQueueCapacity = 1024

// errQueueFull is returned when the audit queue has no remaining capacity.
var errQueueFull = errors.New("audit queue full: entry dropped")

// errManagerStopped is returned when RecordEvent is called after Stop.
var errManagerStopped = errors.New("audit manager stopped")

// Manager provides centralized audit functionality using pluggable storage
type Manager struct {
	store  interfaces.AuditStore
	source string
	logger *slog.Logger

	queue     chan *interfaces.AuditEntry
	flushCh   chan chan struct{}
	stopCh    chan struct{}
	stopOnce  sync.Once
	drainDone chan struct{}
}

// NewManager creates a new audit manager with the specified storage backend.
// A background drain goroutine is started; call Stop to shut it down cleanly.
func NewManager(store interfaces.AuditStore, source string) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("audit manager requires non-nil audit store")
	}
	if source == "" {
		return nil, fmt.Errorf("audit manager requires non-empty source identifier")
	}

	m := &Manager{
		store:     store,
		source:    source,
		logger:    slog.Default(),
		queue:     make(chan *interfaces.AuditEntry, defaultQueueCapacity),
		flushCh:   make(chan chan struct{}),
		stopCh:    make(chan struct{}),
		drainDone: make(chan struct{}),
	}

	go m.drainLoop()

	return m, nil
}

// drainLoop reads entries from the queue and stores them one at a time.
// On a flush request it drains all pending entries before acknowledging.
// On stop it drains remaining entries then exits.
func (m *Manager) drainLoop() {
	defer close(m.drainDone)

	storeEntry := func(entry *interfaces.AuditEntry) {
		ctx := context.Background()
		if err := m.store.StoreAuditEntry(ctx, entry); err != nil {
			m.logger.Warn("audit: failed to store entry", "error", err, "id", entry.ID)
		}
	}

	drainQueue := func() {
		for {
			select {
			case entry := <-m.queue:
				storeEntry(entry)
			default:
				return
			}
		}
	}

	for {
		select {
		case entry := <-m.queue:
			storeEntry(entry)

		case ack := <-m.flushCh:
			// Drain all entries currently queued before acknowledging.
			drainQueue()
			close(ack)

		case <-m.stopCh:
			// Drain any entries that arrived between the last Flush and Stop.
			drainQueue()
			return
		}
	}
}

// Flush waits until all entries enqueued before this call have been stored.
// Returns ctx.Err() if the context is cancelled before draining completes.
func (m *Manager) Flush(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case m.flushCh <- ack:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop flushes all queued entries and shuts down the drain goroutine.
// Stop is idempotent and safe to call multiple times.
func (m *Manager) Stop(ctx context.Context) error {
	var firstErr error
	m.stopOnce.Do(func() {
		if err := m.Flush(ctx); err != nil {
			firstErr = err
		}
		close(m.stopCh)
		select {
		case <-m.drainDone:
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = ctx.Err()
			}
		}
	})
	return firstErr
}

// RecordEvent records an audit event with automatic metadata generation.
// The entry is validated synchronously, then enqueued for async storage.
// If the queue is full the entry is dropped and errQueueFull is returned.
func (m *Manager) RecordEvent(ctx context.Context, event *AuditEventBuilder) error {
	// Check if the manager has been stopped.
	select {
	case <-m.stopCh:
		return errManagerStopped
	default:
	}

	entry := &interfaces.AuditEntry{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Source:    m.source,
		Version:   "1.0",
	}

	event.build(entry)

	if err := m.validateEntry(entry); err != nil {
		return fmt.Errorf("audit validation failed: %w", err)
	}

	entry.Checksum = m.generateChecksum(entry)

	select {
	case m.queue <- entry:
		return nil
	default:
		m.logger.Warn("audit queue full: dropping entry", "id", entry.ID, "action", entry.Action, "source", m.source)
		return errQueueFull
	}
}

// RecordBatch records multiple audit events. Each entry is enqueued individually;
// batch delivery is no longer atomic with respect to store transactions.
// Returns an error listing how many entries were dropped if the queue is full.
func (m *Manager) RecordBatch(ctx context.Context, events []*AuditEventBuilder) error {
	// Check if the manager has been stopped.
	select {
	case <-m.stopCh:
		return errManagerStopped
	default:
	}

	dropped := 0
	for i, event := range events {
		entry := &interfaces.AuditEntry{
			ID:        uuid.New().String(),
			Timestamp: time.Now().UTC(),
			Source:    m.source,
			Version:   "1.0",
		}

		event.build(entry)

		if err := m.validateEntry(entry); err != nil {
			return fmt.Errorf("audit validation failed for entry %d: %w", i, err)
		}

		entry.Checksum = m.generateChecksum(entry)

		select {
		case m.queue <- entry:
		default:
			m.logger.Warn("audit queue full: dropping batch entry", "id", entry.ID, "action", entry.Action, "source", m.source)
			dropped++
		}
	}

	if dropped > 0 {
		return fmt.Errorf("audit queue full: %d of %d batch entries dropped", dropped, len(events))
	}
	return nil
}

// GetEntry retrieves an audit entry by ID
func (m *Manager) GetEntry(ctx context.Context, id string) (*interfaces.AuditEntry, error) {
	return m.store.GetAuditEntry(ctx, id)
}

// QueryEntries queries audit entries with specified filter
func (m *Manager) QueryEntries(ctx context.Context, filter *interfaces.AuditFilter) ([]*interfaces.AuditEntry, error) {
	return m.store.ListAuditEntries(ctx, filter)
}

// GetUserAuditTrail gets audit trail for a specific user
func (m *Manager) GetUserAuditTrail(ctx context.Context, userID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return m.store.GetAuditsByUser(ctx, userID, timeRange)
}

// GetResourceAuditTrail gets audit trail for a specific resource
func (m *Manager) GetResourceAuditTrail(ctx context.Context, resourceType, resourceID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return m.store.GetAuditsByResource(ctx, resourceType, resourceID, timeRange)
}

// GetFailedActions retrieves recent failed actions for security monitoring
func (m *Manager) GetFailedActions(ctx context.Context, timeRange *interfaces.TimeRange, limit int) ([]*interfaces.AuditEntry, error) {
	return m.store.GetFailedActions(ctx, timeRange, limit)
}

// GetSuspiciousActivity retrieves suspicious activity for a tenant
func (m *Manager) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return m.store.GetSuspiciousActivity(ctx, tenantID, timeRange)
}

// GetStatistics retrieves audit statistics
func (m *Manager) GetStatistics(ctx context.Context) (*interfaces.AuditStats, error) {
	return m.store.GetAuditStats(ctx)
}

// validateEntry validates required fields in an audit entry
func (m *Manager) validateEntry(entry *interfaces.AuditEntry) error {
	if entry.TenantID == "" {
		return interfaces.ErrTenantIDRequired
	}
	if entry.UserID == "" {
		return interfaces.ErrUserIDRequired
	}
	if entry.Action == "" {
		return interfaces.ErrActionRequired
	}
	if entry.ResourceType == "" {
		return interfaces.ErrResourceTypeRequired
	}
	if entry.ResourceID == "" {
		return interfaces.ErrResourceIDRequired
	}

	return nil
}

// generateChecksum generates a SHA256 checksum for audit integrity
func (m *Manager) generateChecksum(entry *interfaces.AuditEntry) string {
	// Create a copy of the entry without the checksum field for hashing
	temp := *entry
	temp.Checksum = ""

	// Create a stable representation for hashing using only immutable core fields
	// Note: We use Unix timestamp to avoid precision issues with time formatting
	hashInput := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s",
		temp.ID,
		temp.TenantID,
		temp.Timestamp.Unix(), // Use Unix timestamp for consistency
		temp.EventType,
		temp.Action,
		temp.UserID,
		temp.ResourceType,
		temp.ResourceID,
		temp.Result,
	)

	hash := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(hash[:])
}

// VerifyIntegrity verifies the integrity checksum of an audit entry
func (m *Manager) VerifyIntegrity(entry *interfaces.AuditEntry) bool {
	expectedChecksum := m.generateChecksum(entry)
	return entry.Checksum == expectedChecksum
}

// AuditEventBuilder provides a fluent interface for building audit events
type AuditEventBuilder struct {
	tenantID     string
	eventType    interfaces.AuditEventType
	action       string
	userID       string
	userType     interfaces.AuditUserType
	sessionID    string
	resourceType string
	resourceID   string
	resourceName string
	result       interfaces.AuditResult
	errorCode    string
	errorMessage string
	requestID    string
	ipAddress    string
	userAgent    string
	method       string
	path         string
	details      map[string]interface{}
	changes      *interfaces.AuditChanges
	tags         []string
	severity     interfaces.AuditSeverity
}

// NewEventBuilder creates a new audit event builder
func NewEventBuilder() *AuditEventBuilder {
	return &AuditEventBuilder{
		userType: interfaces.AuditUserTypeSystem,
		result:   interfaces.AuditResultSuccess,
		severity: interfaces.AuditSeverityMedium,
		details:  make(map[string]interface{}),
	}
}

// Tenant sets the tenant ID
func (b *AuditEventBuilder) Tenant(tenantID string) *AuditEventBuilder {
	b.tenantID = tenantID
	return b
}

// Type sets the event type
func (b *AuditEventBuilder) Type(eventType interfaces.AuditEventType) *AuditEventBuilder {
	b.eventType = eventType
	return b
}

// Action sets the action performed
func (b *AuditEventBuilder) Action(action string) *AuditEventBuilder {
	b.action = action
	return b
}

// User sets the user information
func (b *AuditEventBuilder) User(userID string, userType interfaces.AuditUserType) *AuditEventBuilder {
	b.userID = userID
	b.userType = userType
	return b
}

// Session sets the session ID
func (b *AuditEventBuilder) Session(sessionID string) *AuditEventBuilder {
	b.sessionID = sessionID
	return b
}

// Resource sets the resource information
func (b *AuditEventBuilder) Resource(resourceType, resourceID, resourceName string) *AuditEventBuilder {
	b.resourceType = resourceType
	b.resourceID = resourceID
	b.resourceName = resourceName
	return b
}

// Result sets the operation result
func (b *AuditEventBuilder) Result(result interfaces.AuditResult) *AuditEventBuilder {
	b.result = result
	return b
}

// Error sets error information for failed operations
func (b *AuditEventBuilder) Error(code, message string) *AuditEventBuilder {
	b.errorCode = code
	b.errorMessage = message
	b.result = interfaces.AuditResultError
	return b
}

// Request sets HTTP request information
func (b *AuditEventBuilder) Request(requestID, method, path, ipAddress, userAgent string) *AuditEventBuilder {
	b.requestID = requestID
	b.method = method
	b.path = path
	b.ipAddress = ipAddress
	b.userAgent = userAgent
	return b
}

// Detail adds a detail key-value pair
func (b *AuditEventBuilder) Detail(key string, value interface{}) *AuditEventBuilder {
	if b.details == nil {
		b.details = make(map[string]interface{})
	}
	b.details[key] = value
	return b
}

// Details sets multiple details
func (b *AuditEventBuilder) Details(details map[string]interface{}) *AuditEventBuilder {
	if b.details == nil {
		b.details = make(map[string]interface{})
	}
	for k, v := range details {
		b.details[k] = v
	}
	return b
}

// Changes sets before/after change information
func (b *AuditEventBuilder) Changes(before, after map[string]interface{}, fields []string) *AuditEventBuilder {
	b.changes = &interfaces.AuditChanges{
		Before: before,
		After:  after,
		Fields: fields,
	}
	return b
}

// Tag adds a tag
func (b *AuditEventBuilder) Tag(tag string) *AuditEventBuilder {
	b.tags = append(b.tags, tag)
	return b
}

// Tags sets multiple tags
func (b *AuditEventBuilder) Tags(tags []string) *AuditEventBuilder {
	b.tags = append(b.tags, tags...)
	return b
}

// Severity sets the event severity
func (b *AuditEventBuilder) Severity(severity interfaces.AuditSeverity) *AuditEventBuilder {
	b.severity = severity
	return b
}

// build applies the builder configuration to an audit entry
func (b *AuditEventBuilder) build(entry *interfaces.AuditEntry) {
	entry.TenantID = b.tenantID
	entry.EventType = b.eventType
	entry.Action = b.action
	entry.UserID = b.userID
	entry.UserType = b.userType
	entry.SessionID = b.sessionID
	entry.ResourceType = b.resourceType
	entry.ResourceID = b.resourceID
	entry.ResourceName = b.resourceName
	entry.Result = b.result
	entry.ErrorCode = b.errorCode
	entry.ErrorMessage = b.errorMessage
	entry.RequestID = b.requestID
	entry.IPAddress = b.ipAddress
	entry.UserAgent = b.userAgent
	entry.Method = b.method
	entry.Path = b.path
	entry.Details = b.details
	entry.Changes = b.changes
	entry.Tags = b.tags
	entry.Severity = b.severity
}

// Predefined audit event builders for common operations

// AuthenticationEvent creates an authentication event builder
func AuthenticationEvent(tenantID, userID, action string, result interfaces.AuditResult) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(interfaces.AuditEventAuthentication).
		Action(action).
		User(userID, interfaces.AuditUserTypeHuman).
		Resource("session", userID, "").
		Result(result).
		Severity(interfaces.AuditSeverityHigh)
}

// AuthorizationEvent creates an authorization event builder
func AuthorizationEvent(tenantID, userID, resourceType, resourceID, action string, result interfaces.AuditResult) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(interfaces.AuditEventAuthorization).
		Action(action).
		User(userID, interfaces.AuditUserTypeHuman).
		Resource(resourceType, resourceID, "").
		Result(result).
		Severity(interfaces.AuditSeverityHigh)
}

// ConfigurationEvent creates a configuration change event builder
func ConfigurationEvent(tenantID, userID, resourceType, resourceID, resourceName, action string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(interfaces.AuditEventConfiguration).
		Action(action).
		User(userID, interfaces.AuditUserTypeHuman).
		Resource(resourceType, resourceID, resourceName).
		Severity(interfaces.AuditSeverityMedium)
}

// UserManagementEvent creates a user management event builder
func UserManagementEvent(tenantID, actorUserID, targetUserID, action string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(interfaces.AuditEventUserManagement).
		Action(action).
		User(actorUserID, interfaces.AuditUserTypeHuman).
		Resource("user", targetUserID, "").
		Severity(interfaces.AuditSeverityHigh)
}

// SystemAccessEvent creates a system access event builder
func SystemAccessEvent(tenantID, userID, sessionID, action string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(interfaces.AuditEventSystemAccess).
		Action(action).
		User(userID, interfaces.AuditUserTypeHuman).
		Session(sessionID).
		Resource("terminal", sessionID, "").
		Severity(interfaces.AuditSeverityMedium)
}

// SecurityEvent creates a security event builder
func SecurityEvent(tenantID, userID, action, description string, severity interfaces.AuditSeverity) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(interfaces.AuditEventSecurityEvent).
		Action(action).
		User(userID, interfaces.AuditUserTypeSystem).
		Resource("security", userID, "").
		Detail("description", description).
		Severity(severity)
}

// SystemEvent creates a system event builder
func SystemEvent(tenantID, action, description string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(interfaces.AuditEventSystemEvent).
		Action(action).
		User(SystemUserID, interfaces.AuditUserTypeSystem).
		Resource("system", "controller", "").
		Detail("description", description).
		Severity(interfaces.AuditSeverityLow)
}
