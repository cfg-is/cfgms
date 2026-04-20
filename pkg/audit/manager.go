// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package audit provides a unified audit system for all CFGMS components
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// defaultQueueCapacity is the bounded capacity of the internal write queue.
// When the queue is full, RecordEvent logs a warning and drops the entry rather
// than blocking the caller — audit must never stall application code.
const defaultQueueCapacity = 1024

// RedactedKeys is the deny-list of lower-cased key substrings that trigger value redaction
// in Details, Changes.Before, Changes.After, and ErrorMessage.
// Callers may append domain-specific terms before the first call to RecordEvent.
// Note: appending after NewManager is called is not goroutine-safe.
var RedactedKeys = []string{
	"password",
	"secret",
	"token",
	"api_key",
	"apikey",
	"credential",
	"private_key",
	"access_key",
	"auth",
}

// redactedValue is the placeholder used in place of sensitive values.
const redactedValue = "[REDACTED]"

// errorMessageRedactPattern matches key=value pairs where the key contains a sensitive substring.
var errorMessageRedactPattern = regexp.MustCompile(
	`(?i)(\w*(?:password|secret|token|api_key|apikey|credential|private_key|access_key|auth)\w*=)([^\s,]+)`,
)

// redactMap returns a copy of m with string values replaced by [REDACTED] when the
// lowercased key contains any substring from RedactedKeys. Non-string values are copied as-is.
// Returns nil when m is nil.
func redactMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		lower := strings.ToLower(k)
		sensitive := false
		for _, deny := range RedactedKeys {
			if strings.Contains(lower, deny) {
				sensitive = true
				break
			}
		}
		if sensitive {
			if _, isStr := v.(string); isStr {
				out[k] = redactedValue
				continue
			}
		}
		out[k] = v
	}
	return out
}

// redactErrorMessage replaces the value portion of key=value pairs in msg where the key
// matches a sensitive substring from RedactedKeys.
func redactErrorMessage(msg string) string {
	return errorMessageRedactPattern.ReplaceAllString(msg, "${1}"+redactedValue)
}

// SystemTenantID is the sentinel tenant ID used for controller-internal system events.
// TODO(#751): controller identity as a real tenant — replace with proper tenant identity.
const SystemTenantID = "system"

// SystemUserID is the sentinel user ID used for system-originated audit events.
// TODO(#751): controller identity as a real tenant — replace with proper user identity.
const SystemUserID = "system"

// Manager provides centralized audit functionality using pluggable storage.
// Events are enqueued into an internal bounded write queue and drained by a
// background goroutine, ensuring callers are never blocked by slow storage I/O.
// Call Stop(ctx) during shutdown to guarantee all in-flight events reach the store.
type Manager struct {
	store     business.AuditStore
	source    string
	queue     chan *business.AuditEntry
	flushCh   chan chan struct{}
	stopCh    chan struct{}
	drainDone chan struct{}
	stopOnce  sync.Once
}

// NewManager creates a new audit manager with the specified storage backend and
// starts the background drain goroutine. Call Stop(ctx) to flush and shut down.
func NewManager(store business.AuditStore, source string) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("audit manager requires non-nil audit store")
	}
	if source == "" {
		return nil, fmt.Errorf("audit manager requires non-empty source identifier")
	}

	m := &Manager{
		store:     store,
		source:    source,
		queue:     make(chan *business.AuditEntry, defaultQueueCapacity),
		flushCh:   make(chan chan struct{}, 1),
		stopCh:    make(chan struct{}),
		drainDone: make(chan struct{}),
	}
	go m.drainLoop()
	return m, nil
}

// drainLoop runs in the background, storing entries from the queue one at a time.
func (m *Manager) drainLoop() {
	defer close(m.drainDone)
	for {
		select {
		case entry := <-m.queue:
			if err := m.store.StoreAuditEntry(context.Background(), entry); err != nil {
				slog.Warn("audit: failed to store entry", "source", m.source, "error", err)
			}
		case ackCh := <-m.flushCh:
			m.drainRemaining()
			close(ackCh)
		case <-m.stopCh:
			m.drainRemaining()
			return
		}
	}
}

// drainRemaining empties the queue synchronously; called during flush and stop.
func (m *Manager) drainRemaining() {
	for {
		select {
		case entry := <-m.queue:
			if err := m.store.StoreAuditEntry(context.Background(), entry); err != nil {
				slog.Warn("audit: failed to store entry", "source", m.source, "error", err)
			}
		default:
			return
		}
	}
}

// Flush blocks until all entries currently in the write queue have been stored,
// or until ctx is cancelled. It is safe to call Flush concurrently with RecordEvent.
func (m *Manager) Flush(ctx context.Context) error {
	ackCh := make(chan struct{})
	select {
	case m.flushCh <- ackCh:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ackCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop flushes all in-flight events and shuts down the background drain goroutine.
// Stop is idempotent — safe to call multiple times.
func (m *Manager) Stop(ctx context.Context) error {
	var stopErr error
	m.stopOnce.Do(func() {
		if err := m.Flush(ctx); err != nil {
			stopErr = err
		}
		close(m.stopCh)
		<-m.drainDone
	})
	return stopErr
}

// RecordEvent validates and enqueues an audit event for asynchronous storage.
// Validation (field checks, redaction, checksum) runs synchronously so callers
// receive validation errors immediately. If the write queue is full, the entry is
// dropped with a warning log rather than blocking the caller.
func (m *Manager) RecordEvent(_ context.Context, event *AuditEventBuilder) error {
	entry := &business.AuditEntry{
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
	default:
		slog.Warn("audit: write queue full, dropping entry",
			"source", m.source, "action", entry.Action, "capacity", defaultQueueCapacity)
	}
	return nil
}

// RecordBatch validates and enqueues multiple audit events individually.
// Each entry is enqueued separately; batch is no longer guaranteed to be atomic
// with respect to store transactions (entries reach the store via the drain loop).
func (m *Manager) RecordBatch(_ context.Context, events []*AuditEventBuilder) error {
	for i, event := range events {
		entry := &business.AuditEntry{
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
			slog.Warn("audit: write queue full, dropping batch entry",
				"source", m.source, "index", i, "capacity", defaultQueueCapacity)
		}
	}
	return nil
}

// GetEntry retrieves an audit entry by ID
func (m *Manager) GetEntry(ctx context.Context, id string) (*business.AuditEntry, error) {
	return m.store.GetAuditEntry(ctx, id)
}

// QueryEntries queries audit entries with specified filter
func (m *Manager) QueryEntries(ctx context.Context, filter *business.AuditFilter) ([]*business.AuditEntry, error) {
	return m.store.ListAuditEntries(ctx, filter)
}

// GetUserAuditTrail gets audit trail for a specific user
func (m *Manager) GetUserAuditTrail(ctx context.Context, userID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return m.store.GetAuditsByUser(ctx, userID, timeRange)
}

// GetResourceAuditTrail gets audit trail for a specific resource
func (m *Manager) GetResourceAuditTrail(ctx context.Context, resourceType, resourceID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return m.store.GetAuditsByResource(ctx, resourceType, resourceID, timeRange)
}

// GetFailedActions retrieves recent failed actions for security monitoring
func (m *Manager) GetFailedActions(ctx context.Context, timeRange *business.TimeRange, limit int) ([]*business.AuditEntry, error) {
	return m.store.GetFailedActions(ctx, timeRange, limit)
}

// GetSuspiciousActivity retrieves suspicious activity for a tenant
func (m *Manager) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *business.TimeRange) ([]*business.AuditEntry, error) {
	return m.store.GetSuspiciousActivity(ctx, tenantID, timeRange)
}

// GetStatistics retrieves audit statistics
func (m *Manager) GetStatistics(ctx context.Context) (*business.AuditStats, error) {
	return m.store.GetAuditStats(ctx)
}

// validateEntry validates required fields in an audit entry
func (m *Manager) validateEntry(entry *business.AuditEntry) error {
	if entry.TenantID == "" {
		return business.ErrTenantIDRequired
	}
	if entry.UserID == "" {
		return business.ErrUserIDRequired
	}
	if entry.Action == "" {
		return business.ErrActionRequired
	}
	if entry.ResourceType == "" {
		return business.ErrResourceTypeRequired
	}
	if entry.ResourceID == "" {
		return business.ErrResourceIDRequired
	}

	return nil
}

// generateChecksum generates a SHA256 checksum for audit integrity
func (m *Manager) generateChecksum(entry *business.AuditEntry) string {
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
func (m *Manager) VerifyIntegrity(entry *business.AuditEntry) bool {
	expectedChecksum := m.generateChecksum(entry)
	return entry.Checksum == expectedChecksum
}

// AuditEventBuilder provides a fluent interface for building audit events
type AuditEventBuilder struct {
	tenantID     string
	eventType    business.AuditEventType
	action       string
	userID       string
	userType     business.AuditUserType
	sessionID    string
	resourceType string
	resourceID   string
	resourceName string
	result       business.AuditResult
	errorCode    string
	errorMessage string
	requestID    string
	ipAddress    string
	userAgent    string
	method       string
	path         string
	details      map[string]interface{}
	changes      *business.AuditChanges
	tags         []string
	severity     business.AuditSeverity
}

// NewEventBuilder creates a new audit event builder
func NewEventBuilder() *AuditEventBuilder {
	return &AuditEventBuilder{
		userType: business.AuditUserTypeSystem,
		result:   business.AuditResultSuccess,
		severity: business.AuditSeverityMedium,
		details:  make(map[string]interface{}),
	}
}

// Tenant sets the tenant ID
func (b *AuditEventBuilder) Tenant(tenantID string) *AuditEventBuilder {
	b.tenantID = tenantID
	return b
}

// Type sets the event type
func (b *AuditEventBuilder) Type(eventType business.AuditEventType) *AuditEventBuilder {
	b.eventType = eventType
	return b
}

// Action sets the action performed
func (b *AuditEventBuilder) Action(action string) *AuditEventBuilder {
	b.action = action
	return b
}

// User sets the user information
func (b *AuditEventBuilder) User(userID string, userType business.AuditUserType) *AuditEventBuilder {
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
func (b *AuditEventBuilder) Result(result business.AuditResult) *AuditEventBuilder {
	b.result = result
	return b
}

// Error sets error information for failed operations
func (b *AuditEventBuilder) Error(code, message string) *AuditEventBuilder {
	b.errorCode = code
	b.errorMessage = message
	b.result = business.AuditResultError
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
	b.changes = &business.AuditChanges{
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
func (b *AuditEventBuilder) Severity(severity business.AuditSeverity) *AuditEventBuilder {
	b.severity = severity
	return b
}

// build applies the builder configuration to an audit entry
func (b *AuditEventBuilder) build(entry *business.AuditEntry) {
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
	entry.RequestID = b.requestID
	entry.IPAddress = b.ipAddress
	entry.UserAgent = b.userAgent
	entry.Method = b.method
	entry.Path = b.path
	entry.Details = redactMap(b.details)
	if b.changes != nil {
		entry.Changes = &business.AuditChanges{
			Before: redactMap(b.changes.Before),
			After:  redactMap(b.changes.After),
			Fields: b.changes.Fields,
		}
	}
	entry.ErrorMessage = redactErrorMessage(b.errorMessage)
	entry.Tags = b.tags
	entry.Severity = b.severity
}

// Predefined audit event builders for common operations

// AuthenticationEvent creates an authentication event builder
func AuthenticationEvent(tenantID, userID, action string, result business.AuditResult) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventAuthentication).
		Action(action).
		User(userID, business.AuditUserTypeHuman).
		Resource("session", userID, "").
		Result(result).
		Severity(business.AuditSeverityHigh)
}

// AuthorizationEvent creates an authorization event builder
func AuthorizationEvent(tenantID, userID, resourceType, resourceID, action string, result business.AuditResult) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventAuthorization).
		Action(action).
		User(userID, business.AuditUserTypeHuman).
		Resource(resourceType, resourceID, "").
		Result(result).
		Severity(business.AuditSeverityHigh)
}

// ConfigurationEvent creates a configuration change event builder
func ConfigurationEvent(tenantID, userID, resourceType, resourceID, resourceName, action string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(userID, business.AuditUserTypeHuman).
		Resource(resourceType, resourceID, resourceName).
		Severity(business.AuditSeverityMedium)
}

// UserManagementEvent creates a user management event builder
func UserManagementEvent(tenantID, actorUserID, targetUserID, action string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventUserManagement).
		Action(action).
		User(actorUserID, business.AuditUserTypeHuman).
		Resource("user", targetUserID, "").
		Severity(business.AuditSeverityHigh)
}

// SystemAccessEvent creates a system access event builder
func SystemAccessEvent(tenantID, userID, sessionID, action string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(userID, business.AuditUserTypeHuman).
		Session(sessionID).
		Resource("terminal", sessionID, "").
		Severity(business.AuditSeverityMedium)
}

// SecurityEvent creates a security event builder
func SecurityEvent(tenantID, userID, action, description string, severity business.AuditSeverity) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSecurityEvent).
		Action(action).
		User(userID, business.AuditUserTypeSystem).
		Resource("security", userID, "").
		Detail("description", description).
		Severity(severity)
}

// SystemEvent creates a system event builder
func SystemEvent(tenantID, action, description string) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemEvent).
		Action(action).
		User(SystemUserID, business.AuditUserTypeSystem).
		Resource("system", "controller", "").
		Detail("description", description).
		Severity(business.AuditSeverityLow)
}
