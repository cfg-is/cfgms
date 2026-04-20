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

// defaultQueueCapacity bounds the internal write queue so that a slow or stalled
// audit store cannot grow memory without bound. When the queue is full, new
// entries are dropped with a warning log — audit recording MUST NOT block
// application code paths.
const defaultQueueCapacity = 1024

// Manager provides centralized audit functionality using pluggable storage.
//
// Internally, Manager owns a bounded write queue and a background drain goroutine.
// RecordEvent / RecordBatch enqueue entries; the drain goroutine writes them to
// the configured business.AuditStore. Flush provides a synchronous rendezvous for
// callers (such as server shutdown) that need to guarantee in-flight events have
// reached the store. Stop is Flush followed by a one-shot shutdown of the drain
// goroutine and is safe to call multiple times.
type Manager struct {
	store  business.AuditStore
	source string // Component identifier for audit source

	// queue is the bounded write channel feeding the drain goroutine. Entries
	// that cannot be enqueued within a non-blocking send are dropped (logged).
	queue chan *business.AuditEntry

	// flushReq / flushAck implement a channel-based rendezvous with drainLoop.
	// A caller sends an ack-channel on flushReq, drainLoop empties the queue
	// and closes the ack-channel to signal completion.
	flushReq chan chan struct{}

	// stop signals drainLoop to exit after draining remaining entries.
	stop chan struct{}

	// done is closed by drainLoop when it has exited. Stop waits on this to
	// guarantee the goroutine has returned before returning.
	done chan struct{}

	// stopOnce guarantees Stop is idempotent.
	stopOnce sync.Once

	// logger is used for internal diagnostics (queue full, drain errors).
	logger *slog.Logger
}

// NewManager creates a new audit manager with the specified storage backend.
// It starts a background drain goroutine that writes queued entries to the
// store. Callers MUST call Stop (or Flush before process exit) to guarantee
// in-flight entries reach durable storage.
func NewManager(store business.AuditStore, source string) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("audit manager requires non-nil audit store")
	}
	if source == "" {
		return nil, fmt.Errorf("audit manager requires non-empty source identifier")
	}

	m := &Manager{
		store:    store,
		source:   source,
		queue:    make(chan *business.AuditEntry, defaultQueueCapacity),
		flushReq: make(chan chan struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		logger:   slog.Default().With("component", "audit", "source", source),
	}

	go m.drainLoop()

	return m, nil
}

// drainLoop pulls queued entries and writes them to the store. It serves flush
// requests by draining all currently queued entries and closing the ack channel.
// On stop, it drains remaining entries and exits.
func (m *Manager) drainLoop() {
	defer close(m.done)

	for {
		select {
		case entry := <-m.queue:
			m.writeEntry(entry)

		case ack := <-m.flushReq:
			// Drain every entry currently in the queue. New entries that arrive
			// after we read the current length are not part of this flush — the
			// flush guarantees entries enqueued before the Flush call reach the
			// store, not entries enqueued concurrently after it.
			m.drainRemaining()
			close(ack)

		case <-m.stop:
			// Drain anything still in the queue before exiting so Stop provides
			// the same shutdown guarantee as Flush.
			m.drainRemaining()
			return
		}
	}
}

// drainRemaining writes every entry currently in the queue to the store. It is
// called from drainLoop in response to Flush or Stop. It does not wait for new
// entries — it snapshots the current queue length and drains exactly that many.
func (m *Manager) drainRemaining() {
	for {
		select {
		case entry := <-m.queue:
			m.writeEntry(entry)
		default:
			return
		}
	}
}

// writeEntry persists a single entry to the underlying store. Errors are logged
// but do not stop the drain loop — audit writes must be best-effort rather than
// fatal to the process.
func (m *Manager) writeEntry(entry *business.AuditEntry) {
	// Use a background context so a caller-cancelled context (e.g., a short
	// request ctx) cannot abort an in-flight audit write. The queue has already
	// accepted responsibility for the entry.
	if err := m.store.StoreAuditEntry(context.Background(), entry); err != nil {
		m.logger.Warn("audit write failed",
			"error", err,
			"entry_id", entry.ID,
			"action", entry.Action,
			"resource_type", entry.ResourceType,
		)
	}
}

// enqueue attempts a non-blocking send on the queue. Returns nil on success or
// an error if the manager is stopped or the queue is full. On queue full, the
// entry is dropped with a warning log so that application code is never blocked
// by a slow audit store.
func (m *Manager) enqueue(entry *business.AuditEntry) error {
	select {
	case <-m.stop:
		return fmt.Errorf("audit manager is stopped")
	default:
	}

	select {
	case m.queue <- entry:
		return nil
	case <-m.stop:
		return fmt.Errorf("audit manager is stopped")
	default:
		// Queue is full — drop the entry and log a warning. Dropping is
		// intentional: audit recording MUST NOT stall caller goroutines.
		m.logger.Warn("audit queue full, dropping entry",
			"entry_id", entry.ID,
			"action", entry.Action,
			"resource_type", entry.ResourceType,
			"queue_capacity", defaultQueueCapacity,
		)
		return fmt.Errorf("audit queue full (capacity=%d): entry dropped", defaultQueueCapacity)
	}
}

// RecordEvent records an audit event with automatic metadata generation.
// The event is enqueued for asynchronous write; use Flush to wait for
// pending events to reach the store.
func (m *Manager) RecordEvent(ctx context.Context, event *AuditEventBuilder) error {
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

	return m.enqueue(entry)
}

// RecordBatch records multiple audit events. Each event is enqueued individually;
// batch atomicity at the store level is NOT preserved — the drain loop writes
// entries one at a time. This is a deliberate trade-off for shutdown guarantees
// and bounded memory. Callers requiring strict batch atomicity should call the
// store directly.
func (m *Manager) RecordBatch(ctx context.Context, events []*AuditEventBuilder) error {
	entries := make([]*business.AuditEntry, len(events))

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
		entries[i] = entry
	}

	// Enqueue in order so the drain loop preserves batch ordering.
	for i, entry := range entries {
		if err := m.enqueue(entry); err != nil {
			return fmt.Errorf("failed to enqueue entry %d: %w", i, err)
		}
	}
	return nil
}

// Flush blocks until every entry enqueued before this call has been written to
// the store, or ctx is cancelled, or the manager is stopped. It does not close
// the queue — subsequent RecordEvent calls continue to work.
//
// Flush is safe to call concurrently with RecordEvent; entries enqueued after
// the Flush request is observed by drainLoop are NOT guaranteed to be part of
// this flush (but will be part of a later Flush or Stop).
func (m *Manager) Flush(ctx context.Context) error {
	// If the manager is already stopped, the queue has already been drained
	// as part of Stop. Return nil (Flush semantics satisfied trivially).
	select {
	case <-m.done:
		return nil
	default:
	}

	ack := make(chan struct{})

	// Send the flush request. If the manager stops while we're waiting, bail out.
	select {
	case m.flushReq <- ack:
	case <-m.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit flush cancelled while submitting request: %w", ctx.Err())
	}

	// Wait for drainLoop to confirm the flush completed.
	select {
	case <-ack:
		return nil
	case <-m.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit flush timed out waiting for drain: %w", ctx.Err())
	}
}

// Stop flushes pending entries and shuts down the drain goroutine. It is
// idempotent — repeated calls return nil immediately. Callers should call Stop
// during graceful shutdown to guarantee audit durability.
//
// If ctx is cancelled before the flush completes, Stop returns the context
// error but still signals the drain goroutine to exit. The goroutine will
// continue draining the queue in the background on a best-effort basis.
func (m *Manager) Stop(ctx context.Context) error {
	var flushErr error

	m.stopOnce.Do(func() {
		// Attempt a pre-stop flush so callers get synchronous durability.
		flushErr = m.Flush(ctx)

		// Signal drainLoop to exit. It will drain any remaining queued entries
		// before returning.
		close(m.stop)

		// Wait for drainLoop to return so subsequent callers don't race with
		// in-flight writes. Respect ctx so Stop cannot hang indefinitely.
		select {
		case <-m.done:
		case <-ctx.Done():
			if flushErr == nil {
				flushErr = fmt.Errorf("audit stop timed out waiting for drain goroutine: %w", ctx.Err())
			}
		}
	})

	return flushErr
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
