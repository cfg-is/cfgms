// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package audit provides a unified audit system for all CFGMS components
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/logging"
	secretsInterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// StoreRequirements declares the storage stores required by the audit subsystem.
// Collected by collectActiveStorageRequirements in features/controller/server and validated
// at startup via interfaces.ValidateStorageRequirements — a missing AuditStore fails
// closed rather than silently dropping all audit recording when a provider cannot supply it.
var StoreRequirements = []interfaces.StoreRequirement{
	{Subsystem: "audit", Store: interfaces.StoreNameAudit, Severity: interfaces.RequirementRequired},
}

// RedactedKeys is the deny-list of lower-cased key substrings that trigger value redaction
// in Details, Changes.Before, Changes.After, and ErrorMessage.
// Callers may append domain-specific terms before the first call to RecordEvent.
// Note: appending after NewManager is called is not goroutine-safe.
//
// "auth" is matched as a plain substring like every other term, except for the
// small exact-match allow-list of attribution keys in authAttributionKeys
// ("author", "authorized_by", ...), so "authorization", "authentication" and
// "auth_token" are redacted while attribution fields are not.
var RedactedKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api_key",
	"apikey",
	"credential",
	"private_key",
	"privatekey",
	"access_key",
	"auth",
}

// redactedValue is the placeholder used in place of sensitive values.
const redactedValue = "[REDACTED]"

// authAttributionKeys is the exact-match allow-list of keys that contain "auth"
// but carry attribution data — who wrote or approved something — rather than a
// credential. These are the only keys exempt from the "auth" deny-list term.
//
// The exemption is exact-match and therefore fail-closed: any key containing
// "auth" that is not listed here is redacted. This is deliberate. A previous
// attempt at Issue #4098 item 7 exempted attribution keys with a token-boundary
// regexp (`auth(?:[^a-zA-Z]|$)`, i.e. "auth" not followed by a letter), which
// also stopped redacting "Authorization", "authorization", "authentication" and
// "AuthHeader" — writing bearer and basic credentials from HTTP header maps into
// the durable audit store in cleartext. Over-matching an unrecognised attribution
// key costs a redacted audit detail; under-matching leaks a credential.
//
// Keys are compared after lowercasing and stripping non-alphanumeric characters,
// so "authorized_by", "Authorized-By" and "authorizedBy" all match one entry.
var authAttributionKeys = map[string]struct{}{
	"author":         {},
	"authors":        {},
	"authoredby":     {},
	"authorizedby":   {},
	"authorisedby":   {},
	"authorname":     {},
	"authoremail":    {},
	"authorizedbyid": {},
}

// nonAlphanumeric matches the separator characters stripped from a key before it
// is compared against authAttributionKeys.
var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]`)

// isAuthAttributionKey reports whether lowerKey is one of the attribution keys
// exempt from the "auth" deny-list term.
func isAuthAttributionKey(lowerKey string) bool {
	_, ok := authAttributionKeys[nonAlphanumeric.ReplaceAllString(lowerKey, "")]
	return ok
}

// isSensitiveKey reports whether key's lowercased form matches any deny-list term
// in RedactedKeys. Every term, "auth" included, is matched as a plain substring;
// the sole exception is that "auth" does not fire for the exact attribution keys
// in authAttributionKeys, whose over-matching was Issue #4098 item 7. Other
// deny-list terms still apply to those keys, so "author_token" is redacted by
// "token" even though "author" is exempt from "auth".
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, deny := range RedactedKeys {
		if !strings.Contains(lower, deny) {
			continue
		}
		if deny == "auth" && isAuthAttributionKey(lower) {
			continue
		}
		return true
	}
	return false
}

// errorMessagePatternOnce lazily builds compiledErrorMessagePattern from RedactedKeys
// on first use — after any caller-side appends to RedactedKeys made before the first
// RecordEvent call (the documented, single point at which appends are safe), so the
// ErrorMessage/Details/Changes redaction paths never drift onto different key sets
// (Issue #4098 item 4: RedactedKeys and the pattern used to be two independently
// maintained lists).
var (
	errorMessagePatternOnce     sync.Once
	compiledErrorMessagePattern *regexp.Regexp
)

func errorMessageRedactPattern() *regexp.Regexp {
	errorMessagePatternOnce.Do(func() {
		compiledErrorMessagePattern = buildErrorMessageRedactPattern(RedactedKeys)
	})
	return compiledErrorMessagePattern
}

// buildErrorMessageRedactPattern compiles a pattern matching key/value pairs whose
// key contains any of keys, across three separator shapes (key=value, key: value,
// "key":"value"). The value alternative prefers a quoted JSON-style string and
// otherwise consumes everything up to the next comma or newline — not just to the
// next whitespace — so a value containing a space is redacted in its entirety
// rather than truncated at the first space (Issue #4098 item 6).
func buildErrorMessageRedactPattern(keys []string) *regexp.Regexp {
	escaped := make([]string, len(keys))
	for i, k := range keys {
		escaped[i] = regexp.QuoteMeta(k)
	}
	keyAlt := strings.Join(escaped, "|")
	pattern := `(?i)("?\w*(?:` + keyAlt + `)\w*"?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|[^,\n]+)`
	return regexp.MustCompile(pattern)
}

// redactMap returns a copy of m with sensitive values replaced by [REDACTED] and
// nested maps/slices scanned recursively (Issue #4098 item 3): a sensitive key
// redacts its value outright regardless of Go type, a non-sensitive key holding a
// nested map or slice is descended into, and a non-sensitive key holding a string
// has that string scanned for embedded key=value secrets (item 5). Returns nil
// when m is nil.
func redactMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = redactValue(k, v)
	}
	return out
}

// redactValue redacts v under key k: a sensitive key always yields redactedValue,
// whatever v's Go type. Otherwise v is scanned structurally by scanValue.
func redactValue(k string, v interface{}) interface{} {
	if isSensitiveKey(k) {
		return redactedValue
	}
	return scanValue(v)
}

// scanValue recurses into maps and slices, and applies the free-form key=value
// scan to strings. Other types pass through unchanged.
func scanValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return redactMap(val)
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = scanValue(item)
		}
		return out
	case string:
		return redactErrorMessage(val)
	default:
		return v
	}
}

// redactErrorMessage replaces the value portion of key/value pairs in msg where the
// key matches a sensitive substring from RedactedKeys, across the key=value,
// key: value, and "key":"value" separator shapes.
func redactErrorMessage(msg string) string {
	return errorMessageRedactPattern().ReplaceAllString(msg, "${1}"+redactedValue)
}

// SystemTenantID is the sentinel tenant ID used for controller-internal system events.
// TODO(#751): controller identity as a real tenant — replace with proper tenant identity.
const SystemTenantID = "system"

// SystemUserID is the sentinel user ID used for system-originated audit events.
// TODO(#751): controller identity as a real tenant — replace with proper user identity.
const SystemUserID = "system"

// The queue bounds memory while applying backpressure rather than dropping
// security records. The drain batches writes so a burst does not turn into one
// transaction and one chain-head lookup per event.
const (
	defaultQueueCapacity  = 1024
	defaultDrainBatchSize = 256
)

// ChainBreak describes a single integrity violation found by VerifyChain.
type ChainBreak struct {
	EntryID        string
	SequenceNumber uint64
	Reason         string
}

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

	// hmacKey is used for HMAC-SHA256 checksum generation. Generated randomly
	// at startup unless a secrets store is provided.
	hmacKey []byte

	// queue is the bounded write channel feeding the drain goroutine. When it is
	// full, producers wait for capacity or their context cancellation; entries
	// are never silently dropped.
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

	// lostEntries counts entries whose AppendChainedEntry call failed on every
	// bounded-retry attempt (Issue #4098, AC9). It is cumulative for the
	// Manager's lifetime and never cleared — Flush and Stop both report it on
	// every call, not just the first, so a loss cannot be reported into one
	// caller's return value and then silently vanish for the next.
	lostEntries atomic.Uint64

	// logger is used for internal storage and drain diagnostics.
	logger *slog.Logger
}

// managerOption is a functional option for NewManager.
type managerOption func(*Manager, context.Context) error

// WithSecretsStore configures the Manager to load its HMAC signing key from
// the provided secrets store (tenant "audit", key "hmac-key"). If the key does
// not exist it is generated and stored. Corrupt or unavailable durable storage
// fails construction; silently rotating or using an ephemeral key would make
// previously persisted chains unverifiable.
//
// Adversary bound (ADR-004, Issue #3727): the key loaded here is read from the
// controller's own secrets store and stays resident in m.hmacKey for the life
// of the process. It defends the chain against an actor with audit-storage
// access who does not hold this key — it does NOT defend against the
// controller process itself, or anyone who compromises the controller host.
// That actor holds this key by construction and can rewrite audit history
// into a chain VerifyChain reports as fully consistent. See
// docs/architecture/decisions/004-audit-chain-integrity.md#adversary-bound-issue-3727.
func WithSecretsStore(store secretsInterfaces.SecretStore) managerOption {
	return func(m *Manager, ctx context.Context) error {
		const keyName = "audit/hmac-key"
		secret, err := store.GetSecret(ctx, keyName)
		if err == nil && secret != nil && len(secret.Value) > 0 {
			raw, decodeErr := hex.DecodeString(secret.Value)
			if decodeErr == nil && len(raw) == 32 {
				m.hmacKey = raw
				return nil
			}
			return fmt.Errorf("stored audit HMAC key is invalid")
		}
		if err != nil && !errors.Is(err, secretsInterfaces.ErrSecretNotFound) {
			return fmt.Errorf("load audit HMAC key: %w", err)
		}
		// Key is absent — generate and persist before accepting audit events.
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("failed to generate audit HMAC key: %w", err)
		}
		if err := store.StoreSecret(ctx, &secretsInterfaces.SecretRequest{
			Key:         "hmac-key",
			Value:       hex.EncodeToString(key),
			Description: "HMAC signing key for audit chain integrity",
			TenantID:    "audit",
			CreatedBy:   "controller",
		}); err != nil {
			return fmt.Errorf("persist audit HMAC key: %w", err)
		}
		m.hmacKey = key
		return nil
	}
}

// NewManager creates a new audit manager with the specified storage backend.
// It starts a background drain goroutine that writes queued entries to the
// store. Callers MUST call Stop (or Flush before process exit) to guarantee
// in-flight entries reach durable storage.
//
// Optional functional options (e.g. WithSecretsStore) may be passed to
// configure persistent HMAC key storage. Without options a random 32-byte
// in-process key is generated — per-entry integrity is preserved within the
// process run but the key is not durable across restarts.
func NewManager(store business.AuditStore, source string, opts ...managerOption) (*Manager, error) {
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

	ctx := context.Background()
	for _, opt := range opts {
		if err := opt(m, ctx); err != nil {
			return nil, fmt.Errorf("audit manager option failed: %w", err)
		}
	}

	// Fall back to random in-process key if no persistent key was provided.
	if m.hmacKey == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate audit HMAC key: %w", err)
		}
		m.hmacKey = key
		m.logger.Warn("audit HMAC key is ephemeral; use WithSecretsStore for cross-restart integrity")
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
			m.writeBatch(m.collectBatch(entry))

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
			m.writeBatch(m.collectBatch(entry))
		default:
			return
		}
	}
}

func (m *Manager) collectBatch(first *business.AuditEntry) []*business.AuditEntry {
	batch := make([]*business.AuditEntry, 0, defaultDrainBatchSize)
	batch = append(batch, first)
	for len(batch) < defaultDrainBatchSize {
		select {
		case entry := <-m.queue:
			batch = append(batch, entry)
		default:
			return batch
		}
	}
	return batch
}

// maxAppendAttempts bounds retry of a failed AppendChainedEntry (Issue #4098,
// AC9): the initial attempt plus this many total tries before the entry is
// counted as permanently lost. appendRetryDelay scales linearly per retry
// (10ms, 20ms) to keep the bound small and deterministic for a background
// drain goroutine.
const (
	maxAppendAttempts = 3
	appendRetryDelay  = 10 * time.Millisecond
)

// writeBatch persists a group of entries, delegating sequence-number assignment
// and PreviousChecksum linkage to the store's AppendChainedEntry so that
// multiple controller nodes writing this tenant's chain against a shared
// database cannot interleave (ADR-004 amendment, ADR-031 Decision 1, Issue
// #3754). Entries are appended one at a time: each entry's PreviousChecksum
// must link to whatever the store durably holds as the chain head at the
// moment it is appended — which may include an entry another node wrote
// concurrently — so entries cannot be pre-linked client-side across a batch.
//
// A failed append is retried with bounded backoff (appendWithRetry). A failed
// entry does not abort the rest of the batch. When retries are exhausted the
// entry is counted in m.lostEntries and logged at Error — RecordEvent already
// returned successfully for it, so the loss can no longer reach the original
// caller directly; Flush and Stop surface the cumulative count instead
// (Issue #4098, AC9).
func (m *Manager) writeBatch(entries []*business.AuditEntry) {
	ctx := context.Background()
	for _, entry := range entries {
		if err := m.appendWithRetry(ctx, entry); err != nil {
			m.lostEntries.Add(1)
			m.logger.Error("audit entry permanently lost after exhausting append retries",
				"error", logging.SanitizeLogValue(err.Error()),
				"tenant_id", logging.SanitizeLogValue(entry.TenantID),
			)
		}
	}
}

// appendWithRetry calls AppendChainedEntry up to maxAppendAttempts times,
// sleeping appendRetryDelay*attempt between tries, and returns the last error
// if every attempt failed.
func (m *Manager) appendWithRetry(ctx context.Context, entry *business.AuditEntry) error {
	var lastErr error
	for attempt := 0; attempt < maxAppendAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(appendRetryDelay * time.Duration(attempt))
		}
		lastErr = m.store.AppendChainedEntry(ctx, entry.TenantID, entry, m.generateChecksum)
		if lastErr == nil {
			return nil
		}
		m.logger.Warn("audit entry append attempt failed, retrying",
			"error", logging.SanitizeLogValue(lastErr.Error()),
			"tenant_id", logging.SanitizeLogValue(entry.TenantID),
			"attempt", attempt+1,
		)
	}
	return lastErr
}

// lostEntriesErr returns a non-nil error naming the cumulative count of
// permanently lost entries, or nil if none have been lost. The count is never
// cleared, so repeated calls (e.g. a second Stop) report the same total.
func (m *Manager) lostEntriesErr() error {
	n := m.lostEntries.Load()
	if n == 0 {
		return nil
	}
	return fmt.Errorf("audit manager has permanently lost %d entries after exhausting append retries", n)
}

// enqueue waits for bounded queue capacity, manager shutdown, or caller
// cancellation. Backpressure is preferable to silently losing authorization
// evidence; memory remains bounded by defaultQueueCapacity.
func (m *Manager) enqueue(ctx context.Context, entry *business.AuditEntry) error {
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
	case <-ctx.Done():
		return fmt.Errorf("audit enqueue cancelled while waiting for capacity: %w", ctx.Err())
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

	return m.enqueue(ctx, entry)
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

		entries[i] = entry
	}

	// Enqueue in order so the drain loop preserves batch ordering.
	for i, entry := range entries {
		if err := m.enqueue(ctx, entry); err != nil {
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
//
// On every successful return (drain completed or manager already stopped),
// Flush returns a non-nil error naming the cumulative count of entries
// permanently lost to exhausted append retries (Issue #4098, AC9), or nil if
// none have been lost. That count is never cleared, so repeated Flush calls
// report the same total until more entries are lost.
func (m *Manager) Flush(ctx context.Context) error {
	// If the manager is already stopped, the queue has already been drained
	// as part of Stop.
	select {
	case <-m.done:
		return m.lostEntriesErr()
	default:
	}

	ack := make(chan struct{})

	// Send the flush request. If the manager stops while we're waiting, bail out.
	select {
	case m.flushReq <- ack:
	case <-m.done:
		return m.lostEntriesErr()
	case <-ctx.Done():
		return fmt.Errorf("audit flush cancelled while submitting request: %w", ctx.Err())
	}

	// Wait for drainLoop to confirm the flush completed.
	select {
	case <-ack:
		return m.lostEntriesErr()
	case <-m.done:
		return m.lostEntriesErr()
	case <-ctx.Done():
		return fmt.Errorf("audit flush timed out waiting for drain: %w", ctx.Err())
	}
}

// Stop flushes pending entries and shuts down the drain goroutine. It is
// idempotent — repeated calls are safe and each reports the current cumulative
// lost-entry count (see Flush), not just the first call.
//
// If ctx is cancelled before the flush completes, Stop returns the context
// error but still signals the drain goroutine to exit. The goroutine will
// continue draining the queue in the background on a best-effort basis.
func (m *Manager) Stop(ctx context.Context) error {
	var ctxErr error

	m.stopOnce.Do(func() {
		// Attempt a pre-stop flush so callers get synchronous durability. Its
		// return value already folds in the lost-entry count as of that call,
		// but Stop recomputes that count fresh below — after the final drain,
		// which may itself lose entries — so only a genuine ctx-cancellation
		// error from Flush is preserved here.
		if err := m.Flush(ctx); err != nil &&
			(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			ctxErr = err
		}

		// Signal drainLoop to exit. It will drain any remaining queued entries
		// before returning.
		close(m.stop)

		// Wait for drainLoop to return so subsequent callers don't race with
		// in-flight writes. Respect ctx so Stop cannot hang indefinitely.
		select {
		case <-m.done:
		case <-ctx.Done():
			if ctxErr == nil {
				ctxErr = fmt.Errorf("audit stop timed out waiting for drain goroutine: %w", ctx.Err())
			}
		}
	})

	if ctxErr != nil {
		return ctxErr
	}
	// Runs on every call, including calls after the first: m.lostEntries is a
	// live cumulative counter, not a value captured once by stopOnce (Issue
	// #4098, AC9 — a second Stop must still report an earlier loss).
	return m.lostEntriesErr()
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

// canonicalDetails nils out an empty (len-0) Details map so its JSON
// representation is stable whether the map is nil or empty-but-non-nil — see
// the round-trip note in generateChecksum.
func canonicalDetails(details map[string]interface{}) map[string]interface{} {
	if len(details) == 0 {
		return nil
	}
	return details
}

// canonicalChanges returns a copy of changes with empty Before/After/Fields
// nilled out, for the same round-trip stability reason as canonicalDetails.
// The original is not mutated.
func canonicalChanges(changes *business.AuditChanges) *business.AuditChanges {
	if changes == nil {
		return nil
	}
	c := *changes
	if len(c.Before) == 0 {
		c.Before = nil
	}
	if len(c.After) == 0 {
		c.After = nil
	}
	if len(c.Fields) == 0 {
		c.Fields = nil
	}
	return &c
}

// generateChecksum computes an HMAC-SHA256 over every field of entry except
// Checksum itself. The HMAC key is the Manager's per-instance or
// secrets-backed key. Callers must set SequenceNumber and PreviousChecksum on
// the entry before calling generateChecksum.
//
// Issue #4098, AC1: the previous formula hashed 11 of the entry's 27
// non-Checksum fields, so the other 16 (UserType, SessionID, ResourceName,
// ErrorCode, ErrorMessage, RequestID, IPAddress, UserAgent, Method, Path,
// Details, Changes, Tags, Severity, Source, Version) could be rewritten with
// no checksum break — the chain proved ordering and identity but not what an
// entry said. This widening is a hard break, not a migration (AC2): entries
// checksummed under the old formula are reported as a mismatch by
// VerifyChain, and are not re-signed.
//
// Details and Changes are structured values; they are included via
// json.Marshal, which sorts map keys, so the hash input is deterministic
// regardless of Go map iteration order.
//
// Field framing: each value is written to the MAC as
// <decimal byte length> ":" <value> (netstring framing), never as values
// concatenated around a delimiter. That encoding is injective — the length
// prefix is read up to the first ":", and exactly that many bytes follow, so
// no byte string can be parsed as two different field assignments. A bare
// delimiter is not injective: strings.Join([]string{"Mozilla|/etc/passwd",
// "/x"}, "|") and strings.Join([]string{"Mozilla", "/etc/passwd|/x"}, "|")
// are byte-identical, so an attacker who plants a "|" in an
// attacker-influenced field (UserAgent, Path, ResourceName, ErrorMessage —
// logging.SanitizeLogValue strips only control characters, so "|" survives)
// could later shift the boundary between two adjacent string fields and the
// recomputed HMAC would still match. That is precisely the adversary ADR-004
// claims to detect, so the framing is part of the tamper-evidence property,
// not a formatting detail.
//
// Tags is a slice, so it is written as a length-prefixed element count
// followed by each tag as its own framed field. Joining tags with a separator
// would reintroduce the same ambiguity one level down ([]string{"a,b"} and
// []string{"a", "b"} share an encoding), and the count keeps a trailing tag
// from being confused with the field that follows the slice.
func (m *Manager) generateChecksum(entry *business.AuditEntry) string {
	// Details and Changes.{Before,After,Fields} carry `json:"...,omitempty"` on
	// business.AuditEntry / business.AuditChanges. A store round-trip (the
	// entry is serialized to persist it, then deserialized by QueryEntries for
	// VerifyChain) collapses an empty-but-non-nil map/slice to nil, because
	// omitempty drops the field on encode whichever it was, and decode leaves
	// the zero value when the key is absent. Left uncanonicalized, that
	// produces a different json.Marshal byte sequence — and therefore a
	// different checksum — for the identical entry before and after storage,
	// which VerifyChain would report as tampering that never happened.
	// Canonicalizing empty to nil here matches what every round-trip already
	// converges to, so the hash is stable across it.
	detailsJSON, _ := json.Marshal(canonicalDetails(entry.Details))
	changesJSON, _ := json.Marshal(canonicalChanges(entry.Changes))

	mac := hmac.New(sha256.New, m.hmacKey)

	// field writes v framed as <decimal byte length> ":" <v>. hash.Hash never
	// returns an error from Write, per its documented contract.
	field := func(v string) {
		_, _ = mac.Write([]byte(strconv.Itoa(len(v))))
		_, _ = mac.Write([]byte{':'})
		_, _ = mac.Write([]byte(v))
	}

	field(entry.ID)
	field(entry.TenantID)
	field(strconv.FormatInt(entry.Timestamp.Unix(), 10))
	field(string(entry.EventType))
	field(entry.Action)
	field(entry.UserID)
	field(string(entry.UserType))
	field(entry.SessionID)
	field(entry.ResourceType)
	field(entry.ResourceID)
	field(entry.ResourceName)
	field(string(entry.Result))
	field(entry.ErrorCode)
	field(entry.ErrorMessage)
	field(entry.RequestID)
	field(entry.IPAddress)
	field(entry.UserAgent)
	field(entry.Method)
	field(entry.Path)
	field(string(detailsJSON))
	field(string(changesJSON))
	field(strconv.Itoa(len(entry.Tags)))
	for _, tag := range entry.Tags {
		field(tag)
	}
	field(string(entry.Severity))
	field(entry.Source)
	field(entry.Version)
	field(strconv.FormatUint(entry.SequenceNumber, 10))
	field(entry.PreviousChecksum)

	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyChain walks entries (which must be sorted ascending by SequenceNumber)
// and reports every integrity violation as a ChainBreak. It is a pure in-memory
// operation — callers are responsible for providing a complete, sorted slice.
//
// The following violations are detected:
//   - Missing sequence number (SequenceNumber == 0 — see below)
//   - Checksum mismatch (tampering of an entry's fields)
//   - PreviousChecksum mismatch (entry does not link to the prior entry)
//   - Sequence gap (a sequence number is missing between two consecutive entries)
//
// Entries with SequenceNumber == 0 are rejected, not skipped (Issue #4098,
// AC3): an entry with no assigned sequence number is unverifiable and is
// reported as a ChainBreak naming that reason. This was previously a silent
// skip on the theory that such entries were pre-chain legacy data; AC2's hard
// checksum break removes that legacy class, so there is nothing left to
// protect by special-casing sequence zero.
//
// Adversary bound (ADR-004, Issue #3727): these checks detect an actor who
// modifies, deletes, or reorders entries WITHOUT recomputing SequenceNumber,
// PreviousChecksum, and Checksum in order using m.hmacKey — i.e. an actor who
// does not hold the key. An actor who does hold the key (see WithSecretsStore)
// can recompute a fully consistent chain over rewritten content, and this
// function will report zero breaks for it. That is not a defect in this
// function; it is the documented bound of a keyed hash chain.
func (m *Manager) VerifyChain(entries []*business.AuditEntry) []ChainBreak {
	// Sort a working copy by SequenceNumber ascending so callers don't have to.
	sorted := make([]*business.AuditEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].SequenceNumber < sorted[j].SequenceNumber
	})

	var breaks []ChainBreak
	var prev *business.AuditEntry

	for _, e := range sorted {
		if e.SequenceNumber == 0 {
			breaks = append(breaks, ChainBreak{
				EntryID:        e.ID,
				SequenceNumber: e.SequenceNumber,
				Reason:         "sequence number missing: entry has no assigned SequenceNumber and cannot be chain-verified",
			})
		}

		// Detect sequence gap.
		if prev != nil && e.SequenceNumber != prev.SequenceNumber+1 {
			breaks = append(breaks, ChainBreak{
				EntryID:        e.ID,
				SequenceNumber: e.SequenceNumber,
				Reason: fmt.Sprintf("sequence gap: expected %d, got %d",
					prev.SequenceNumber+1, e.SequenceNumber),
			})
		}

		// Detect PreviousChecksum mismatch.
		if prev != nil && e.PreviousChecksum != prev.Checksum {
			breaks = append(breaks, ChainBreak{
				EntryID:        e.ID,
				SequenceNumber: e.SequenceNumber,
				Reason: fmt.Sprintf("previous_checksum mismatch: expected %q, got %q",
					prev.Checksum, e.PreviousChecksum),
			})
		}

		// Detect checksum tampering by recomputing.
		expected := m.generateChecksum(e)
		if e.Checksum != expected {
			breaks = append(breaks, ChainBreak{
				EntryID:        e.ID,
				SequenceNumber: e.SequenceNumber,
				Reason:         "checksum mismatch: entry fields have been tampered with",
			})
		}

		prev = e
	}
	return breaks
}

// VerifyIntegrity verifies the HMAC-SHA256 checksum of a single audit entry.
func (m *Manager) VerifyIntegrity(entry *business.AuditEntry) bool {
	return entry.Checksum == m.generateChecksum(entry)
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
	entry.ResourceName = logging.SanitizeLogValue(b.resourceName)
	entry.Result = b.result
	entry.ErrorCode = b.errorCode
	entry.RequestID = b.requestID
	entry.IPAddress = logging.SanitizeLogValue(b.ipAddress)
	entry.UserAgent = logging.SanitizeLogValue(b.userAgent)
	entry.Method = logging.SanitizeLogValue(b.method)
	entry.Path = logging.SanitizeLogValue(b.path)
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

// authOutcomeSeverity maps an AuditResult to the calibrated severity for auth/authz events.
// Success is Low (routine operation); anything else is High (failure, denial, or error).
// Call sites that want Critical (e.g. compromised-device or session-hijack indicators) must
// override with .Severity(business.AuditSeverityCritical) after the constructor.
func authOutcomeSeverity(result business.AuditResult) business.AuditSeverity {
	if result == business.AuditResultSuccess {
		return business.AuditSeverityLow
	}
	return business.AuditSeverityHigh
}

// AuthenticationEvent creates an authentication event builder.
// Severity is outcome-aware: success → Low, failure/denied/error → High.
// Call sites for compromise-indicator-grade failures (revoked device, session hijack, invalid PoP)
// must add .Severity(business.AuditSeverityCritical) to override.
func AuthenticationEvent(tenantID, userID, action string, result business.AuditResult) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventAuthentication).
		Action(action).
		User(userID, business.AuditUserTypeHuman).
		Resource("session", userID, "").
		Result(result).
		Severity(authOutcomeSeverity(result))
}

// AuthorizationEvent creates an authorization event builder.
// Severity is outcome-aware: success → Low, failure/denied/error → High.
// Call sites for sensitive authorization management actions (permission grants, JIT approvals)
// must add .Severity(business.AuditSeverityHigh) to override, since those represent
// security-relevant operations regardless of outcome.
func AuthorizationEvent(tenantID, userID, resourceType, resourceID, action string, result business.AuditResult) *AuditEventBuilder {
	return NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventAuthorization).
		Action(action).
		User(userID, business.AuditUserTypeHuman).
		Resource(resourceType, resourceID, "").
		Result(result).
		Severity(authOutcomeSeverity(result))
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
