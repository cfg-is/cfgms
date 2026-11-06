// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Reserved QueuedExecution.Metadata keys. They carry the evaluated pin and the
// persisted run guard through the durable queue store. Only QueueExecution writes
// them, from values set by WithPin and WithGuard; raw Metadata that already holds
// any pin_* or guard_* key is rejected.
const (
	MetaPinOwnerTenant  = "pin_owner_tenant"
	MetaPinVersion      = "pin_version"
	MetaPinApprovalHash = "pin_approval_hash"
	MetaGuardRunID      = "guard_run_id"
	MetaGuardGrantID    = "guard_grant_id"

	// maxQueueMetadataEntries bounds caller Metadata before it is copied.
	maxQueueMetadataEntries = 1024

	reservedPinPrefix   = "pin_"
	reservedGuardPrefix = "guard_"
)

var (
	// ErrReservedMetadataKey reports caller-supplied Metadata that holds a
	// reserved pin_* or guard_* key.
	ErrReservedMetadataKey = errors.New("metadata carries a reserved pin_ or guard_ key")
	// ErrMetadataTooLarge reports caller-supplied Metadata with more than
	// maxQueueMetadataEntries entries.
	ErrMetadataTooLarge = errors.New("metadata has too many entries")
	// ErrPinMismatch reports that a pinned execution no longer resolves to the
	// object that was evaluated.
	ErrPinMismatch = errors.New("pinned script differs from the evaluated script")
	// ErrGuardFailed reports that the run guard no longer holds; the command is cancelled.
	ErrGuardFailed = errors.New("execution guard failed")
	// ErrAPIScopeNotGrantable reports a pinned script that requires an API scope;
	// a grant must never mint an ephemeral API key.
	ErrAPIScopeNotGrantable = errors.New("pinned script requires an API scope")
)

// GuardResolver checks that the run a queued command belongs to is live and its
// grant is neither revoked nor expired. A non-nil error fails the guard.
type GuardResolver func(ctx context.Context, runID, grantID string) error

// PrivilegeScopeLookup returns the script's current RequiredAPIScope. An error
// fails closed.
type PrivilegeScopeLookup func(ctx context.Context, tenantID, scriptID string) ([]string, error)

type executionPin struct{ ownerTenant, version, approvalHash string }

type executionGuard struct{ runID, grantID string }

// WithPin pins the execution to the owner library object that was evaluated.
// QueueExecution persists it; prepare resolves exactly that owner and version
// and refuses when the recomputed approval hash differs.
func (e *QueuedExecution) WithPin(ownerTenant, version, approvalHash string) *QueuedExecution {
	e.pin = &executionPin{ownerTenant: ownerTenant, version: version, approvalHash: approvalHash}
	return e
}

// WithGuard attaches a persisted run guard reference. The queue evaluates it at
// dequeue and again before dispatch through the registered GuardResolver.
func (e *QueuedExecution) WithGuard(runID, grantID string) *QueuedExecution {
	e.guard = &executionGuard{runID: runID, grantID: grantID}
	return e
}

func hasReservedKey(m map[string]interface{}) bool {
	for k := range m {
		if strings.HasPrefix(k, reservedPinPrefix) || strings.HasPrefix(k, reservedGuardPrefix) {
			return true
		}
	}
	return false
}

// metadataWithReserved returns a copy of Metadata plus the reserved keys derived
// from the pin and guard fields. Caller-set reserved keys are rejected.
func (e *QueuedExecution) metadataWithReserved() (map[string]interface{}, error) {
	if hasReservedKey(e.Metadata) {
		return nil, ErrReservedMetadataKey
	}
	if e.pin == nil && e.guard == nil {
		return e.Metadata, nil
	}
	if len(e.Metadata) > maxQueueMetadataEntries {
		return nil, fmt.Errorf("%w: limit is %d", ErrMetadataTooLarge, maxQueueMetadataEntries)
	}
	m := make(map[string]interface{}, len(e.Metadata))
	for k, v := range e.Metadata {
		m[k] = v
	}
	if err := e.pin.putReserved(m); err != nil {
		return nil, err
	}
	if err := e.guard.putReserved(m); err != nil {
		return nil, err
	}
	return m, nil
}

// putReserved writes the pin's reserved keys into m. A nil pin writes nothing;
// an incomplete pin is rejected.
func (p *executionPin) putReserved(m map[string]interface{}) error {
	if p == nil {
		return nil
	}
	if p.ownerTenant == "" || p.version == "" || p.approvalHash == "" {
		return fmt.Errorf("%w: pin needs owner tenant, version and approval hash", ErrPinMismatch)
	}
	m[MetaPinOwnerTenant] = p.ownerTenant
	m[MetaPinVersion] = p.version
	m[MetaPinApprovalHash] = p.approvalHash
	return nil
}

// putReserved writes the guard's reserved keys into m. A nil guard writes
// nothing; an incomplete guard is rejected.
func (g *executionGuard) putReserved(m map[string]interface{}) error {
	if g == nil {
		return nil
	}
	if g.runID == "" || g.grantID == "" {
		return fmt.Errorf("%w: guard needs run id and grant id", ErrGuardFailed)
	}
	m[MetaGuardRunID] = g.runID
	m[MetaGuardGrantID] = g.grantID
	return nil
}

// reservedFromMetadata rebuilds the pin and guard from a stored entry. Any
// reserved key present makes the matching struct present, even if incomplete,
// so a damaged entry still fails closed instead of running unpinned.
func reservedFromMetadata(m map[string]interface{}) (*executionPin, *executionGuard) {
	str := func(k string) string { s, _ := m[k].(string); return s }
	var pin *executionPin
	var guard *executionGuard
	for k := range m {
		switch {
		case strings.HasPrefix(k, reservedPinPrefix):
			pin = &executionPin{str(MetaPinOwnerTenant), str(MetaPinVersion), str(MetaPinApprovalHash)}
		case strings.HasPrefix(k, reservedGuardPrefix):
			guard = &executionGuard{str(MetaGuardRunID), str(MetaGuardGrantID)}
		}
	}
	return pin, guard
}

// SetGuardResolver registers the resolver that evaluates guard references. A
// command that carries a guard reference while none is registered is cancelled.
func (q *ExecutionQueue) SetGuardResolver(r GuardResolver) {
	q.guardMu.Lock()
	q.guardResolver = r
	q.guardMu.Unlock()
}

// SetPrivilegeScopeLookup registers the lookup prepare uses to read a pinned
// script's current RequiredAPIScope.
func (q *ExecutionQueue) SetPrivilegeScopeLookup(l PrivilegeScopeLookup) {
	q.guardMu.Lock()
	q.scopeLookup = l
	q.guardMu.Unlock()
}

// checkGuard evaluates the guard reference, if any. It fails closed.
func (q *ExecutionQueue) checkGuard(ctx context.Context, e *QueuedExecution) error {
	if e.guard == nil {
		return nil
	}
	q.guardMu.RLock()
	resolver := q.guardResolver
	q.guardMu.RUnlock()
	if resolver == nil {
		return fmt.Errorf("%w: no guard resolver is registered", ErrGuardFailed)
	}
	if e.guard.runID == "" || e.guard.grantID == "" {
		return fmt.Errorf("%w: incomplete guard reference", ErrGuardFailed)
	}
	if err := resolver(ctx, e.guard.runID, e.guard.grantID); err != nil {
		return fmt.Errorf("%w: %s", ErrGuardFailed, err.Error())
	}
	return nil
}

// cancelGuarded cancels a command whose guard failed and records the reason in
// the durable execution tracker when one is set.
func (q *ExecutionQueue) cancelGuarded(deviceID string, e *QueuedExecution, reason error) {
	_ = q.CancelExecution(deviceID, e.ExecutionID) //nolint:errcheck // the entry may already be terminal
	if q.tracker == nil {
		return
	}
	ref := e.ScriptRef
	if ref == "" {
		ref = e.ScriptID
	}
	_ = q.tracker.Record(context.Background(), &ExecutionRecord{ //nolint:errcheck // audit side-channel
		ExecutionID: e.ExecutionID,
		DeviceID:    deviceID,
		ScriptRef:   ref,
		Shell:       string(e.Shell),
		State:       string(QueueStateCancelled),
		Stderr:      reason.Error(),
		QueuedAt:    e.QueuedAt,
		CompletedAt: time.Now(),
	})
}

// resolvePinned reads the pinned owner's exact version once and verifies it
// against the evaluated approval hash and the no-API-scope rule.
func (q *ExecutionQueue) resolvePinned(ctx context.Context, runTenant, scriptRef string, e *QueuedExecution) (*VersionedScript, error) {
	p := e.pin
	if p.ownerTenant == "" || p.version == "" || p.approvalHash == "" {
		return nil, fmt.Errorf("%w: incomplete pin", ErrPinMismatch)
	}
	resolver, ok := q.scriptRepo.(TenantScriptResolver)
	if !ok {
		return nil, fmt.Errorf("%w: library is not tenant-resolved", ErrPinMismatch)
	}
	vs, err := resolver.GetForTenant(p.ownerTenant, scriptRef, p.version)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve pinned script %q: %w", scriptRef, err)
	}
	if err := p.verify(vs); err != nil {
		return nil, err
	}
	if err := q.checkPinnedScope(ctx, tenantForExecution(runTenant, e), scriptRef, e); err != nil {
		return nil, err
	}
	return vs, nil
}

// verify checks that the resolved object is exactly the pinned version and that
// its recomputed approval hash matches the evaluated one.
func (p *executionPin) verify(vs *VersionedScript) error {
	if vs == nil || vs.Metadata == nil || vs.Metadata.Version == nil || vs.Metadata.Version.String() != p.version {
		return fmt.Errorf("%w: version differs", ErrPinMismatch)
	}
	if ScriptApprovalHash(p.ownerTenant, vs) != p.approvalHash {
		return fmt.Errorf("%w: approval hash differs", ErrPinMismatch)
	}
	return nil
}

// checkPinnedScope refuses a pinned script that requires an API scope, either in
// the queued Metadata or in the script's current RequiredAPIScope. A failed
// lookup fails closed.
func (q *ExecutionQueue) checkPinnedScope(ctx context.Context, tenant, scriptRef string, e *QueuedExecution) error {
	if !emptyScope(e.Metadata["required_api_scope"]) {
		return ErrAPIScopeNotGrantable
	}
	q.guardMu.RLock()
	lookup := q.scopeLookup
	q.guardMu.RUnlock()
	if lookup == nil {
		return nil
	}
	scope, err := lookup(ctx, tenant, scriptRef)
	if err != nil {
		return fmt.Errorf("%w: privilege lookup failed", ErrAPIScopeNotGrantable)
	}
	if len(scope) > 0 {
		return ErrAPIScopeNotGrantable
	}
	return nil
}

// tenantForExecution returns tenantID, or the run's Metadata["tenant_id"] when
// tenantID is empty.
func tenantForExecution(tenantID string, e *QueuedExecution) string {
	if tenantID != "" {
		return tenantID
	}
	t, _ := e.Metadata["tenant_id"].(string)
	return t
}

func emptyScope(v interface{}) bool {
	switch s := v.(type) {
	case nil:
		return true
	case []string:
		return len(s) == 0
	case []interface{}:
		return len(s) == 0
	case string:
		return s == ""
	}
	return false
}
