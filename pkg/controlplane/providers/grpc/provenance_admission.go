// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/cfgis/cfgms/features/controller/registration"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// HostAttrsHeader is the gRPC metadata key on the ControlChannel call that
	// carries the steward's host attributes: base64(JSON map[string]string).
	HostAttrsHeader = "x-cfgms-host-attrs"

	// MaxHostAttrsHeaderBytes is the hard cap on the encoded header value. An
	// oversized header is treated as if no attributes were sent.
	MaxHostAttrsHeaderBytes = 4096

	// maxHostAttrKeys and maxHostAttrValueLen bound what the controller keeps
	// from a caller-supplied map.
	maxHostAttrKeys     = 16
	maxHostAttrValueLen = 1024

	// Audit actions recorded by the store-backed provenance checker.
	auditActionProvenanceDivergence = "steward_provenance_divergence"
	auditActionProvenanceBaseline   = "steward_provenance_baseline_recorded"

	// provenanceAuditInterval is the minimum spacing between divergence audit
	// events for one steward ID, so a looping copy cannot flood the audit log.
	provenanceAuditInterval = time.Minute

	// provenanceFallbackTenant owns audit events for a steward whose record has
	// no tenant; the audit store requires a tenant on every entry.
	provenanceFallbackTenant = "system"
)

// ProvenanceDecision is the outcome of comparing a connecting host against the
// approved record (ADR-034 §2).
type ProvenanceDecision string

const (
	// ProvenanceUnknown: no baseline is recorded, no attributes were sent, or the
	// comparison could not be made. The connection is admitted as before.
	ProvenanceUnknown ProvenanceDecision = "unknown"
	// ProvenanceApprovedMachine: the host matches the baseline at or above
	// registration.ProvenanceMatchThreshold.
	ProvenanceApprovedMachine ProvenanceDecision = "approved_machine"
	// ProvenanceCopy: the host scores below the threshold, so the connection is
	// judged a copy of the approved machine.
	ProvenanceCopy ProvenanceDecision = "copy"
)

// ProvenanceAssessment is the result of one admission-time provenance check.
// DivergentKeys names the attributes that differed; values are never included.
type ProvenanceAssessment struct {
	Decision      ProvenanceDecision
	Score         float64
	MatchedFields int
	TotalFields   int
	DivergentKeys []string
}

// ProvenanceChecker compares a connecting steward's host attributes against its
// approved record. It is demote-only (ADR-011 §7): it runs after the revocation
// and approval gates and can only classify a connection, never admit one those
// gates refused. Implementations must not fail the admission: on any internal
// error they return ProvenanceUnknown.
type ProvenanceChecker interface {
	CheckProvenance(ctx context.Context, stewardID string, attrs map[string]string) ProvenanceAssessment
}

// WithProvenanceChecker injects the provenance checker consulted by
// ControlChannel admission after the revocation and approval gates. Nil (the
// default) disables the check.
func WithProvenanceChecker(checker ProvenanceChecker) option {
	return func(p *Provider) {
		p.provenanceChecker = checker
	}
}

// WithHostAttributes (client mode) supplies the host attributes sent in the
// HostAttrsHeader on every ControlChannel dial. The supplier is called per
// dial so a reconnect reports current values. Nil sends no header.
func WithHostAttributes(supplier func() map[string]string) option {
	return func(p *Provider) {
		p.hostAttributes = supplier
	}
}

// encodeHostAttrs returns the header value for attrs, or "" when there is
// nothing to send or the encoding would exceed MaxHostAttrsHeaderBytes.
func encodeHostAttrs(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return ""
	}
	enc := base64.StdEncoding.EncodeToString(raw)
	if len(enc) > MaxHostAttrsHeaderBytes {
		return ""
	}
	return enc
}

// hostAttrsFromContext reads and validates the host-attributes header from the
// incoming call metadata. A missing, oversized, undecodable or malformed header
// yields nil ("no attributes"); it never fails the call.
func hostAttrsFromContext(ctx context.Context) map[string]string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	vals := md.Get(HostAttrsHeader)
	if len(vals) != 1 || vals[0] == "" || len(vals[0]) > MaxHostAttrsHeaderBytes {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(vals[0])
	if err != nil {
		return nil
	}
	var attrs map[string]string
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return nil
	}
	return sanitizeHostAttrs(attrs)
}

// sanitizeHostAttrs drops DNA keys (never a provenance input) and bounds the
// key count and value length of a caller-supplied map.
func sanitizeHostAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxHostAttrKeys {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if registration.DNAFieldKeys[k] || k == "" || len(v) > maxHostAttrValueLen {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// assessProvenance runs the configured checker, or returns ProvenanceUnknown
// when none is configured.
func (p *Provider) assessProvenance(ctx context.Context, stewardID string) ProvenanceAssessment {
	if p.provenanceChecker == nil {
		return ProvenanceAssessment{Decision: ProvenanceUnknown}
	}
	attrs := hostAttrsFromContext(ctx)
	if attrs == nil {
		return ProvenanceAssessment{Decision: ProvenanceUnknown}
	}
	a := p.provenanceChecker.CheckProvenance(ctx, stewardID, attrs)
	if a.Decision == "" {
		a.Decision = ProvenanceUnknown
	}
	return a
}

// stewardStoreProvenanceChecker is the production ProvenanceChecker: it reads
// the baseline from the steward store, scores the incoming attributes with the
// registration matcher, records the baseline on first use and audits a copy.
type stewardStoreProvenanceChecker struct {
	store  business.StewardStore
	audit  *audit.Manager
	logger logging.Logger
	now    func() time.Time

	matcher registration.ProvenanceMatcher

	mu       sync.Mutex
	lastSeen map[string]time.Time
}

// NewStewardStoreProvenanceChecker builds the production provenance checker.
// auditManager may be nil (events are then only logged).
//
// A store error never refuses or blocks admission: the check fails toward the
// pre-provenance behaviour (ProvenanceUnknown, logged at error) so a store
// outage cannot lock the fleet out. The revocation and approval gates, which
// run first and fail closed, are unaffected.
func NewStewardStoreProvenanceChecker(store business.StewardStore, auditManager *audit.Manager, logger logging.Logger) ProvenanceChecker {
	return &stewardStoreProvenanceChecker{
		store:    store,
		audit:    auditManager,
		logger:   logger,
		now:      time.Now,
		lastSeen: make(map[string]time.Time),
	}
}

func (c *stewardStoreProvenanceChecker) CheckProvenance(ctx context.Context, stewardID string, attrs map[string]string) ProvenanceAssessment {
	unknown := ProvenanceAssessment{Decision: ProvenanceUnknown}
	if c.store == nil || len(attrs) == 0 {
		return unknown
	}
	record, err := c.store.GetSteward(ctx, stewardID)
	if err != nil {
		if !errors.Is(err, business.ErrStewardNotFound) {
			c.logger.Error("provenance check: steward lookup failed, admitting as unknown",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return unknown
	}

	if record.LastProvenanceJSON == "" {
		c.recordBaseline(ctx, record, attrs)
		return unknown
	}

	result := c.matcher.FuzzyMatch(record.LastProvenanceJSON, attrs)
	if result.TotalFields == 0 {
		return unknown
	}
	a := ProvenanceAssessment{
		Score:         result.Score,
		MatchedFields: result.MatchedFields,
		TotalFields:   result.TotalFields,
	}
	if result.Score >= registration.ProvenanceMatchThreshold {
		a.Decision = ProvenanceApprovedMachine
		return a
	}
	a.Decision = ProvenanceCopy
	a.DivergentKeys = divergentKeys(record.LastProvenanceJSON, attrs)
	c.auditDivergence(ctx, record, stewardID, a)
	return a
}

// recordBaseline stores attrs as the steward's baseline (trust on first use).
func (c *stewardStoreProvenanceChecker) recordBaseline(ctx context.Context, record *business.StewardRecord, attrs map[string]string) {
	raw, err := json.Marshal(attrs)
	if err != nil {
		return
	}
	if err := c.store.SetStewardProvenance(ctx, record.ID, string(raw)); err != nil {
		c.logger.Error("provenance baseline write failed",
			"steward_id", logging.SanitizeLogValue(record.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	c.record(ctx, record, audit.NewEventBuilder().
		Type(business.AuditEventSystemEvent).
		Action(auditActionProvenanceBaseline).
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Detail("reason", "first_admission").
		Detail("attribute_keys", keys))
}

func (c *stewardStoreProvenanceChecker) auditDivergence(ctx context.Context, record *business.StewardRecord, stewardID string, a ProvenanceAssessment) {
	c.logger.Warn("steward host provenance diverges from approved record",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"score", a.Score)
	if !c.allow(stewardID) {
		return
	}
	c.record(ctx, record, audit.NewEventBuilder().
		Type(business.AuditEventSecurityEvent).
		Action(auditActionProvenanceDivergence).
		Result(business.AuditResultFailure).
		Severity(business.AuditSeverityHigh).
		Detail("decision", string(a.Decision)).
		Detail("score", a.Score).
		Detail("matched_fields", a.MatchedFields).
		Detail("total_fields", a.TotalFields).
		Detail("divergent_keys", a.DivergentKeys))
}

func (c *stewardStoreProvenanceChecker) record(ctx context.Context, record *business.StewardRecord, b *audit.AuditEventBuilder) {
	if c.audit == nil {
		return
	}
	tenantID := record.TenantID
	if tenantID == "" {
		tenantID = provenanceFallbackTenant
	}
	b.Tenant(tenantID).
		User(record.ID, business.AuditUserTypeSystem).
		Resource("steward", record.ID, "").
		Detail("steward_id", record.ID)
	if err := c.audit.RecordEvent(ctx, b); err != nil {
		c.logger.Warn("Failed to record steward provenance audit event",
			"steward_id", logging.SanitizeLogValue(record.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// allow reports whether a divergence event for stewardID may be written now.
func (c *stewardStoreProvenanceChecker) allow(stewardID string) bool {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, ok := c.lastSeen[stewardID]; ok && now.Sub(last) < provenanceAuditInterval {
		return false
	}
	for id, t := range c.lastSeen {
		if now.Sub(t) >= provenanceAuditInterval {
			delete(c.lastSeen, id)
		}
	}
	c.lastSeen[stewardID] = now
	return true
}

// divergentKeys names the baseline attributes (DNA keys excluded) whose
// incoming value differs or is missing. Values are never returned.
func divergentKeys(storedJSON string, incoming map[string]string) []string {
	var stored map[string]string
	if err := json.Unmarshal([]byte(storedJSON), &stored); err != nil {
		return nil
	}
	var keys []string
	for k, sv := range stored {
		if registration.DNAFieldKeys[k] {
			continue
		}
		if iv, ok := incoming[k]; !ok || iv != sv {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
