// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// OwnerImmutableSubject reports whether subject is an EID whose authority is
// directory or m365. For these, the owning tenant of an existing subject never
// changes on ingest: eg_entity_index.subject is a global key and the writing
// peer's tenant overwrites the payload's, so without this rule any tenant able
// to name the subject could take it over. Host and cluster subjects are
// unaffected (a steward move legitimately changes a host's tenant).
func OwnerImmutableSubject(subject string) bool {
	i := strings.IndexByte(subject, ':')
	if i < 0 {
		return false
	}
	switch subject[:i] {
	case "directory", "m365":
		return true
	}
	return false
}

// OwnerImmutableKind reports whether an observation of this kind can change an
// entity's owning tenant, and so is subject to the owner-immutability rule.
func OwnerImmutableKind(k types.ObservationKind) bool {
	return k == types.ObservationKindState || k == types.ObservationKindPresence
}

// OwnerConflict describes a rejected write to a directory or m365 subject whose
// existing owning tenant differs from the writer's.
type OwnerConflict struct {
	Subject         string
	ExistingTenant  string
	AttemptedTenant string
	Source          string
}

// OwnerConflictObserver receives each OwnerConflict. It carries both tenant ids,
// so it must only ever feed the root admin audit stream, never a tenant-visible
// surface.
type OwnerConflictObserver func(ctx context.Context, c OwnerConflict)

// OwnerConflictSink holds a provider's observer behind a lock so the controller
// can wire it after the provider is constructed. The zero value is ready to use.
type OwnerConflictSink struct {
	mu  sync.RWMutex
	obs OwnerConflictObserver
}

// Set installs (or clears, with nil) the observer.
func (s *OwnerConflictSink) Set(o OwnerConflictObserver) {
	s.mu.Lock()
	s.obs = o
	s.mu.Unlock()
}

// Report forwards c to the observer, if one is installed.
func (s *OwnerConflictSink) Report(ctx context.Context, c OwnerConflict) {
	s.mu.RLock()
	o := s.obs
	s.mu.RUnlock()
	if o != nil {
		o(ctx, c)
	}
}

// ReportOwnerConflict records a rejected cross-tenant write: a security log line
// that names both tenants, then the sink's observer. The log line carries tenant
// ids, so it belongs to the root admin / operator log stream only.
func ReportOwnerConflict(ctx context.Context, sink *OwnerConflictSink, c OwnerConflict) {
	slog.Warn("SECURITY: entity graph write rejected, subject owned by a different tenant",
		"event", "entitygraph_owner_conflict",
		"subject", logging.SanitizeLogValue(c.Subject),
		"existing_tenant", logging.SanitizeLogValue(c.ExistingTenant),
		"attempted_tenant", logging.SanitizeLogValue(c.AttemptedTenant),
		"source", logging.SanitizeLogValue(c.Source),
	)
	sink.Report(ctx, c)
}
