// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// defaultSigningMigrationInterval is how often a node re-runs the migration
// steps, so an election made after startup (the cursor named by an operator on
// another node) is promoted and the local keys removed without a restart.
const defaultSigningMigrationInterval = time.Minute

// SigningMigrationService moves a cluster-mode node from its own signing
// certificate and key to the shared signing identity (Issue #4796). One pass:
// import every valid local signing certificate into the migration namespace,
// promote the serial the shared cursor names into the shared namespace, then —
// only in Shared mode and only for keys read back equal — delete the local key
// files. Every step is audit-logged.
type SigningMigrationService struct {
	certManager *cert.Manager
	logger      logging.Logger
	interval    time.Duration

	mu           sync.RWMutex
	auditManager *audit.Manager

	runMu  sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewSigningMigrationService creates the service and routes the Manager's
// migration events to the audit log (once SetAuditManager is called).
func NewSigningMigrationService(certManager *cert.Manager, logger logging.Logger) *SigningMigrationService {
	s := &SigningMigrationService{certManager: certManager, logger: logger, interval: defaultSigningMigrationInterval}
	if certManager != nil {
		certManager.SetSigningMigrationAuditSink(s.recordEvent)
	}
	return s
}

// SetAuditManager wires the audit manager that records migration events. Nil-safe.
func (s *SigningMigrationService) SetAuditManager(m *audit.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditManager = m
}

// SetInterval overrides how often Start re-runs the steps. Call before Start.
func (s *SigningMigrationService) SetInterval(d time.Duration) {
	if d > 0 {
		s.interval = d
	}
}

// Run performs one import → promote → verified-removal pass. Nodes without a
// shared signing key store (single-node controllers) have nothing to migrate and
// Run returns nil.
func (s *SigningMigrationService) Run(ctx context.Context) error {
	if s.certManager == nil {
		return nil
	}
	if _, err := s.certManager.ImportLocalSigningCertificates(ctx); err != nil {
		if errors.Is(err, cert.ErrNoSigningKeyStore) {
			return nil
		}
		return fmt.Errorf("import local signing certificates: %w", err)
	}
	if _, _, err := s.certManager.PromoteElectedSigner(ctx); err != nil {
		return fmt.Errorf("promote elected signing certificate: %w", err)
	}
	if _, err := s.certManager.RemoveVerifiedLocalSigningKeys(ctx); err != nil {
		return fmt.Errorf("remove verified local signing keys: %w", err)
	}
	return nil
}

// Start runs the steps on an interval until ctx is cancelled or Stop is called.
// A second Start while running is a no-op.
func (s *SigningMigrationService) Start(ctx context.Context) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.cancel != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	interval := s.interval
	// The goroutine closes its own copy of the channel: Stop clears s.done under
	// runMu, so the field must not be read from here.
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			}
			if err := s.Run(runCtx); err != nil && runCtx.Err() == nil {
				s.logger.Error("signing identity migration pass failed",
					"error", logging.SanitizeLogValue(err.Error()))
			}
		}
	}()
}

// Stop ends the loop and waits for it to exit. Idempotent.
func (s *SigningMigrationService) Stop() {
	s.runMu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.runMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// recordEvent writes one migration event to the audit log. Serials, fingerprints
// and reasons only; never PEM or key bytes. No-op without an audit manager.
func (s *SigningMigrationService) recordEvent(ctx context.Context, ev cert.SigningMigrationEvent) {
	s.mu.RLock()
	am := s.auditManager
	s.mu.RUnlock()
	if am == nil {
		return
	}
	result := business.AuditResultSuccess
	severity := business.AuditSeverityHigh
	if ev.Action == cert.SigningMigrationRefused {
		result = business.AuditResultFailure
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSecurityEvent).
		Action(ev.Action).
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("signing_certificate", logging.SanitizeLogValue(ev.Serial), "").
		Result(result).
		Severity(severity).
		Details(map[string]interface{}{
			"serial":      logging.SanitizeLogValue(ev.Serial),
			"fingerprint": logging.SanitizeLogValue(ev.Fingerprint),
			"reason":      logging.SanitizeLogValue(ev.Reason),
		})
	if err := am.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to record signing migration audit event",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
