// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// defaultRetirementSweepInterval is how often the leader checks whether a
// rotation's overlap window has elapsed. A check is one cursor read.
const defaultRetirementSweepInterval = time.Minute

// RevokeResult summarises an emergency revocation of a signing certificate.
type RevokeResult struct {
	Serial           string
	StewardsNotified int
	// RetiredFromCursor is true when the serial was the cursor's rotating serial
	// and this call retired it.
	RetiredFromCursor bool
}

// SigningRetirementService withdraws superseded signing certificates from the
// fleet (Issue #4795). It does two things:
//
//   - When a rotation's overlap window has elapsed it sends every steward a
//     push_signing_cert carrying the current certificate and
//     retire_serials=[rotating serial], then marks the cursor retired.
//   - On an operator's request it records a named signing serial as revoked and
//     sends the same retirement for it immediately.
//
// Stewards that are offline for either action receive the retirement in the one
// push they already get on connect (SigningRotationService.EnsureStewardCurrent).
type SigningRetirementService struct {
	rotation *SigningRotationService
	logger   logging.Logger

	mu            sync.RWMutex
	hasLeadership func() bool
	auditManager  *audit.Manager
	interval      time.Duration

	runMu  sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewSigningRetirementService creates a retirement service that delivers through
// rotation's publisher and fleet enumeration. hasLeadership gates the sweep in a
// cluster (pass haManager.HasLeadership); nil means this node always sweeps.
func NewSigningRetirementService(rotation *SigningRotationService, hasLeadership func() bool, logger logging.Logger) *SigningRetirementService {
	return &SigningRetirementService{
		rotation:      rotation,
		logger:        logger,
		hasLeadership: hasLeadership,
		interval:      defaultRetirementSweepInterval,
	}
}

// SetAuditManager wires the audit manager that records sweep retirements.
func (s *SigningRetirementService) SetAuditManager(m *audit.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditManager = m
}

// SetSweepInterval overrides how often Start checks the cursor. Call before Start.
func (s *SigningRetirementService) SetSweepInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d > 0 {
		s.interval = d
	}
}

// Start runs the sweep on an interval until ctx is cancelled or Stop is called.
// A second Start while running is a no-op.
func (s *SigningRetirementService) Start(ctx context.Context) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.cancel != nil {
		return
	}
	s.mu.RLock()
	interval := s.interval
	s.mu.RUnlock()

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := s.Sweep(runCtx); err != nil && runCtx.Err() == nil {
				s.logger.Error("signing retirement sweep failed",
					"error", logging.SanitizeLogValue(err.Error()))
			}
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Stop ends the sweep loop and waits for it to exit. Idempotent.
func (s *SigningRetirementService) Stop() {
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

// Sweep retires the rotating signing certificate when its overlap window has
// elapsed. It returns the number of stewards notified; zero with a nil error
// means there was nothing to do (not the leader, legacy mode, no rotation, window
// still open, already retired).
func (s *SigningRetirementService) Sweep(ctx context.Context) (int, error) {
	s.mu.RLock()
	hasLeadership := s.hasLeadership
	s.mu.RUnlock()
	// Only the node holding lease-backed authority sweeps: the fan-out is
	// side-effecting and every node would otherwise repeat it.
	if hasLeadership != nil && !hasLeadership() {
		return 0, nil
	}

	certManager := s.rotation.certManager
	mode, err := certManager.SigningIdentityMode(ctx)
	if err != nil {
		return 0, fmt.Errorf("signing retirement: resolve signing identity mode: %w", err)
	}
	// LegacyLocal: the current local key is not trusted by every steward, so a
	// retirement would strand some. Unprovisioned: there is nothing to retire.
	if mode == cert.SigningIdentityLegacyLocal || mode == cert.SigningIdentityUnprovisioned {
		return 0, nil
	}

	cursor, err := certManager.GetSigningCursorState()
	if err != nil {
		return 0, fmt.Errorf("signing retirement: load cursor: %w", err)
	}
	if cursor == nil || cursor.RotatingSerial == "" || cursor.RetiredAt != nil {
		return 0, nil
	}
	if !rotatingWindowClosed(cursor, time.Now()) {
		return 0, nil
	}
	rotating := cursor.RotatingSerial

	notified, err := s.fanOutRetire(ctx, []string{rotating})
	if err != nil {
		return 0, err
	}
	retired, err := certManager.RetireRotatingSigningCertificate(rotating)
	if err != nil {
		return notified, err
	}
	if retired {
		s.logger.Info("signing certificate retired at overlap end",
			"serial", logging.SanitizeLogValue(rotating),
			"stewards_notified", notified)
		s.recordSweepAudit(ctx, rotating, notified)
	}
	return notified, nil
}

// Revoke withdraws serial as a signing certificate immediately: it is recorded in
// the revocation store, retired from the cursor when it is the rotating serial,
// and a retirement is sent to every steward. The current signing certificate is
// refused (cert.ErrRevokeCurrentSigningCert) — rotate first. Root scope is
// required, matching Rotate.
func (s *SigningRetirementService) Revoke(ctx context.Context, operatorSerial, serial, reason string) (*RevokeResult, error) {
	scope, _ := ctx.Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if !scope.IsRoot() {
		return nil, errors.New("signing revoke: unscoped (root) caller required")
	}

	certManager := s.rotation.certManager
	before, err := certManager.GetSigningCursorState()
	if err != nil {
		return nil, fmt.Errorf("signing revoke: load cursor: %w", err)
	}
	wasRotating := before != nil && before.RotatingSerial == serial && before.RetiredAt == nil

	if err := certManager.RevokeSigningCertificate(serial, reason); err != nil {
		return nil, err
	}

	notified, fanErr := s.fanOutRetire(ctx, []string{serial})
	if fanErr != nil {
		// The revocation is recorded and stewards pick it up on connect; the
		// operator still needs to know the immediate fan-out did not happen.
		s.logger.Error("signing revoke: fan-out failed; stewards will receive the retirement on connect",
			"serial", logging.SanitizeLogValue(serial),
			"error", logging.SanitizeLogValue(fanErr.Error()))
	}

	s.logger.Info("signing certificate revoked",
		"operator_serial", logging.SanitizeLogValue(operatorSerial),
		"serial", logging.SanitizeLogValue(serial),
		"stewards_notified", notified)

	return &RevokeResult{Serial: serial, StewardsNotified: notified, RetiredFromCursor: wasRotating}, nil
}

// fanOutRetire sends every steward in the fleet a push_signing_cert carrying the
// current certificate and retire_serials. It is the delivery shared by Sweep and
// Revoke. Per-steward failures are logged and do not abort the fan-out; a steward
// that missed it receives the same retirement on connect. The fan-out is
// fleet-wide and tenant-independent for the reason Rotate documents.
func (s *SigningRetirementService) fanOutRetire(ctx context.Context, retire []string) (int, error) {
	rot := s.rotation
	rot.mu.RLock()
	publisher := rot.publisher
	controllerSvc := rot.controllerService
	rot.mu.RUnlock()
	if publisher == nil || controllerSvc == nil {
		return 0, fmt.Errorf("signing retirement: publisher or controller service not initialized")
	}

	push, err := rot.buildPush(ctx, retire)
	if err != nil {
		return 0, err
	}

	fleetCtx := ctxkeys.WithSystem(ctx)
	notified := 0
	for _, steward := range controllerSvc.ListFleetStewards(fleetCtx) {
		// Signed by the current certificate: a steward that is connected has taken
		// every push since the rotation, so it trusts it. One that is not gets the
		// retirement on connect, signed for what it trusts.
		if _, pubErr := publisher.PublishCommand(ctx, steward.ID, types.CommandPushSigningCert, push.params); pubErr != nil {
			s.logger.Error("failed to push signing cert retirement to steward",
				"steward_id", logging.SanitizeLogValue(steward.ID),
				"error", logging.SanitizeLogValue(pubErr.Error()))
			continue
		}
		notified++
	}
	return notified, nil
}

// recordSweepAudit records a retirement performed by the sweep. Only serials and
// counts are recorded; no PEM. No-op when no audit manager is wired.
func (s *SigningRetirementService) recordSweepAudit(ctx context.Context, serial string, notified int) {
	s.mu.RLock()
	am := s.auditManager
	s.mu.RUnlock()
	if am == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSecurityEvent).
		Action("signing_certificate_retired").
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("signing_certificate", logging.SanitizeLogValue(serial), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{
			"serial":            logging.SanitizeLogValue(serial),
			"trigger":           "overlap_elapsed",
			"stewards_notified": notified,
		})
	if err := am.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to record signing retirement audit event",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// NewSigningResolver returns the resolver a signature.DynamicSigner uses to sign
// controller commands and configs with the current signing certificate. It
// refuses to resolve a revoked serial, and a revocation check that cannot be
// answered also refuses: a revoked key must never sign anything (Issue #4795).
// The single delivery that retires a revoked serial is signed through
// SigningRotationService.EnsureStewardCurrent, not through this resolver.
func NewSigningResolver(cm *cert.Manager) signature.CurrentSignerResolver {
	return func() (string, func() (signature.SigningKeyExport, error), error) {
		current, err := cm.GetCurrentCertForPurpose(cert.PurposeSigning)
		if err != nil {
			return "", nil, err
		}
		serial := current.SerialNumber
		revoked, err := cm.IsRevoked(serial)
		if err != nil {
			return "", nil, fmt.Errorf("check revocation of signing certificate: %w", err)
		}
		if revoked {
			return "", nil, fmt.Errorf("current signing certificate %s is revoked", logging.SanitizeLogValue(serial))
		}
		return serial, func() (signature.SigningKeyExport, error) {
			certPEM, keyPEM, exportErr := cm.ExportCertificate(serial, true, false)
			if exportErr != nil {
				return signature.SigningKeyExport{}, exportErr
			}
			return signature.SigningKeyExport{CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}, nil
		}, nil
	}
}
