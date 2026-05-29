// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// RotationResult summarises the outcome of a signing certificate rotation.
type RotationResult struct {
	OldSerial         string
	NewSerial         string
	OverlapWindowDays int
	StewardsNotified  int
	// OverlapExpiresAt is the UTC RFC3339 deadline after which the old (rotating)
	// signing cert is no longer accepted by stewards. Empty when overlapDays == 0.
	OverlapExpiresAt string
}

// SigningRotationService delivers the controller's current signing certificate
// to stewards that need it refreshed. It is the service-layer implementation of
// the StewardOnConnectHook interface (Issue #1817).
type SigningRotationService struct {
	mu                sync.RWMutex
	certManager       *cert.Manager
	publisher         *commands.Publisher
	controllerService *ControllerService
	logger            logging.Logger
}

// NewSigningRotationService creates a new SigningRotationService. The publisher
// must be injected after construction via SetPublisher once it is available,
// because the command publisher depends on the control-plane provider which in
// turn depends on this service's hook (initialization cycle).
func NewSigningRotationService(certManager *cert.Manager, logger logging.Logger) *SigningRotationService {
	return &SigningRotationService{
		certManager: certManager,
		logger:      logger,
	}
}

// SetPublisher injects the command publisher. Must be called before the
// ControlChannel accepts connections (i.e. before server Start()).
func (s *SigningRotationService) SetPublisher(p *commands.Publisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publisher = p
}

// SetControllerService injects the controller service used by Rotate to enumerate
// connected stewards for fan-out.
func (s *SigningRotationService) SetControllerService(cs *ControllerService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controllerService = cs
}

// Rotate generates a new ConfigSigning certificate, transitions the lifecycle
// cursor, and fans out a COMMAND_TYPE_PUSH_SIGNING_CERT command to all currently
// connected stewards. Per-steward delivery errors are logged but do not abort
// the rotation. An audit log entry is emitted that contains no PEM body data.
func (s *SigningRotationService) Rotate(ctx context.Context, operatorSerial string, overlapDays int) (*RotationResult, error) {
	// Capture the old serial before rotating.
	cursor, err := s.certManager.GetSigningCursorState()
	if err != nil {
		return nil, fmt.Errorf("signing rotation: get cursor state: %w", err)
	}
	var oldSerial string
	if cursor != nil {
		oldSerial = cursor.CurrentSerial
	}

	newCert, err := s.certManager.RotateSigningCertificate(overlapDays)
	if err != nil {
		return nil, fmt.Errorf("signing rotation: rotate certificate: %w", err)
	}

	// Steward push always carries an RFC3339 deadline so the client-side
	// overlap check fires deterministically — overlapDays == 0 yields a
	// just-elapsed timestamp, retiring the old cert on the next verifier rebuild.
	overlapExpiresAt := time.Now().UTC().Add(time.Duration(overlapDays) * 24 * time.Hour).Format(time.RFC3339)

	// The API contract reports an empty overlap_expires_at when overlapDays == 0
	// so operators can distinguish "no overlap" from a real future deadline.
	apiOverlapExpiresAt := overlapExpiresAt
	if overlapDays == 0 {
		apiOverlapExpiresAt = ""
	}

	s.mu.RLock()
	publisher := s.publisher
	controllerSvc := s.controllerService
	s.mu.RUnlock()

	var stewardsNotified int
	if publisher != nil && controllerSvc != nil {
		stewards := controllerSvc.GetAllStewards()
		certPEM := base64.StdEncoding.EncodeToString(newCert.CertificatePEM)
		params := map[string]interface{}{
			"cert_pem":           certPEM,
			"overlap_expires_at": overlapExpiresAt,
		}
		for _, steward := range stewards {
			if _, pubErr := publisher.PublishCommand(ctx, steward.ID, types.CommandPushSigningCert, params); pubErr != nil {
				s.logger.Error("failed to push signing cert to steward",
					"steward_id", logging.SanitizeLogValue(steward.ID),
					"error", pubErr)
			} else {
				stewardsNotified++
			}
		}
	}

	s.logger.Info("signing-cert rotation",
		"operator_serial", operatorSerial,
		"old_serial", oldSerial,
		"new_serial", newCert.SerialNumber,
		"overlap_days", overlapDays,
		"stewards_notified", stewardsNotified)

	return &RotationResult{
		OldSerial:         oldSerial,
		NewSerial:         newCert.SerialNumber,
		OverlapWindowDays: overlapDays,
		StewardsNotified:  stewardsNotified,
		OverlapExpiresAt:  apiOverlapExpiresAt,
	}, nil
}

// EnsureStewardCurrent pushes the controller's current signing certificate to
// the specified steward via COMMAND_TYPE_PUSH_SIGNING_CERT. The push is
// fire-and-forget (no ack required). Idempotent: the steward ignores pushes
// with the same fingerprint it already holds.
func (s *SigningRotationService) EnsureStewardCurrent(ctx context.Context, stewardID string) error {
	s.mu.RLock()
	publisher := s.publisher
	s.mu.RUnlock()

	if publisher == nil {
		return fmt.Errorf("signing rotation service: publisher not initialized")
	}

	signingCert, err := s.certManager.GetCurrentCertForPurpose(cert.PurposeSigning)
	if err != nil {
		return fmt.Errorf("signing rotation service: load signing cursor: %w", err)
	}

	certPEM, _, err := s.certManager.ExportCertificate(signingCert.SerialNumber, false)
	if err != nil {
		return fmt.Errorf("signing rotation service: export signing cert serial=%s: %w", signingCert.SerialNumber, err)
	}
	if len(certPEM) == 0 {
		return fmt.Errorf("signing rotation service: empty cert PEM for serial=%s", signingCert.SerialNumber)
	}

	// Compute overlap_expires_at from the active cursor if rotation is in progress.
	var overlapExpiresAt string
	if rotCursor, cursorErr := s.certManager.GetSigningCursorState(); cursorErr == nil && rotCursor != nil && rotCursor.RotatingSerial != "" {
		deadline := rotCursor.RotatedAt.Add(time.Duration(rotCursor.OverlapWindowDays) * 24 * time.Hour)
		overlapExpiresAt = deadline.UTC().Format(time.RFC3339)
	}

	params := map[string]interface{}{
		"cert_pem":           base64.StdEncoding.EncodeToString(certPEM),
		"serial":             signingCert.SerialNumber,
		"overlap_expires_at": overlapExpiresAt,
	}

	if _, pubErr := publisher.PublishCommand(ctx, stewardID, types.CommandPushSigningCert, params); pubErr != nil {
		return fmt.Errorf("signing rotation service: publish push_signing_cert to steward %s: %w", stewardID, pubErr)
	}

	s.logger.Info("signing cert pushed to steward on connect",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"serial", logging.SanitizeLogValue(signingCert.SerialNumber))

	return nil
}

// OnConnect implements the StewardOnConnectHook interface. Called by the gRPC
// control-plane provider after a steward successfully registers on the
// ControlChannel, before the receive loop begins (Issue #1817).
func (s *SigningRotationService) OnConnect(ctx context.Context, stewardID string) error {
	return s.EnsureStewardCurrent(ctx, stewardID)
}
