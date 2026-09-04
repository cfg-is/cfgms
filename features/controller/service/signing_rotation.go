// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
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
// cursor, and fans out a COMMAND_TYPE_PUSH_SIGNING_CERT command to every steward
// in the fleet. Per-steward delivery errors are logged but do not abort the
// rotation. An audit log entry is emitted that contains no PEM body data.
//
// The fan-out is deliberately fleet-wide and tenant-independent: there is one
// controller-wide signing CA, so a rotation that reached only part of the fleet
// would strand the rest once the overlap window expires. The caller's tenant
// scope, if any, does not narrow the fan-out.
//
// When force is true, an active in-progress overlap is cleared before the new
// rotation runs — operator-initiated rotations should not block on a previous
// overlap that has not yet expired. When force is false, the primitive's
// in-progress guard is enforced (used to validate the crash-mid-rotation path).
func (s *SigningRotationService) Rotate(ctx context.Context, operatorSerial string, overlapDays int, force bool) (*RotationResult, error) {
	// Capture the old serial before rotating. Prefer the cursor (set after the
	// first rotation); fall back to the active signing cert for fresh controllers
	// where no rotation cursor exists yet.
	cursor, err := s.certManager.GetSigningCursorState()
	if err != nil {
		return nil, fmt.Errorf("signing rotation: get cursor state: %w", err)
	}
	var oldSerial string
	if cursor != nil {
		oldSerial = cursor.CurrentSerial
	}
	if oldSerial == "" {
		if currentCert, cErr := s.certManager.GetCurrentCertForPurpose(cert.PurposeSigning); cErr == nil && currentCert != nil {
			oldSerial = currentCert.SerialNumber
		}
	}

	var newCert *cert.Certificate
	if force {
		newCert, err = s.certManager.ForceRotateSigningCertificate(overlapDays)
	} else {
		newCert, err = s.certManager.RotateSigningCertificate(overlapDays)
	}
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
		// push_signing_cert must be signed with the OLD cert (the cert stewards already
		// trust), not the new cert. After rotation the DynamicSigner resolves to the new
		// cert; a steward that hasn't received the refresh yet has no way to verify a
		// new-cert-signed command, creating a bootstrapping deadlock (Issue #1844).
		// Sign the fan-out with the rotating cert so the steward's existing verifier
		// can authenticate the command before updating its trust set.
		oldSigner := s.buildRotatingSigner(oldSerial)

		// The signing CA is controller-wide, not per-tenant: every steward in the
		// fleet verifies commands against it, so every steward must receive the new
		// cert before the overlap window closes. ListFleetStewards narrows its result
		// to the subtree named by ctxkeys.TenantID, and Rotate runs on an HTTP request
		// context whose tenant is the calling admin's own tenant — so passing ctx
		// through unchanged would silently skip every steward outside that subtree and
		// strand them on the retired cert. Clear the scope (empty tenant == whole
		// fleet) while keeping the request's cancellation and deadline.
		fleetCtx := context.WithValue(ctx, ctxkeys.TenantID, "")
		stewards := controllerSvc.ListFleetStewards(fleetCtx)
		certPEM := base64.StdEncoding.EncodeToString(newCert.CertificatePEM)
		params := map[string]interface{}{
			"cert_pem":           certPEM,
			"serial":             newCert.SerialNumber,
			"overlap_expires_at": overlapExpiresAt,
		}
		for _, steward := range stewards {
			var pubErr error
			if oldSigner != nil {
				_, pubErr = publisher.PublishCommandWithSigner(ctx, steward.ID, types.CommandPushSigningCert, params, oldSigner)
			} else {
				_, pubErr = publisher.PublishCommand(ctx, steward.ID, types.CommandPushSigningCert, params)
			}
			if pubErr != nil {
				s.logger.Error("failed to push signing cert to steward",
					"steward_id", logging.SanitizeLogValue(steward.ID),
					"error", pubErr)
			} else {
				stewardsNotified++
			}
		}
	}

	s.logger.Info("signing-cert rotation",
		"operator_serial", logging.SanitizeLogValue(operatorSerial),
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

	certPEM, _, err := s.certManager.ExportCertificate(signingCert.SerialNumber, false, false)
	if err != nil {
		return fmt.Errorf("signing rotation service: export signing cert serial=%s: %w", signingCert.SerialNumber, err)
	}
	if len(certPEM) == 0 {
		return fmt.Errorf("signing rotation service: empty cert PEM for serial=%s", signingCert.SerialNumber)
	}

	// Compute overlap_expires_at from the active cursor if rotation is in progress.
	// Also capture the rotating serial: push_signing_cert must be signed with the
	// rotating (old) cert so stewards that were offline during the rotation fan-out
	// can verify the command before their trust set is updated (Issue #1844).
	var overlapExpiresAt string
	var rotatingSigner signature.Signer
	if rotCursor, cursorErr := s.certManager.GetSigningCursorState(); cursorErr == nil && rotCursor != nil && rotCursor.RotatingSerial != "" {
		deadline := rotCursor.RotatedAt.Add(time.Duration(rotCursor.OverlapWindowDays) * 24 * time.Hour)
		overlapExpiresAt = deadline.UTC().Format(time.RFC3339)
		// Always sign push_signing_cert with the rotating (old) cert, regardless of
		// whether the overlap window has expired. A steward that was offline during
		// the rotation fan-out only trusts the rotating cert; signing with the new
		// cert would make verification fail before the trust set is updated —
		// the bootstrapping deadlock from Issue #1844. The overlap expiry only controls
		// how the steward filters its own trust set after receiving this push.
		// If the rotating cert has been purged, buildRotatingSigner returns nil and
		// we fall back to the DynamicSigner (requiring re-enrollment via Issue #1845).
		rotatingSigner = s.buildRotatingSigner(rotCursor.RotatingSerial)
	}

	params := map[string]interface{}{
		"cert_pem":           base64.StdEncoding.EncodeToString(certPEM),
		"serial":             signingCert.SerialNumber,
		"overlap_expires_at": overlapExpiresAt,
	}

	var pubErr error
	if rotatingSigner != nil {
		_, pubErr = publisher.PublishCommandWithSigner(ctx, stewardID, types.CommandPushSigningCert, params, rotatingSigner)
	} else {
		_, pubErr = publisher.PublishCommand(ctx, stewardID, types.CommandPushSigningCert, params)
	}
	if pubErr != nil {
		return fmt.Errorf("signing rotation service: publish push_signing_cert to steward %s: %w", stewardID, pubErr)
	}

	s.logger.Info("signing cert pushed to steward on connect",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"serial", logging.SanitizeLogValue(signingCert.SerialNumber))

	return nil
}

// buildRotatingSigner exports the cert identified by serial and returns a Signer
// backed by it, or nil if the export or signer construction fails. Used to sign
// push_signing_cert commands with the rotating (old) cert so stewards that haven't
// yet received the new cert can still verify the command (Issue #1844).
func (s *SigningRotationService) buildRotatingSigner(serial string) signature.Signer {
	if serial == "" {
		return nil
	}
	certPEM, keyPEM, err := s.certManager.ExportCertificate(serial, true, false)
	if err != nil || len(keyPEM) == 0 {
		s.logger.Warn("signing rotation: could not export rotating cert for push_signing_cert signing; falling back to dynamic signer",
			"serial", logging.SanitizeLogValue(serial),
			"error", err)
		return nil
	}
	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	})
	if err != nil {
		s.logger.Warn("signing rotation: could not create rotating cert signer; falling back to dynamic signer",
			"serial", logging.SanitizeLogValue(serial),
			"error", err)
		return nil
	}
	return signer
}

// OnConnect implements the StewardOnConnectHook interface. Called by the gRPC
// control-plane provider after a steward successfully registers on the
// ControlChannel, before the receive loop begins (Issue #1817).
func (s *SigningRotationService) OnConnect(ctx context.Context, stewardID string) error {
	return s.EnsureStewardCurrent(ctx, stewardID)
}
