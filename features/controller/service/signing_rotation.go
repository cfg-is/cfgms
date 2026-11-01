// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
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
	// NodeID is the controller node that performed the rotation. Empty when the
	// service was not given a node ID (single-node controllers).
	NodeID string
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
	nodeID            string
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

// SetNodeID records the controller node's cluster ID, reported in RotationResult
// and the rotation log line so a rotation can be attributed to the node that ran it.
func (s *SigningRotationService) SetNodeID(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodeID = nodeID
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
	// Root-scope gate (Issue #4346). The signing CA is a single fleet-wide
	// resource (see the fan-out comment below), so rotating it is a root-only
	// operation — the same rule handleRotateSigningCert already enforces via
	// scope.IsRoot() before calling here. That handler-side check verifies
	// strong authentication (AssuranceStrong) separately; neither implies the
	// other; conflating them would let any AssuranceStrong-authenticated
	// tenant-scoped admin rotate the fleet-wide signing CA. Re-checking the
	// authoritative root-scope primitive here — rather than trusting that every
	// current and future caller re-derives it correctly — is the
	// service-layer defense-in-depth this story exists to add.
	scope, _ := ctx.Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if !scope.IsRoot() {
		return nil, fmt.Errorf("signing rotation: unscoped (root) caller required")
	}

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
	nodeID := s.nodeID
	s.mu.RUnlock()

	var stewardsNotified int
	if publisher != nil && controllerSvc != nil {
		// push_signing_cert must be signed with the OLD cert (the cert stewards already
		// trust), not the new cert. After rotation the DynamicSigner resolves to the new
		// cert; a steward that hasn't received the refresh yet has no way to verify a
		// new-cert-signed command, creating a bootstrapping deadlock (Issue #1844).
		// Sign the fan-out with the rotating cert so the steward's existing verifier
		// can authenticate the command before updating its trust set.
		oldSigner := s.signerForPush(oldSerial, nil)

		// The signing CA is controller-wide, not per-tenant: every steward in the
		// fleet verifies commands against it, so every steward must receive the new
		// cert before the overlap window closes. ListFleetStewards narrows its result
		// to the subtree named by ctxkeys.TenantID, and Rotate runs on an HTTP request
		// context whose tenant is the calling admin's own tenant — so passing ctx
		// through unchanged would silently skip every steward outside that subtree and
		// strand them on the retired cert. Drop the caller's tenant identity — a
		// system-internal context reaches the whole fleet — while keeping the
		// request's cancellation and deadline (Issue #4665).
		fleetCtx := ctxkeys.WithSystem(ctx)
		stewards := controllerSvc.ListFleetStewards(fleetCtx)
		// Send the issuer chain with the leaf so a certificate issued by an
		// imported intermediate CA verifies against the steward's pinned root.
		pushPEM, _, exportErr := s.certManager.ExportCertificate(newCert.SerialNumber, false, true)
		if exportErr != nil {
			// The rotation has already committed; fall back to the leaf alone.
			s.logger.Warn("signing rotation: could not export issuer chain for push; pushing leaf only",
				"serial", logging.SanitizeLogValue(newCert.SerialNumber),
				"error", logging.SanitizeLogValue(exportErr.Error()))
			pushPEM = newCert.CertificatePEM
		}
		certPEM := base64.StdEncoding.EncodeToString(pushPEM)
		params := map[string]interface{}{
			"cert_pem":           certPEM,
			"serial":             newCert.SerialNumber,
			"overlap_expires_at": overlapExpiresAt,
		}
		// Serials already revoked as signing certificates are retired by this
		// same push, so a revoke that predates the rotation still reaches every
		// steward.
		if retire, retireErr := s.retireSet(ctx, nil, newCert.SerialNumber, nil); retireErr != nil {
			s.logger.Warn("signing rotation: could not list revoked signing serials for the push",
				"error", logging.SanitizeLogValue(retireErr.Error()))
		} else if len(retire) > 0 {
			params["retire_serials"] = retire
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
					"error", logging.SanitizeLogValue(pubErr.Error()))
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
		NodeID:            nodeID,
	}, nil
}

// EnsureStewardCurrent pushes the controller's current signing certificate to
// the specified steward via COMMAND_TYPE_PUSH_SIGNING_CERT. The push is
// fire-and-forget (no ack required). Idempotent: the steward ignores pushes
// with the same fingerprint it already holds.
//
// The same single command carries retire_serials (Issue #4795): a rotating
// serial whose overlap window has elapsed and every serial revoked as a signing
// certificate. A steward that was offline when the controller fanned the
// retirement out gets it here, in the push it already receives on connect. A
// second command signed by the new key right after this one could be rejected,
// because the steward verifies on receipt, before this push has been applied.
func (s *SigningRotationService) EnsureStewardCurrent(ctx context.Context, stewardID string) error {
	s.mu.RLock()
	publisher := s.publisher
	s.mu.RUnlock()

	if publisher == nil {
		return fmt.Errorf("signing rotation service: publisher not initialized")
	}

	push, err := s.buildPush(ctx, nil)
	if err != nil {
		return err
	}

	// push_signing_cert must be signed with the rotating (old) cert so stewards
	// that were offline during the rotation fan-out can verify the command before
	// their trust set is updated (Issue #1844). Always sign with the rotating cert,
	// regardless of whether the overlap window has expired: a steward that missed
	// the fan-out only trusts the rotating cert, and signing with the new cert
	// would fail verification before the trust set is updated. If the rotating
	// cert has been purged, signerForPush returns nil and we fall back to the
	// DynamicSigner (requiring re-enrollment via Issue #1845).
	rotatingSigner := s.signerForPush(push.rotatingSerial, push.retireSerials)

	var pubErr error
	if rotatingSigner != nil {
		_, pubErr = publisher.PublishCommandWithSigner(ctx, stewardID, types.CommandPushSigningCert, push.params, rotatingSigner)
	} else {
		_, pubErr = publisher.PublishCommand(ctx, stewardID, types.CommandPushSigningCert, push.params)
	}
	if pubErr != nil {
		return fmt.Errorf("signing rotation service: publish push_signing_cert to steward %s: %w", stewardID, pubErr)
	}

	s.logger.Info("signing cert pushed to steward on connect",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"serial", logging.SanitizeLogValue(push.currentSerial),
		"retire_count", len(push.retireSerials))

	return nil
}

// signingPush is a push_signing_cert payload together with what the signer
// choice depends on.
type signingPush struct {
	params        map[string]interface{}
	currentSerial string
	// rotatingSerial is the cursor's rotating serial while one exists, "" otherwise.
	rotatingSerial string
	// retireSerials is the retire_serials list carried in params.
	retireSerials []string
}

// buildPush assembles the push_signing_cert payload for the current signing
// certificate. extraRetire names serials the caller is withdrawing right now, on
// top of the ones the cursor and the revocation store already require retiring.
// It refuses when the current signing certificate is itself revoked.
func (s *SigningRotationService) buildPush(ctx context.Context, extraRetire []string) (*signingPush, error) {
	signingCert, err := s.certManager.GetCurrentCertForPurpose(cert.PurposeSigning)
	if err != nil {
		return nil, fmt.Errorf("signing rotation service: load signing cursor: %w", err)
	}
	revoked, err := s.certManager.IsRevoked(signingCert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("signing rotation service: check revocation of current signing cert: %w", err)
	}
	if revoked {
		return nil, fmt.Errorf("signing rotation service: current signing cert serial=%s is revoked; refusing to sign", signingCert.SerialNumber)
	}

	certPEM, _, err := s.certManager.ExportCertificate(signingCert.SerialNumber, false, true)
	if err != nil {
		return nil, fmt.Errorf("signing rotation service: export signing cert serial=%s: %w", signingCert.SerialNumber, err)
	}
	if len(certPEM) == 0 {
		return nil, fmt.Errorf("signing rotation service: empty cert PEM for serial=%s", signingCert.SerialNumber)
	}

	// overlap_expires_at comes from the active cursor while a rotation is in
	// progress, and is sent on every push: omitting it would clear a deadline the
	// steward already holds and leave the rotating cert trusted indefinitely.
	var overlapExpiresAt string
	var rotatingSerial string
	cursor, cursorErr := s.certManager.GetSigningCursorState()
	if cursorErr == nil && cursor != nil && cursor.RotatingSerial != "" {
		rotatingSerial = cursor.RotatingSerial
		deadline := cursor.RotatedAt.Add(time.Duration(cursor.OverlapWindowDays) * 24 * time.Hour)
		overlapExpiresAt = deadline.UTC().Format(time.RFC3339)
	}

	retire, err := s.retireSet(ctx, cursor, signingCert.SerialNumber, extraRetire)
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"cert_pem":           base64.StdEncoding.EncodeToString(certPEM),
		"serial":             signingCert.SerialNumber,
		"overlap_expires_at": overlapExpiresAt,
	}
	if len(retire) > 0 {
		// A JSON array of strings, never a comma-joined string: the steward would
		// decode a bare decimal serial as a number.
		params["retire_serials"] = retire
	}
	return &signingPush{
		params:         params,
		currentSerial:  signingCert.SerialNumber,
		rotatingSerial: rotatingSerial,
		retireSerials:  retire,
	}, nil
}

// retireSet is the sorted, de-duplicated set of serials a push must retire: the
// rotating serial once its overlap window has elapsed or it is marked retired
// (never in LegacyLocal mode, where the current local key is not trusted by every
// steward and a retirement would strand some), every serial revoked as a signing
// certificate, and extra. The current serial is never in the set.
func (s *SigningRotationService) retireSet(ctx context.Context, cursor *cert.SigningCertCursor, currentSerial string, extra []string) ([]string, error) {
	set := make(map[string]struct{})
	for _, serial := range extra {
		set[serial] = struct{}{}
	}

	revoked, err := s.certManager.ListRevokedSigningSerials()
	if err != nil {
		return nil, fmt.Errorf("signing rotation service: list revoked signing serials: %w", err)
	}
	for _, serial := range revoked {
		set[serial] = struct{}{}
	}

	if cursor != nil && cursor.RotatingSerial != "" && rotatingWindowClosed(cursor, time.Now()) {
		mode, modeErr := s.certManager.SigningIdentityMode(ctx)
		if modeErr == nil && mode != cert.SigningIdentityLegacyLocal && mode != cert.SigningIdentityUnprovisioned {
			set[cursor.RotatingSerial] = struct{}{}
		}
	}

	delete(set, currentSerial)
	out := make([]string, 0, len(set))
	for serial := range set {
		out = append(out, serial)
	}
	sort.Strings(out)
	return out, nil
}

// rotatingWindowClosed reports whether the cursor's rotating serial is past its
// overlap window or already marked retired.
func rotatingWindowClosed(cursor *cert.SigningCertCursor, now time.Time) bool {
	if cursor.RetiredAt != nil {
		return true
	}
	deadline := cursor.RotatedAt.Add(time.Duration(cursor.OverlapWindowDays) * 24 * time.Hour)
	return !now.Before(deadline)
}

// signerForPush returns a signer backed by the rotating serial for a push, or nil
// to fall back to the current (dynamic) signer. A revoked serial is never used to
// sign, except for the one push that retires that same serial: a steward that
// trusts nothing else can verify nothing but this one delivery.
func (s *SigningRotationService) signerForPush(rotatingSerial string, retire []string) signature.Signer {
	if rotatingSerial == "" {
		return nil
	}
	revoked, err := s.certManager.IsRevoked(rotatingSerial)
	if err != nil {
		s.logger.Warn("signing rotation: could not check revocation of rotating cert; falling back to dynamic signer",
			"serial", logging.SanitizeLogValue(rotatingSerial),
			"error", logging.SanitizeLogValue(err.Error()))
		return nil
	}
	if revoked && !containsString(retire, rotatingSerial) {
		return nil
	}
	return s.buildRotatingSigner(rotatingSerial)
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
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
			"error", logging.SanitizeLogValue(errText(err)))
		return nil
	}
	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
	})
	if err != nil {
		s.logger.Warn("signing rotation: could not create rotating cert signer; falling back to dynamic signer",
			"serial", logging.SanitizeLogValue(serial),
			"error", logging.SanitizeLogValue(err.Error()))
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

// errText renders an error for a log value; a nil error (an export that
// returned no key without failing) renders as an explanatory string.
func errText(err error) string {
	if err == nil {
		return "no private key returned"
	}
	return err.Error()
}
