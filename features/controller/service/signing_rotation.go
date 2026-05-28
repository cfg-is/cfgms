// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// SigningRotationService delivers the controller's current signing certificate
// to stewards that need it refreshed. It is the service-layer implementation of
// the StewardOnConnectHook interface (Issue #1817).
type SigningRotationService struct {
	mu          sync.RWMutex
	certManager *cert.Manager
	publisher   *commands.Publisher
	logger      logging.Logger
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

	// loadSigningCursor: get the current signing cert from the cert manager.
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

	params := map[string]interface{}{
		"cert_pem": base64.StdEncoding.EncodeToString(certPEM),
		"serial":   signingCert.SerialNumber,
	}

	if _, err := publisher.PublishCommand(ctx, stewardID, types.CommandPushSigningCert, params); err != nil {
		return fmt.Errorf("signing rotation service: publish push_signing_cert to steward %s: %w", stewardID, err)
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
