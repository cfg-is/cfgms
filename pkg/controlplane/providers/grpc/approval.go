// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// StewardApprovalChecker is the extension point for the approval-gate epic
// (#1690–#1698). When injected via WithApprovalChecker, the ControlChannel
// handler calls it for every connecting steward before admitting the stream.
//
// Implementors return (false, nil) to reject the steward, (true, nil) to admit
// it, or (_, err) when the check cannot be completed. Errors are fail-closed.
//
// The default behaviour (no checker injected) is equivalent to always returning
// (true, nil): all mTLS-authenticated stewards are admitted.
type StewardApprovalChecker interface {
	// IsApproved returns true when the steward identified by stewardID is
	// permitted to open a ControlChannel stream.
	IsApproved(ctx context.Context, stewardID string) (bool, error)
}

// WithApprovalChecker injects a StewardApprovalChecker into the Provider.
// The checker is called in server mode whenever a steward opens a ControlChannel.
// Intended for the approval-gate epic (#1690–#1698); production code that does
// not need approval gating should leave the default (nil, always-admit).
func WithApprovalChecker(checker StewardApprovalChecker) option {
	return func(p *Provider) {
		p.approvalChecker = checker
	}
}

type stewardStoreApprovalChecker struct {
	store business.StewardStore
}

// NewStewardStoreApprovalChecker builds the production admission checker. Only
// stewards in reconnect-capable lifecycle states may open a ControlChannel.
func NewStewardStoreApprovalChecker(store business.StewardStore) StewardApprovalChecker {
	return &stewardStoreApprovalChecker{store: store}
}

func (c *stewardStoreApprovalChecker) IsApproved(ctx context.Context, stewardID string) (bool, error) {
	if c.store == nil {
		return false, fmt.Errorf("steward approval store is unavailable")
	}
	record, err := c.store.GetSteward(ctx, stewardID)
	if err != nil {
		// "No such steward" is a determinate authorization answer, not a failure
		// of the approval service: a steward with no record is definitively not
		// approved. Reporting it as an error made ControlChannel answer
		// codes.Unavailable ("steward approval service unavailable"), which the
		// client treats as a transient transport fault and retries — so a steward
		// holding a still-valid mTLS cert whose record is gone reconnected
		// indefinitely while the controller logged the miss at ERROR on every
		// attempt. Observed live on the cfg-lab cluster (story #3096): three such
		// stewards produced ~1 reconnect/second each and 78 MB of controller log
		// in a day. Denying with (false, nil) is equally fail-closed — admission
		// is still refused — but it is reported as PermissionDenied, the
		// determinate answer it actually is.
		if errors.Is(err, business.ErrStewardNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("load steward approval state: %w", err)
	}
	switch record.Status {
	case business.StewardStatusRegistered, business.StewardStatusActive, business.StewardStatusLost,
		// A tampered steward stays admitted: it must keep reporting, and refusing
		// controller-to-endpoint traffic for it is a separate decision.
		business.StewardStatusTampered:
		return true, nil
	default:
		return false, nil
	}
}

// defaultRevocationRecheckInterval bounds how long an already-open
// ControlChannel survives the revocation of its client-certificate serial.
const defaultRevocationRecheckInterval = 30 * time.Second

// CertRevocationChecker reports whether a client-certificate serial is
// revoked. *cert.Manager satisfies it. A non-nil error means the status cannot
// be determined and callers must fail closed.
type CertRevocationChecker interface {
	IsRevoked(serial string) (bool, error)
}

// WithRevocationChecker injects the certificate revocation checker consulted by
// Register and ControlChannel admission, and by the periodic re-check of open
// control channels (Issue #4930). Nil (default) disables the check.
func WithRevocationChecker(checker CertRevocationChecker) option {
	return func(p *Provider) {
		p.revocationChecker = checker
	}
}

// WithRevocationRecheckInterval overrides how often an open ControlChannel
// re-checks its peer serial. Non-positive values keep the default (30s).
func WithRevocationRecheckInterval(d time.Duration) option {
	return func(p *Provider) {
		p.revocationRecheckInterval = d
	}
}

func (p *Provider) recheckInterval() time.Duration {
	if p.revocationRecheckInterval > 0 {
		return p.revocationRecheckInterval
	}
	return defaultRevocationRecheckInterval
}

// peerCertSerial returns the decimal serial of the verified client certificate.
func peerCertSerial(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer info in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate")
	}
	return tlsInfo.State.PeerCertificates[0].SerialNumber.String(), nil
}

// checkPeerRevocation refuses a peer whose certificate serial is revoked
// (PermissionDenied) or whose status cannot be determined (Unavailable,
// fail-closed). It returns the peer serial; with no checker it admits and
// returns "".
func (p *Provider) checkPeerRevocation(ctx context.Context, stewardID string) (string, error) {
	if p.revocationChecker == nil {
		return "", nil
	}
	serial, err := peerCertSerial(ctx)
	if err != nil {
		return "", status.Errorf(codes.Unauthenticated, "failed to read peer certificate serial")
	}
	revoked, err := p.revocationChecker.IsRevoked(serial)
	if err != nil {
		p.logger.Error("certificate revocation check error, rejecting (fail-closed)",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"serial", logging.SanitizeLogValue(serial),
			"error", logging.SanitizeLogValue(err.Error()))
		return "", status.Error(codes.Unavailable, "certificate revocation service unavailable")
	}
	if revoked {
		p.logger.Warn("steward rejected: client certificate revoked",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"serial", logging.SanitizeLogValue(serial))
		return "", status.Error(codes.PermissionDenied, "client certificate revoked")
	}
	return serial, nil
}
