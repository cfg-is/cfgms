// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"net"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const (
	// identityInUseReason and identityInUseDomain are the ErrorInfo fields that
	// mark a ControlChannel refusal as "this identity is in use by another
	// device" (ADR-034 §4), as distinct from any other PermissionDenied.
	identityInUseReason = "IDENTITY_IN_USE"
	identityInUseDomain = "cfgms.io"
)

// IdentityConflict describes one steward identity observed in use on two
// endpoints at once (ADR-034 §3): a ControlChannel opened for a steward ID that
// already has a live stream from a different host.
type IdentityConflict struct {
	// StewardID is the mTLS-verified steward identity.
	StewardID string
	// TenantID is resolved server-side from the fleet record; never caller-supplied.
	// Empty when the steward has no record or the lookup failed.
	TenantID string
	// ExistingAddr is the remote address of the stream already registered.
	ExistingAddr string
	// NewAddr is the remote address of the connection being admitted.
	NewAddr string
	// NewSerial is the client certificate serial presented by the new connection.
	NewSerial string
	// ExistingSerial is the serial of the existing connection; empty when unknown.
	ExistingSerial string
	// DetectedAt is when the conflict was detected.
	DetectedAt time.Time
	// Provenance is the host-provenance assessment of the connection being
	// admitted (ADR-034 §2), so a conflict carries the same evidence as a
	// divergence. Its Decision is ProvenanceUnknown when no check ran.
	Provenance ProvenanceAssessment
}

// IdentityConflictObserver receives identity-conflict reports. Implementations
// must return quickly: the report is made on the ControlChannel admission path.
// The observer is informational — it cannot refuse or alter the admission.
type IdentityConflictObserver interface {
	ObserveIdentityConflict(ctx context.Context, conflict IdentityConflict)
}

// WithIdentityConflictObserver injects the observer told about duplicate
// steward identities. Nil (the default) disables reporting. Detection does not
// change which connection wins: registry.Register behaviour is unchanged.
func WithIdentityConflictObserver(observer IdentityConflictObserver) option {
	return func(p *Provider) {
		p.identityConflictObserver = observer
	}
}

// reportIdentityConflict compares the incoming connection with any live
// registry entry for the same steward ID and reports a conflict when the peer
// hosts differ. A same-host reconnect (a restarting steward whose stale stream
// has not yet errored) is not a conflict.
//
// It returns the live connection when one exists on a different host, whether or
// not an observer is configured, so the caller can apply the admission rules of
// ADR-034 §2; nil otherwise.
func (p *Provider) reportIdentityConflict(ctx context.Context, stewardID, newAddr, newSerial string, provenance ProvenanceAssessment) *registry.StewardConnection {
	existing, ok := p.registry.Get(stewardID)
	if !ok || existing == nil {
		return nil
	}
	existingHost := addrHost(existing.RemoteAddr)
	newHost := addrHost(newAddr)
	if existingHost == "" || newHost == "" || existingHost == newHost {
		return nil
	}
	if p.identityConflictObserver == nil {
		return existing
	}

	tenantID := ""
	if p.stewardTenantResolver != nil {
		t, err := p.stewardTenantResolver.TenantForSteward(ctx, stewardID)
		if err != nil {
			p.logger.Warn("identity conflict tenant lookup failed",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		} else {
			tenantID = t
		}
	}

	p.logger.Warn("steward identity in use on two endpoints",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"existing_addr", logging.SanitizeLogValue(existing.RemoteAddr),
		"new_addr", logging.SanitizeLogValue(newAddr))

	p.identityConflictObserver.ObserveIdentityConflict(ctx, IdentityConflict{
		StewardID:      stewardID,
		TenantID:       tenantID,
		ExistingAddr:   existing.RemoteAddr,
		NewAddr:        newAddr,
		NewSerial:      newSerial,
		ExistingSerial: existing.PeerSerial,
		DetectedAt:     time.Now().UTC(),
		Provenance:     provenance,
	})
	return existing
}

// addrHost returns the host part of a host:port address, or the input when it
// has no port.
func addrHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
