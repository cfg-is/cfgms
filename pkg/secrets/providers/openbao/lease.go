// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package openbao — LeasedSecret implementation for OpenBaoSecretStore.
// M-AUTH-1: Lease mint/renew/revoke via OpenBao /sys/leases endpoints.
package openbao

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Ensure OpenBaoSecretStore implements interfaces.LeasedSecret at compile time.
var _ interfaces.LeasedSecret = (*OpenBaoSecretStore)(nil)

// LeaseSecret attempts to mint a lease for the named secret.
//
// OpenBao KV v2 is a static secrets engine: it does not produce server-managed
// leases the way dynamic engines (database, PKI, AWS) do. This method returns
// interfaces.ErrLeaseNotSupported for KV v2 secrets. Callers that need real
// leases must configure a dynamic secrets engine and use the engine's own path.
func (s *OpenBaoSecretStore) LeaseSecret(ctx context.Context, req *interfaces.LeaseRequest) (*interfaces.Lease, error) {
	if req == nil {
		return nil, fmt.Errorf("lease request cannot be nil")
	}
	if req.TenantID == "" {
		return nil, fmt.Errorf("TenantID is required: %w", cfgconfig.ErrTenantRequired)
	}
	if req.Key == "" {
		return nil, fmt.Errorf("secret key cannot be empty")
	}

	// KV v2 static secrets do not produce server-managed leases.
	return nil, fmt.Errorf("KV v2 path %s/%s: %w",
		logging.SanitizeLogValue(req.TenantID),
		logging.SanitizeLogValue(req.Key),
		interfaces.ErrLeaseNotSupported)
}

// RenewLease extends an active lease by the requested increment.
// Uses OpenBao's /sys/leases/renew endpoint.
func (s *OpenBaoSecretStore) RenewLease(ctx context.Context, leaseID string, increment time.Duration) (*interfaces.Lease, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("leaseID cannot be empty")
	}

	incrementSeconds := int(increment.Seconds())
	result, err := s.client.Sys().RenewWithContext(ctx, leaseID, incrementSeconds)
	if err != nil {
		return nil, fmt.Errorf("failed to renew lease %s: %w",
			logging.SanitizeLogValue(leaseID), err)
	}
	if result == nil {
		return nil, fmt.Errorf("renew returned nil response for lease %s",
			logging.SanitizeLogValue(leaseID))
	}

	ttl := time.Duration(result.LeaseDuration) * time.Second
	now := time.Now()

	return &interfaces.Lease{
		LeaseID:   result.LeaseID,
		TTL:       ttl,
		Renewable: result.Renewable,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}, nil
}

// RevokeLease immediately revokes an active lease.
// Uses OpenBao's /sys/leases/revoke endpoint.
func (s *OpenBaoSecretStore) RevokeLease(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return fmt.Errorf("leaseID cannot be empty")
	}

	if err := s.client.Sys().RevokeWithContext(ctx, leaseID); err != nil {
		return fmt.Errorf("failed to revoke lease %s: %w",
			logging.SanitizeLogValue(leaseID), err)
	}

	return nil
}
