// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"errors"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// stewardCapabilityStore adapts the shared steward store to
// controlplaneTypes.SigningCapabilityStore (#5174), so every controller node that
// shares the store signs the payload version a steward advertised on any node.
type stewardCapabilityStore struct {
	stewards business.StewardStore
}

// NewSigningCapabilityStore returns the steward store as a signing-capability store.
// A steward with no record reads as 0 (v1); a heartbeat for one is an error.
func NewSigningCapabilityStore(stewards business.StewardStore) controlplaneTypes.SigningCapabilityStore {
	return &stewardCapabilityStore{stewards: stewards}
}

func (s *stewardCapabilityStore) SetSigningPayloadVersion(ctx context.Context, stewardID string, version uint32) error {
	return s.stewards.SetStewardSigningPayloadVersion(ctx, stewardID, version)
}

func (s *stewardCapabilityStore) GetSigningPayloadVersion(ctx context.Context, stewardID string) (uint32, error) {
	v, err := s.stewards.GetStewardSigningPayloadVersion(ctx, stewardID)
	if errors.Is(err, business.ErrStewardNotFound) {
		return 0, nil
	}
	return v, err
}
