// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"time"
)

// SigningTrustAck records that one steward confirmed one config-signing
// certificate. JSON tags are load-bearing: pkg/cert's file-backed
// implementation marshals this exact type to disk.
type SigningTrustAck struct {
	// StewardID identifies the acknowledging steward.
	StewardID string `json:"steward_id"`
	// Serial is the serial of the signing certificate the steward confirmed.
	Serial string `json:"serial"`
	// AcknowledgedAt is when the first acknowledgement for this pair was
	// recorded.
	AcknowledgedAt time.Time `json:"acknowledged_at"`
}

// SigningTrustAckStore defines durable storage for per-steward confirmation of
// a signing certificate. A cluster-visible implementation lets any controller
// node read acknowledgements recorded by any other node.
type SigningTrustAckStore interface {
	// RecordAck records that stewardID confirmed the certificate with the
	// given serial. It is idempotent: a repeated call for the same pair
	// keeps the first AcknowledgedAt. Empty stewardID or serial is rejected.
	RecordAck(ctx context.Context, stewardID, serial string) error

	// GetAck returns the acknowledgement for the pair, or nil if the steward
	// has not acknowledged that serial.
	GetAck(ctx context.Context, stewardID, serial string) (*SigningTrustAck, error)

	// ListAcked returns every acknowledgement recorded for serial, ordered
	// by steward ID. The result is empty when none exist.
	ListAcked(ctx context.Context, serial string) ([]SigningTrustAck, error)
}
