// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package registration

import "errors"

// ErrRefreshPending is returned by RefreshComplete when the controller accepts the
// proof-of-possession but queues the request for manual approval (HTTP 202).
// Callers should log and schedule a retry rather than treating this as fatal.
var ErrRefreshPending = errors.New("registration refresh pending operator approval")

// ErrRefreshRejected is returned by RefreshChallenge or RefreshComplete when the
// controller refuses the request for a revoked or dormant device (HTTP 403).
// Callers must halt and not fall through to full re-registration.
var ErrRefreshRejected = errors.New("registration refresh rejected by controller")

// RefreshChallengeResponse is the response body from POST /api/v1/stewards/{device_id}/refresh/challenge.
type RefreshChallengeResponse struct {
	Nonce     string `json:"nonce"`      // base64url-encoded 32-byte random nonce
	ServerTS  uint64 `json:"server_ts"`  // unix nanoseconds, included in the PoP digest
	ExpiresIn int    `json:"expires_in"` // seconds until the nonce expires (typically 60)
}

// RefreshCompleteResponse is the response body from POST /api/v1/stewards/{device_id}/refresh/complete
// on HTTP 200 (cert issued immediately). HTTP 202 returns ErrRefreshPending; HTTP 403 returns ErrRefreshRejected.
type RefreshCompleteResponse struct {
	ClientCert       string `json:"client_cert"`
	ClientKey        string `json:"client_key"`
	CACert           string `json:"ca_cert"`
	IssuerChain      string `json:"issuer_chain,omitempty"`
	ServerCert       string `json:"server_cert,omitempty"`
	TransportAddress string `json:"transport_address"`
}
