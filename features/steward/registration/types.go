// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package registration

import "errors"

// ErrRefreshPending is returned by RefreshComplete when the controller accepts the
// proof-of-possession but queues the request for manual approval (HTTP 202).
// Callers should log and schedule a retry rather than treating this as fatal.
var ErrRefreshPending = errors.New("registration refresh pending operator approval")

// RefreshPendingError is the ErrRefreshPending a queued refresh returns, carrying
// the pending ID the steward collects the outcome with through RefreshClaim
// (Issue #4532). errors.Is(err, ErrRefreshPending) matches it.
type RefreshPendingError struct {
	PendingID string
}

func (e *RefreshPendingError) Error() string { return ErrRefreshPending.Error() }

// Is reports whether target is ErrRefreshPending.
func (e *RefreshPendingError) Is(target error) bool { return target == ErrRefreshPending }

// ErrRefreshRejected is returned by RefreshChallenge, RefreshComplete or
// RefreshClaim when the controller refuses the request (HTTP 403): the device is
// revoked, tenant policy rejects refreshes, or an operator rejected it. The
// refusal holds until the controller changes it; callers keep asking at a slow
// interval rather than stopping, so a later approval needs no one at the device
// (Issue #4532). They must not fall through to full re-registration.
var ErrRefreshRejected = errors.New("registration refresh rejected by controller")

// ErrRefreshUnknownDevice is returned when the controller has no steward record
// for this device (HTTP 404 from the challenge or complete call): the device must
// register with its token instead (Issue #4532).
var ErrRefreshUnknownDevice = errors.New("controller has no record of this device")

// ErrRefreshNotAvailable is returned by RefreshClaim when the pending refresh no
// longer exists, has expired, or was already collected: the steward starts a new
// refresh (Issue #4532).
var ErrRefreshNotAvailable = errors.New("pending registration refresh is no longer available")

// ErrDeviceAlreadyRegistered is returned by Register when the controller already
// holds an active record for this device ID (HTTP 409). The device re-admits with
// its device key through the refresh handshake instead (Issue #4532).
var ErrDeviceAlreadyRegistered = errors.New("device is already registered with the controller")

// RefreshChallengeResponse is the response body from POST /api/v1/stewards/{device_id}/refresh/challenge.
type RefreshChallengeResponse struct {
	Nonce     string `json:"nonce"`      // base64url-encoded 32-byte random nonce
	ServerTS  uint64 `json:"server_ts"`  // unix nanoseconds, included in the PoP digest
	ExpiresIn int    `json:"expires_in"` // seconds until the nonce expires (typically 60)
}

// RefreshCompleteResponse is the response body from POST /api/v1/stewards/{device_id}/refresh/complete
// on HTTP 200 (cert issued immediately). HTTP 202 returns ErrRefreshPending; HTTP 403 returns ErrRefreshRejected.
//
// No client_key field exists on this response (Issue #3781: the controller never
// generates or sees a private key for this credential). The caller generates its
// own fresh keypair, submits its public half as a CSR via RefreshComplete's csrPEM
// parameter, and pairs the response's ClientCert with the locally held private key.
type RefreshCompleteResponse struct {
	ClientCert       string `json:"client_cert"`
	CACert           string `json:"ca_cert"`
	IssuerChain      string `json:"issuer_chain,omitempty"`
	ServerCert       string `json:"server_cert,omitempty"`
	TransportAddress string `json:"transport_address"`

	// StewardID and TenantID identify the record the certificate was issued for,
	// so a steward re-admitting without its stored identity record can rebuild it
	// (Issue #4532). Empty from controllers that predate the fields.
	StewardID string `json:"steward_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}
