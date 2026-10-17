// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import "context"

type terminalProofKey struct{}

// TerminalProof is the verified operator proof a redeemed one-time ticket carries to
// ServeWebSocket. The REST layer redeems the ticket and verifies it belongs to the
// caller; ServeWebSocket refuses to open a terminal without one.
type TerminalProof struct {
	// StewardID is the steward the proof was verified for.
	StewardID string
	// UserID is the raw principal ID, kept for the audit record only.
	UserID string
	// TenantID is the tenant the session is opened under; it must equal the request's tenant.
	TenantID string
	// TerminalShell is the shell the operator signed for; it is the only shell opened.
	TerminalShell string
	// Params are the operator envelope keys (targets, nonce, expires_at, credential
	// fields, WebAuthn manifest), published to the steward unchanged.
	Params map[string]interface{}
}

// WithTerminalProof returns ctx carrying a verified terminal proof.
func WithTerminalProof(ctx context.Context, p *TerminalProof) context.Context {
	return context.WithValue(ctx, terminalProofKey{}, p)
}

// TerminalProofFromContext returns the verified proof in ctx, if any.
func TerminalProofFromContext(ctx context.Context) (*TerminalProof, bool) {
	p, ok := ctx.Value(terminalProofKey{}).(*TerminalProof)
	return p, ok && p != nil
}
