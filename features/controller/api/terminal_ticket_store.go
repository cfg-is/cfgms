// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

const (
	// ceremonyPrefixTerminalTicket namespaces terminal tickets in the shared NonceStore.
	// It is distinct from every other ceremony prefix, so a ticket hash cannot be consumed
	// as a presence token or any other ceremony, and the reverse.
	ceremonyPrefixTerminalTicket = "webauthn-ceremony:terminal-ticket:"

	// terminalTicketTTL is the lifetime of a minted ticket. It only has to span the
	// browser's immediate WebSocket connect.
	terminalTicketTTL = 30 * time.Second

	// terminalTicketBytes is the entropy of a ticket.
	terminalTicketBytes = 32
)

// terminalTicketRecord is the state bound to a one-time terminal ticket: who minted it,
// for which steward and shell, and the verified operator proof the steward needs.
type terminalTicketRecord struct {
	principalID   string
	tenantID      string
	webSessionID  string
	stewardID     string
	terminalShell string
	expires       time.Time

	targets   []string
	nonce     string
	expiresAt time.Time

	x509     *OperatorX509Proof
	webAuthn *OperatorWebAuthnProof
	manifest string // WebAuthn roster manifest; empty for X.509
}

// terminalTicketWire is the JSON twin of terminalTicketRecord for the shared NonceStore.
type terminalTicketWire struct {
	PrincipalID   string                 `json:"principal_id"`
	TenantID      string                 `json:"tenant_id"`
	WebSessionID  string                 `json:"web_session_id"`
	StewardID     string                 `json:"steward_id"`
	TerminalShell string                 `json:"terminal_shell"`
	Expires       time.Time              `json:"expires"`
	Targets       []string               `json:"targets"`
	Nonce         string                 `json:"nonce"`
	ExpiresAt     time.Time              `json:"expires_at"`
	X509          *OperatorX509Proof     `json:"x509,omitempty"`
	WebAuthn      *OperatorWebAuthnProof `json:"webauthn,omitempty"`
	Manifest      string                 `json:"manifest,omitempty"`
}

func (r *terminalTicketRecord) toWire() terminalTicketWire {
	return terminalTicketWire{PrincipalID: r.principalID, TenantID: r.tenantID, WebSessionID: r.webSessionID,
		StewardID: r.stewardID, TerminalShell: r.terminalShell, Expires: r.expires, Targets: r.targets,
		Nonce: r.nonce, ExpiresAt: r.expiresAt, X509: r.x509, WebAuthn: r.webAuthn, Manifest: r.manifest}
}

func (w terminalTicketWire) toRecord() *terminalTicketRecord {
	return &terminalTicketRecord{principalID: w.PrincipalID, tenantID: w.TenantID, webSessionID: w.WebSessionID,
		stewardID: w.StewardID, terminalShell: w.TerminalShell, expires: w.Expires, targets: w.Targets,
		nonce: w.Nonce, expiresAt: w.ExpiresAt, x509: w.X509, webAuthn: w.WebAuthn, manifest: w.Manifest}
}

// newTerminalTicket returns a fresh random ticket (base64url) and its storage hash.
func newTerminalTicket() (ticket, ticketHash string, err error) {
	buf := make([]byte, terminalTicketBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	ticket = base64.RawURLEncoding.EncodeToString(buf)
	return ticket, hashTerminalTicket(ticket), nil
}

// hashTerminalTicket returns the hex SHA-256 under which a ticket is stored; the
// plaintext ticket is never stored.
func hashTerminalTicket(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:])
}

// putTerminalTicket stores rec under ticketHash. ceremonyUnavailable means nothing was
// stored (ClusterMode with an unwired or erroring NonceStore).
func (s *Server) putTerminalTicket(ctx context.Context, ticketHash string, rec *terminalTicketRecord) ceremonyOutcome {
	if s.webAuthnClusterMode() {
		return s.putClusterCeremony(ctx, ceremonyPrefixTerminalTicket, ticketHash, rec.toWire(), terminalTicketTTL)
	}
	s.terminalTickets.Store(ticketHash, rec)
	return ceremonyOK
}

// takeTerminalTicket atomically consumes the ticket stored under ticketHash: single use,
// cluster-wide in ClusterMode. An expired node-local record is consumed but not returned;
// the NonceStore enforces the TTL itself in ClusterMode.
func (s *Server) takeTerminalTicket(ctx context.Context, ticketHash string) (*terminalTicketRecord, ceremonyOutcome) {
	if s.webAuthnClusterMode() {
		w, out := takeClusterCeremony[terminalTicketWire](s, ctx, ceremonyPrefixTerminalTicket, ticketHash)
		if out != ceremonyOK {
			return nil, out
		}
		return w.toRecord(), ceremonyOK
	}
	raw, ok := s.terminalTickets.LoadAndDelete(ticketHash)
	if !ok {
		return nil, ceremonyNotFound
	}
	rec, ok := raw.(*terminalTicketRecord)
	if !ok || !time.Now().Before(rec.expires) {
		return nil, ceremonyNotFound
	}
	return rec, ceremonyOK
}
