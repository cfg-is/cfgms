// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
)

// principalRefresh re-derives the principal behind a request from the source of truth
// for its credential type (account store, API-key record, certificate binding). It
// returns false when the principal can no longer be established; every uncertain
// outcome fails closed. Called repeatedly, from one goroutine, by long-lived handlers.
type principalRefresh func(ctx context.Context) (*Principal, bool)

// authzRecheck returns a re-check for a long-lived stream authorized for permissionID
// on resourceTenant at open time. Unlike requestAuthRecheck, which tests only that the
// credential is still valid and its account enabled, each call re-derives the current
// principal and re-runs the route's permission and tenant decision, so a removed
// permission or an ended ADR-025 tenant crossing closes the stream. It returns true
// only if the credential re-check passes, the principal refreshes, the principal holds
// permissionID and tenantAccessForScope still allows resourceTenant. A request with no
// recorded credential re-check or refresh gets a re-check that always returns false.
func (s *Server) authzRecheck(r *http.Request, permissionID, resourceTenant, route string) authRecheck {
	live := requestAuthRecheck(r)
	refresh, _ := r.Context().Value(principalRefreshContextKey).(principalRefresh)
	if live == nil || refresh == nil {
		return func(context.Context) bool { return false }
	}
	return func(ctx context.Context) bool {
		if !live(ctx) {
			return false
		}
		principal, ok := refresh(ctx)
		if !ok || principal == nil {
			return false
		}
		if !s.hasPermission(principal, permissionID) {
			return false
		}
		// tenantAccessForScope reads the principal from the context, so the refreshed
		// one must replace the principal the request was opened with.
		ctx = context.WithValue(ctx, principalContextKey, principal)
		ctx = context.WithValue(ctx, ctxkeys.TenantID, principal.TenantID)
		scope := principalTenantScope(principal)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
		return s.tenantAccessForScope(ctx, scope, resourceTenant, route) == tenantAuthAllowed
	}
}

// sessionPrincipalRefresh refreshes a Bearer or web-cookie session principal from the
// account store on every call. sessionRootScoped is the session's own RootScoped marker
// captured at open (always false for a web session, which derives it per request).
func (s *Server) sessionPrincipalRefresh(orig *Principal, sessionRootScoped bool) principalRefresh {
	return func(ctx context.Context) (*Principal, bool) {
		acct, err := s.getAccountByID(ctx, orig.ID)
		if err != nil {
			return nil, false
		}
		if acct == nil {
			if orig.AccountBound {
				return nil, false
			}
			// Unbound session (admin-certificate-derived): nothing to re-derive.
			cp := *orig
			return &cp, true
		}
		if acct.Disabled {
			return nil, false
		}
		p := *orig
		p.TenantID = s.accountPrincipalTenant(ctx, acct)
		p.GlobalScope = acct.RootScope
		p.AuthenticatorCount = len(acct.Credentials)
		p.RootScoped = sessionRootScoped || rootScopeFromAssertion(acct, orig.Assurance)
		p.AccountBound = true
		if acct.RootScope {
			p.ImplicitAdmin = true
			p.Permissions = nil
		} else {
			p.ImplicitAdmin = false
			p.Permissions = append([]string{}, acct.Permissions...)
		}
		return &p, true
	}
}

// adminCertRefresh refreshes an admin-certificate principal from the certificate
// binding. It never records use or emits the bootstrap-fallback audit.
func (s *Server) adminCertRefresh(peerCert *x509.Certificate) principalRefresh {
	return func(ctx context.Context) (*Principal, bool) {
		if time.Now().After(peerCert.NotAfter) {
			return nil, false
		}
		p := s.principalFromAdminCert(ctx, peerCert, false)
		return p, p != nil
	}
}

// apiKeyPrincipal builds the principal for an API key. The key record is the source of
// truth for its permissions and tenant.
func apiKeyPrincipal(keyInfo *APIKey) *Principal {
	return &Principal{
		Channel:     AuthChannelAPIKey,
		ID:          keyInfo.ID,
		Name:        keyInfo.Name,
		Assurance:   session.AssuranceMachine,
		GlobalScope: false,
		Permissions: keyInfo.Permissions,
		TenantID:    keyInfo.TenantID,
	}
}

// apiKeyTracker re-validates an API key against the secret store and holds the last
// confirmed record. A key deleted (on any node) or expired is invalid; a store outage
// keeps the last confirmed record only within apiKeyMaxStaleness of the last
// successful confirmation, matching the per-request policy in authenticationMiddleware.
type apiKeyTracker struct {
	s       *Server
	current *APIKey
	lastOK  time.Time
}

func (s *Server) newAPIKeyTracker(keyInfo *APIKey) *apiKeyTracker {
	lastOK := keyInfo.validatedAt
	if lastOK.IsZero() {
		lastOK = s.apiKeyNow()
	}
	return &apiKeyTracker{s: s, current: keyInfo, lastOK: lastOK}
}

// live reports whether the key is still valid, refreshing the held record on success.
func (t *apiKeyTracker) live(ctx context.Context) bool {
	s := t.s
	now := s.apiKeyNow()
	if t.current.ExpiresAt != nil && now.After(*t.current.ExpiresAt) {
		return false
	}
	if t.current.recordRef == "" {
		// Env-gated test keys have no durable record: valid while still cached.
		s.mu.RLock()
		_, ok := s.apiKeys[t.current.Key]
		s.mu.RUnlock()
		return ok
	}
	refreshed, err := s.revalidateCachedAPIKey(ctx, t.current.Key, t.current, now)
	switch {
	case err == nil:
		t.current, t.lastOK = refreshed, now
		return true
	case errors.Is(err, errAPIKeyRevoked):
		return false
	default:
		return now.Sub(t.lastOK) < apiKeyMaxStaleness
	}
}

// principal is the principal for the last confirmed key record.
func (t *apiKeyTracker) principal() *Principal {
	return apiKeyPrincipal(t.current)
}

// refresh adapts the tracker to a principalRefresh. It relies on live having run first
// (authzRecheck guarantees that order), so it never re-reads the store itself.
func (t *apiKeyTracker) refresh() principalRefresh {
	return func(context.Context) (*Principal, bool) { return t.principal(), true }
}

// apiKeyRecheck is the credential-liveness re-check for an API key.
func (s *Server) apiKeyRecheck(keyInfo *APIKey) authRecheck {
	return s.newAPIKeyTracker(keyInfo).live
}
