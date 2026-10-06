// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ctxkeys

import (
	"context"
	"testing"
	"time"
)

// TestTenantRestriction guards Issue #4665: only an explicit root scope, or a
// context explicitly marked system-internal, is unrestricted — an empty tenant ID
// never is, and neither is a context that merely carries no caller.
func TestTenantRestriction(t *testing.T) {
	bg := context.Background()
	cases := []struct {
		name             string
		ctx              context.Context
		wantTenant       string
		wantUnrestricted bool
		wantOK           bool
	}{
		{"root scope", context.WithValue(bg, TenantScopeKey, NewRootScope()), "", true, true},
		{"root scope with the root tenant ID", context.WithValue(context.WithValue(bg, TenantID, "acme-root"), TenantScopeKey, NewRootScope()), "", true, true},
		{"tenant scope", context.WithValue(bg, TenantScopeKey, NewTenantScope("acme-corp")), "acme-corp", false, true},
		{"empty-path tenant scope", context.WithValue(bg, TenantScopeKey, NewTenantScope("")), "", false, false},
		{"unset scope", context.WithValue(bg, TenantScopeKey, TenantScope{}), "", false, false},
		{"empty tenant ID, no scope", context.WithValue(bg, TenantID, ""), "", false, false},
		{"tenant ID, no scope", context.WithValue(bg, TenantID, "acme-corp"), "acme-corp", false, true},
		{"no caller and no system mark", bg, "", false, false},
		{"system-internal", WithSystem(bg), "", true, true},
		{"system mark over a caller", WithSystem(context.WithValue(bg, TenantScopeKey, NewTenantScope("acme-corp"))), "", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant, unrestricted, ok := TenantRestriction(tc.ctx)
			if tenant != tc.wantTenant || unrestricted != tc.wantUnrestricted || ok != tc.wantOK {
				t.Fatalf("TenantRestriction = (%q, %v, %v), want (%q, %v, %v)",
					tenant, unrestricted, ok, tc.wantTenant, tc.wantUnrestricted, tc.wantOK)
			}
		})
	}
}

// TestWithSystem guards Issue #4665: a request context marked system-internal
// drops its caller's tenant identity, reads as fleet-wide, and keeps its
// cancellation, deadline and other values.
func TestWithSystem(t *testing.T) {
	type otherKey struct{}
	deadline := time.Now().Add(time.Hour)
	parent, cancel := context.WithDeadline(context.Background(), deadline)
	parent = context.WithValue(parent, TenantID, "acme-corp")
	parent = context.WithValue(parent, TenantScopeKey, NewTenantScope("acme-corp"))
	parent = context.WithValue(parent, otherKey{}, "kept")

	if IsSystem(parent) {
		t.Fatal("an unmarked context must not read as system-internal")
	}
	ctx := WithSystem(parent)
	if !IsSystem(ctx) {
		t.Fatal("WithSystem must mark the context")
	}
	if _, unrestricted, ok := TenantRestriction(ctx); !unrestricted || !ok {
		t.Fatalf("WithSystem context must be system-internal, got unrestricted=%v ok=%v", unrestricted, ok)
	}
	if ctx.Value(TenantID) != nil || ctx.Value(TenantScopeKey) != nil {
		t.Fatal("the caller's tenant identity must be dropped")
	}
	if ctx.Value(otherKey{}) != "kept" {
		t.Fatal("other values must be kept")
	}
	if d, ok := ctx.Deadline(); !ok || !d.Equal(deadline) {
		t.Fatal("the deadline must be kept")
	}
	cancel()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancellation must propagate")
	}
}
