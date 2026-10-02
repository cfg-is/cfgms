// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package acme

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestACMEModule_Set_LogsAuthenticatedTenant covers Issue #4339: Set must
// read the tenant from the canonical ctxkeys.TenantID context key set by the
// authentication path, not from logging.ExtractTenantFromContext (which reads
// a different, never-written key and always yielded "").
func TestACMEModule_Set_LogsAuthenticatedTenant(t *testing.T) {
	const wantTenant = "tenant-acme-4339"

	m := New()
	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("acme module does not implement modules.LoggingInjectable")
	}
	capLog := logging.NewCapturingLogger()
	if err := injectable.SetLogger(capLog); err != nil {
		t.Fatalf("SetLogger failed: %v", err)
	}

	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, wantTenant)

	// State "absent" validates trivially and short-circuits before any
	// network/ACME activity, once the tenant tag has already been logged.
	cfg := &ACMEConfig{State: "absent", CertStorePath: t.TempDir()}
	_ = m.Set(ctx, "example.com", cfg)

	entry, found := capLog.FindInfo("Setting ACME certificate state")
	if !found {
		t.Fatal("expected a 'Setting ACME certificate state' log entry")
	}

	got, _ := entry["tenant_id"].(string)
	if got == "" {
		t.Fatal("tenant_id field is empty; it must carry the authenticated tenant")
	}
	if got != wantTenant {
		t.Fatalf("tenant_id: got %q, want %q", got, wantTenant)
	}
}
