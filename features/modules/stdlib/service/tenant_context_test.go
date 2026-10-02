// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestServiceModule_Get_LogsAuthenticatedTenant covers Issue #4339: Get must
// read the tenant from the canonical ctxkeys.TenantID context key set by the
// authentication path, not from logging.ExtractTenantFromContext (which reads
// a different, never-written key and always yielded "").
func TestServiceModule_Get_LogsAuthenticatedTenant(t *testing.T) {
	const wantTenant = "tenant-service-4339"

	m := New()
	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("service module does not implement modules.LoggingInjectable")
	}
	capLog := logging.NewCapturingLogger()
	if err := injectable.SetLogger(capLog); err != nil {
		t.Fatalf("SetLogger failed: %v", err)
	}

	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, wantTenant)

	// The underlying OS service lookup may fail in a container without an
	// init system; that's fine — the tenant tag is logged before that call.
	_, _ = m.Get(ctx, "cfgms-test-service")

	entry, found := capLog.FindInfo("Getting service state")
	if !found {
		t.Fatal("expected a 'Getting service state' log entry")
	}

	got, _ := entry["tenant_id"].(string)
	if got == "" {
		t.Fatal("tenant_id field is empty; it must carry the authenticated tenant")
	}
	if got != wantTenant {
		t.Fatalf("tenant_id: got %q, want %q", got, wantTenant)
	}
}
