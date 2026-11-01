// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert_trust

import (
	"context"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestCertTrustModule_Get_LogsAuthenticatedTenant covers Issue #4339: Get must
// read the tenant from the canonical ctxkeys.TenantID context key set by the
// authentication path, not from logging.ExtractTenantFromContext (which reads
// a different, never-written key and always yielded "").
func TestCertTrustModule_Get_LogsAuthenticatedTenant(t *testing.T) {
	const wantTenant = "tenant-cert-trust-4339"

	m := New()
	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("cert_trust module does not implement modules.LoggingInjectable")
	}
	capLog := logging.NewCapturingLogger()
	if err := injectable.SetLogger(capLog); err != nil {
		t.Fatalf("SetLogger failed: %v", err)
	}

	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, wantTenant)

	// A well-formed 64-char hex fingerprint that will not be present in the
	// trust store; that's fine — the tenant tag is logged before the lookup.
	fingerprint := strings.Repeat("a", 64)
	_, _ = m.Get(ctx, fingerprint)

	entry, found := capLog.FindInfo("Getting trust store entry")
	if !found {
		t.Fatal("expected a 'Getting trust store entry' log entry")
	}

	got, _ := entry["tenant_id"].(string)
	if got == "" {
		t.Fatal("tenant_id field is empty; it must carry the authenticated tenant")
	}
	if got != wantTenant {
		t.Fatalf("tenant_id: got %q, want %q", got, wantTenant)
	}
}
