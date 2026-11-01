// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestScriptModule_Set_LogsAuthenticatedTenant covers Issue #4339: Set must
// read the tenant from the canonical ctxkeys.TenantID context key set by the
// authentication path, not from logging.ExtractTenantFromContext (which reads
// a different, never-written key and always yielded ""). The audit trail
// (audit.go's LogExecution) already reads ctxkeys.TenantID directly and is
// covered separately by audit_test.go; this test covers the module's own
// log-tag site in Set().
func TestScriptModule_Set_LogsAuthenticatedTenant(t *testing.T) {
	const wantTenant = "tenant-script-4339"

	m := New()
	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("script module does not implement modules.LoggingInjectable")
	}
	capLog := logging.NewCapturingLogger()
	if err := injectable.SetLogger(capLog); err != nil {
		t.Fatalf("SetLogger failed: %v", err)
	}

	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, wantTenant)

	// A nil config is rejected immediately after the tenant tag is logged, so
	// the assertion below never depends on shell availability or execution.
	err := m.Set(ctx, "test-resource", nil)
	if err == nil {
		t.Fatal("expected Set with nil config to return an error")
	}

	entry, found := capLog.FindInfo("Starting script execution")
	if !found {
		t.Fatal("expected a 'Starting script execution' log entry")
	}

	got, _ := entry["tenant_id"].(string)
	if got == "" {
		t.Fatal("tenant_id field is empty; it must carry the authenticated tenant")
	}
	if got != wantTenant {
		t.Fatalf("tenant_id: got %q, want %q", got, wantTenant)
	}
}
