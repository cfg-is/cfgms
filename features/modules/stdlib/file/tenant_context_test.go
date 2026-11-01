// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestFileModule_Set_LogsAuthenticatedTenant covers Issue #4339: setFile must
// read the tenant from the canonical ctxkeys.TenantID context key set by the
// authentication path, not from logging.ExtractTenantFromContext (which reads
// a different, never-written key and always yielded "").
func TestFileModule_Set_LogsAuthenticatedTenant(t *testing.T) {
	const wantTenant = "tenant-file-4339"

	m := New()
	injectable, ok := m.(modules.LoggingInjectable)
	if !ok {
		t.Fatal("file module does not implement modules.LoggingInjectable")
	}
	capLog := logging.NewCapturingLogger()
	if err := injectable.SetLogger(capLog); err != nil {
		t.Fatalf("SetLogger failed: %v", err)
	}

	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, wantTenant)

	cfg := &FileConfig{
		AllowedBasePath: t.TempDir(),
		State:           "absent",
	}
	// The file does not exist; Set() still logs the "Starting file
	// configuration" line, with the tenant tag, before touching the filesystem.
	_ = m.Set(ctx, "does-not-exist.txt", cfg)

	entry, found := capLog.FindInfo("Starting file configuration")
	if !found {
		t.Fatal("expected a 'Starting file configuration' log entry")
	}

	got, _ := entry["tenant_id"].(string)
	if got == "" {
		t.Fatal("tenant_id field is empty; it must carry the authenticated tenant")
	}
	if got != wantTenant {
		t.Fatalf("tenant_id: got %q, want %q", got, wantTenant)
	}
}
