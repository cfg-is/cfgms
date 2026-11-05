// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlstore

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func openPolicyDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`CREATE TABLE p (tenant_id TEXT, permission_id TEXT, min_override INTEGER, require_user_presence BOOLEAN);
		INSERT INTO p VALUES ('a','x',2,1),('a','y',NULL,0),('b','z',1,0)`)
	require.NoError(t, err)
	return db
}

const policyQuery = `SELECT permission_id, min_override, require_user_presence FROM p WHERE tenant_id = ?`

var testLabels = PolicyLabels{Prefix: "test: ", Noun: "assurance policy"}

func TestGetPolicy_FoundNotFoundAndScoping(t *testing.T) {
	db := openPolicyDB(t)
	ctx := context.Background()

	a, err := GetPolicy(ctx, db, policyQuery, "a", testLabels, ScanAssuranceOverride, BuildAssurancePolicy)
	require.NoError(t, err)
	assert.Equal(t, "a", a.TenantID)
	require.Len(t, a.Overrides, 2)
	require.NotNil(t, a.Overrides[0].MinOverride)
	assert.Equal(t, 2, *a.Overrides[0].MinOverride)
	assert.True(t, a.Overrides[0].RequireUserPresence)
	assert.Nil(t, a.Overrides[1].MinOverride)

	none, err := GetPolicy(ctx, db, policyQuery, "zz", testLabels, ScanAssuranceOverride, BuildAssurancePolicy)
	require.NoError(t, err)
	assert.Equal(t, "zz", none.TenantID)
	assert.Nil(t, none.Overrides)
}

// TestGetPolicy_GenericOverPolicyType proves the helper is not tied to the assurance policy.
func TestGetPolicy_GenericOverPolicyType(t *testing.T) {
	db := openPolicyDB(t)
	type other struct {
		Tenant string
		IDs    []string
	}
	got, err := GetPolicy(context.Background(), db, `SELECT permission_id FROM p WHERE tenant_id = ?`, "a",
		PolicyLabels{Noun: "other policy"},
		func(r *sql.Rows) (string, error) { var s string; return s, r.Scan(&s) },
		func(tenant string, ids []string) *other { return &other{Tenant: tenant, IDs: ids} })
	require.NoError(t, err)
	assert.Equal(t, &other{Tenant: "a", IDs: []string{"x", "y"}}, got)
}

func TestGetPolicy_ErrorText(t *testing.T) {
	db := openPolicyDB(t)
	ctx := context.Background()

	_, err := GetPolicy(ctx, db, `SELECT nope FROM p WHERE tenant_id = ?`, "a", testLabels, ScanAssuranceOverride, BuildAssurancePolicy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test: failed to get assurance policy for tenant a: ")

	// A one-column result cannot be scanned into three destinations.
	_, err = GetPolicy(ctx, db, `SELECT permission_id FROM p WHERE tenant_id = ?`, "a", testLabels, ScanAssuranceOverride, BuildAssurancePolicy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test: failed to scan assurance policy row for tenant a: ")
}

func TestBuildAssurancePolicy(t *testing.T) {
	p := BuildAssurancePolicy("t", []business.AssurancePolicyOverride{{PermissionID: "x"}})
	assert.Equal(t, "t", p.TenantID)
	assert.Len(t, p.Overrides, 1)
}
