// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tenant

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestGenerateBillingLabel_FormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		l, err := GenerateBillingLabel()
		require.NoError(t, err)
		assert.True(t, ValidBillingLabel(l), "generated label %q must validate", l)
		assert.True(t, strings.HasPrefix(l, "bl-"))
		assert.GreaterOrEqual(t, len(strings.TrimPrefix(l, "bl-")), 16, "at least 80 bits of base32")
		assert.False(t, seen[l], "labels must not repeat")
		seen[l] = true
	}
}

func TestValidBillingLabel(t *testing.T) {
	assert.True(t, ValidBillingLabel("bl-abcdefghij234567"))
	assert.True(t, ValidBillingLabel("bl-0123456789abcdef0123")) // migration-written hex form
	for _, bad := range []string{"", "bl-", "bl-short", "abcdefghij234567abcd", "bl-ABCDEFGHIJ234567", "bl-abcdefghij23456_", "bl-abcdefghij23456 7"} {
		assert.False(t, ValidBillingLabel(bad), "%q must be rejected", bad)
	}
}

// TestBillingLabelSource asserts the generator draws only from crypto/rand and
// imports no math/rand, crypto/sha* or crypto/hmac (nothing derived).
func TestBillingLabelSource(t *testing.T) {
	src, err := os.ReadFile("billing_label.go")
	require.NoError(t, err)
	s := string(src)
	assert.Contains(t, s, `"crypto/rand"`)
	for _, banned := range []string{`"math/rand`, `"crypto/sha`, `"crypto/hmac"`, `"crypto/md5"`} {
		assert.NotContains(t, s, banned)
	}
}

func TestCreateTenant_BillingLabelNotDerived(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()

	a, err := m.CreateTenant(ctx, &TenantRequest{ID: "acme-one", Name: "acme-corp", ParentID: testRootTenantID})
	require.NoError(t, err)
	b, err := m.CreateTenant(ctx, &TenantRequest{ID: "acme-two", Name: "acme-corp", ParentID: testRootTenantID})
	require.NoError(t, err)

	assert.True(t, ValidBillingLabel(a.BillingLabel))
	assert.True(t, ValidBillingLabel(b.BillingLabel))
	assert.NotEqual(t, a.BillingLabel, b.BillingLabel, "same name must not give the same label")
	for _, td := range []*business.TenantData{a, b} {
		assert.NotContains(t, td.BillingLabel, "acme")
		assert.NotContains(t, td.BillingLabel, td.ID)
	}

	stored, err := m.store.GetTenant(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a.BillingLabel, stored.BillingLabel, "label is persisted")
}

func TestUpdateAndSuspend_CarryBillingLabel(t *testing.T) {
	m := newTestTenantManager(t)
	ctx := context.Background()

	created, err := m.CreateTenant(ctx, &TenantRequest{ID: "carry-parent", Name: "Carry", ParentID: testRootTenantID})
	require.NoError(t, err)
	child, err := m.CreateTenant(ctx, &TenantRequest{ID: "carry-child", Name: "Child", ParentID: "carry-parent"})
	require.NoError(t, err)

	_, err = m.UpdateTenant(ctx, "carry-parent", &TenantRequest{Name: "Renamed", Description: "d"})
	require.NoError(t, err)
	_, err = m.SuspendTenant(ctx, "carry-parent")
	require.NoError(t, err)

	got, err := m.store.GetTenant(ctx, "carry-parent")
	require.NoError(t, err)
	assert.Equal(t, created.BillingLabel, got.BillingLabel)
	gotChild, err := m.store.GetTenant(ctx, "carry-child")
	require.NoError(t, err)
	assert.Equal(t, child.BillingLabel, gotChild.BillingLabel, "cascade suspend keeps the child's label")
}

func TestTenantDataJSONOmitsBillingLabel(t *testing.T) {
	raw, err := json.Marshal(&business.TenantData{ID: "x", Name: "X", BillingLabel: "bl-secretsecretsecret"})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "bl-secret")
	assert.NotContains(t, string(raw), "billing_label")
	assert.NotContains(t, string(raw), "BillingLabel")
}
