//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
)

// isWorkstationSKU returns true when the host is a Windows workstation (ProductType=WinNT).
// Domain Controllers (LanmanNT) and servers (ServerNT) are not workstations.
// Root/SecurityCenter2 only returns AV products on workstations, so tests that
// assert non-empty AV data must skip on non-workstation SKUs.
func isWorkstationSKU() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\ProductOptions`,
		registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	productType, _, err := key.GetStringValue("ProductType")
	if err != nil {
		return false
	}
	return strings.EqualFold(productType, "WinNT")
}

// TestWindowsSecurityCollector runs the full Windows security collector against
// the real host and asserts the shape of each emitted attribute.
func TestWindowsSecurityCollector(t *testing.T) {
	col := &WindowsSecurityCollector{}
	attrs := make(map[string]string)
	ctx := context.Background()

	require.NoError(t, col.CollectUsers(ctx, attrs))
	require.NoError(t, col.CollectGroups(ctx, attrs))
	require.NoError(t, col.CollectPermissions(ctx, attrs))

	// local_user_count must be a parseable integer > 0
	countStr, ok := attrs["local_user_count"]
	require.True(t, ok, "local_user_count must be set")
	count, err := strconv.Atoi(countStr)
	require.NoError(t, err, "local_user_count must parse as integer: %q", countStr)
	assert.Greater(t, count, 0, "local_user_count must be > 0")

	// domain_joined must be exactly "true" or "false"
	djVal, ok := attrs["domain_joined"]
	require.True(t, ok, "domain_joined must be set")
	assert.True(t, djVal == "true" || djVal == "false",
		"domain_joined must be 'true' or 'false', got %q", djVal)

	// bitlocker_enabled must be exactly "true" or "false"
	blVal, ok := attrs["bitlocker_enabled"]
	require.True(t, ok, "bitlocker_enabled must be set")
	assert.True(t, blVal == "true" || blVal == "false",
		"bitlocker_enabled must be 'true' or 'false', got %q", blVal)

	// av_products_detected: must be non-empty on workstation SKU.
	// Server SKU may return "none" because root/SecurityCenter2 returns empty there.
	avVal, ok := attrs["av_products_detected"]
	require.True(t, ok, "av_products_detected must be set")
	if isWorkstationSKU() {
		assert.NotEmpty(t, avVal, "av_products_detected must not be empty on workstation SKU")
	} else {
		// On server SKU, "none" is the expected value
		assert.Equal(t, "none", avVal, "av_products_detected should be 'none' on server SKU")
	}

	// local_admins_sample MUST NOT appear (identity data exfil prevention)
	_, hasAdminSample := attrs["local_admins_sample"]
	assert.False(t, hasAdminSample, "local_admins_sample must not be emitted")
}

// TestCollectCertificates_NoPrivateKeyMaterial asserts that no attribute value
// returned by CollectCertificates contains private-key PEM headers.
func TestCollectCertificates_NoPrivateKeyMaterial(t *testing.T) {
	col := &WindowsSecurityCollector{}
	attrs := make(map[string]string)

	require.NoError(t, col.CollectCertificates(context.Background(), attrs))

	privateKeyMarkers := []string{
		"BEGIN RSA PRIVATE KEY",
		"BEGIN PRIVATE KEY",
		"BEGIN EC PRIVATE KEY",
		"BEGIN ENCRYPTED PRIVATE KEY",
		"BEGIN DSA PRIVATE KEY",
		"PRIVATE KEY",
	}

	for k, v := range attrs {
		for _, marker := range privateKeyMarkers {
			assert.NotContains(t, v, marker,
				"attribute %q must not contain private-key PEM header %q", k, marker)
		}
	}
}

// TestWindowsCollectDomainMembership verifies that collectDomainMembership always
// sets domain_joined to "true" or "false".
func TestWindowsCollectDomainMembership(t *testing.T) {
	col := &WindowsSecurityCollector{}
	attrs := make(map[string]string)

	col.collectDomainMembership(attrs)

	djVal, ok := attrs["domain_joined"]
	require.True(t, ok, "domain_joined must be set")
	assert.True(t, djVal == "true" || djVal == "false",
		"domain_joined must be 'true' or 'false', got %q", djVal)
}

// TestWindowsCollectBitLocker verifies that collectBitLockerState always sets
// bitlocker_enabled to "true" or "false".
func TestWindowsCollectBitLocker(t *testing.T) {
	col := &WindowsSecurityCollector{}
	attrs := make(map[string]string)

	col.collectBitLockerState(context.Background(), attrs)

	blVal, ok := attrs["bitlocker_enabled"]
	require.True(t, ok, "bitlocker_enabled must be set")
	assert.True(t, blVal == "true" || blVal == "false",
		"bitlocker_enabled must be 'true' or 'false', got %q", blVal)
}

// TestWindowsCollectAVProducts verifies that collectAVProducts always sets
// av_products_detected to a non-empty value.
func TestWindowsCollectAVProducts(t *testing.T) {
	col := &WindowsSecurityCollector{}
	attrs := make(map[string]string)

	col.collectAVProducts(context.Background(), attrs)

	avVal, ok := attrs["av_products_detected"]
	require.True(t, ok, "av_products_detected must be set")
	assert.NotEmpty(t, avVal, "av_products_detected must not be empty string")
}
