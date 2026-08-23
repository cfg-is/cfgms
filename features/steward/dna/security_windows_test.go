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
	defer func() { _ = key.Close() }()

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

	// local_group_count must be a parseable integer > 0
	groupCountStr, ok := attrs["local_group_count"]
	require.True(t, ok, "local_group_count must be set")
	groupCount, err := strconv.Atoi(groupCountStr)
	require.NoError(t, err, "local_group_count must parse as integer: %q", groupCountStr)
	assert.Greater(t, groupCount, 0, "local_group_count must be > 0")

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

// TestWinCountWMICRows verifies the wmic output row counter.
func TestWinCountWMICRows(t *testing.T) {
	// Header + 2 data rows + blank trailing line (typical wmic output)
	sample := "Name  \r\nAdministrator  \r\nrunneradmin  \r\n\r\n"
	assert.Equal(t, 2, winCountWMICRows(sample), "should count 2 data rows")

	assert.Equal(t, 0, winCountWMICRows(""), "empty output should yield 0")

	// Header only — wmic returned no matching accounts
	assert.Equal(t, 0, winCountWMICRows("Name  \r\n\r\n"), "header-only output should yield 0")
}

// TestWinCountNetLocalgroupMembers verifies the "net localgroup <name>" member counter.
func TestWinCountNetLocalgroupMembers(t *testing.T) {
	sample := "Alias name     Administrators\r\n" +
		"Comment        \r\n\r\n" +
		"Members\r\n\r\n" +
		"------------------------\r\n" +
		"Administrator\r\n" +
		"runneradmin\r\n" +
		"The command completed successfully.\r\n"
	assert.Equal(t, 2, winCountNetLocalgroupMembers(sample), "should count 2 members")

	// Non-English locale — French completion message ends in period, not "The command"
	frenchSample := "Nom d'alias     Administrateurs\r\n\r\n" +
		"Membres\r\n\r\n" +
		"------------------------\r\n" +
		"Administrator\r\n" +
		"La commande s'est terminée correctement.\r\n"
	assert.Equal(t, 1, winCountNetLocalgroupMembers(frenchSample), "should handle non-English locale")

	// Zero members
	emptyGroup := "Alias name     Guests\r\n\r\n" +
		"Members\r\n\r\n" +
		"------------------------\r\n" +
		"The command completed successfully.\r\n"
	assert.Equal(t, 0, winCountNetLocalgroupMembers(emptyGroup), "empty group should yield 0")
}

// TestWinCountLocalUsers exercises winCountLocalUsers against the live host.
// On CI runners where wmic is absent, this specifically validates the PowerShell fallback.
func TestWinCountLocalUsers(t *testing.T) {
	count := winCountLocalUsers(context.Background())
	assert.Greater(t, count, 0, "winCountLocalUsers must return > 0 on any live Windows host")
}

// TestWinCountLocalGroups exercises winCountLocalGroups against the live host.
// On CI runners where wmic is absent, this specifically validates the PowerShell fallback.
func TestWinCountLocalGroups(t *testing.T) {
	count := winCountLocalGroups(context.Background())
	assert.Greater(t, count, 0, "winCountLocalGroups must return > 0 on any live Windows host")
}

// TestWindowsCollectAVProducts verifies that collectAVProducts sets av_products_detected
// to a real product name on workstation SKU and "none" on server SKU.
func TestWindowsCollectAVProducts(t *testing.T) {
	col := &WindowsSecurityCollector{}
	attrs := make(map[string]string)

	col.collectAVProducts(context.Background(), attrs)

	avVal, ok := attrs["av_products_detected"]
	require.True(t, ok, "av_products_detected must be set")
	if isWorkstationSKU() {
		// Windows Defender is always registered in root/SecurityCenter2 on workstation SKU.
		assert.NotEqual(t, "none", avVal,
			"av_products_detected must be a product name on workstation SKU, got %q", avVal)
	} else {
		// root/SecurityCenter2 is not available on server SKU — expect "none".
		assert.Equal(t, "none", avVal,
			"av_products_detected must be 'none' on server SKU, got %q", avVal)
	}
}
