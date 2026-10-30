//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/cfgis/cfgms/pkg/testutil/winacct"
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
	// The PowerShell fallbacks stage scripts in an admin-only base (#5628).
	stagingBaseOwnedBy(t, "O:BA")
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
	// The PowerShell fallbacks stage scripts in an admin-only base (#5628).
	stagingBaseOwnedBy(t, "O:BA")
	count := winCountLocalUsers(context.Background())
	assert.Greater(t, count, 0, "winCountLocalUsers must return > 0 on any live Windows host")
}

// TestWinCountLocalGroups exercises winCountLocalGroups against the live host.
// On CI runners where wmic is absent, this specifically validates the PowerShell fallback.
func TestWinCountLocalGroups(t *testing.T) {
	// The PowerShell fallbacks stage scripts in an admin-only base (#5628).
	stagingBaseOwnedBy(t, "O:BA")
	count := winCountLocalGroups(context.Background())
	assert.Greater(t, count, 0, "winCountLocalGroups must return > 0 on any live Windows host")
}

// TestWindowsCollectAVProducts verifies that collectAVProducts sets av_products_detected
// to a real product name on workstation SKU and "none" on server SKU.
func TestWindowsCollectAVProducts(t *testing.T) {
	// The PowerShell fallbacks stage scripts in an admin-only base (#5628).
	stagingBaseOwnedBy(t, "O:BA")
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

// requireElevated skips t unless the test runs elevated. Securing the DNA
// staging base assigns BUILTIN\Administrators as owner, and the tests hand
// directories to other principals; both need an elevated administrator, as
// the steward (a SYSTEM service) and the native Windows CI runners are.
func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator: securing the DNA staging base assigns BUILTIN\\Administrators as owner")
	}
}

// stagingBaseOwnedBy creates a staging base under t.TempDir() owned by the
// owner in sddl (e.g. "O:BA") and points dnaStagingBase at it for the test.
func stagingBaseOwnedBy(t *testing.T, sddl string) string {
	t.Helper()
	requireElevated(t)
	base := filepath.Join(t.TempDir(), "dna-staging")
	require.NoError(t, os.Mkdir(base, 0o700))
	sd, err := windows.SecurityDescriptorFromString(sddl)
	require.NoError(t, err)
	owner, _, err := sd.Owner()
	require.NoError(t, err)
	winacct.SetOwner(t, base, owner)

	prev := dnaStagingBase
	dnaStagingBase = base
	t.Cleanup(func() { dnaStagingBase = prev })
	return base
}

// powerShellCall is what a recording runSecurityCommand saw.
type powerShellCall struct {
	file       string
	fileExists bool
}

// recordPowerShell replaces runSecurityCommand with a recorder that captures
// the -File argument, whether that file existed when PowerShell would have
// read it, and returns output. PowerShell never runs.
func recordPowerShell(t *testing.T, output string) *[]powerShellCall {
	t.Helper()
	var calls []powerShellCall
	prev := runSecurityCommand
	runSecurityCommand = func(_ context.Context, name string, args ...string) (string, error) {
		call := powerShellCall{}
		for i, a := range args {
			if a == "-File" && i+1 < len(args) {
				call.file = args[i+1]
				_, err := os.Stat(call.file)
				call.fileExists = err == nil
			}
		}
		calls = append(calls, call)
		return output, nil
	}
	t.Cleanup(func() { runSecurityCommand = prev })
	return &calls
}

// isUnderDir reports whether path lies inside dir, ignoring case.
func isUnderDir(path, dir string) bool {
	return strings.HasPrefix(strings.ToLower(filepath.Clean(path)),
		strings.ToLower(filepath.Clean(dir))+string(filepath.Separator))
}

// TestSecurityCollectors_StageScriptsInAdminOnlyBase (REQUIRED, #5628):
// collectAVProducts and winPowerShellCount pass a -File path whose parent is
// the configured staging base and which is not under os.TempDir().
func TestSecurityCollectors_StageScriptsInAdminOnlyBase(t *testing.T) {
	base := stagingBaseOwnedBy(t, "O:BA")
	// Move the system temporary directory elsewhere so a regression to
	// os.CreateTemp("", ...) would stage there and fail the assertions.
	fakeTemp := filepath.Join(t.TempDir(), "system-temp")
	require.NoError(t, os.Mkdir(fakeTemp, 0o700))
	t.Setenv("TMP", fakeTemp)
	t.Setenv("TEMP", fakeTemp)
	require.True(t, strings.EqualFold(filepath.Clean(os.TempDir()), filepath.Clean(fakeTemp)))

	calls := recordPowerShell(t, "7")

	attrs := map[string]string{}
	(&WindowsSecurityCollector{}).collectAVProducts(context.Background(), attrs)
	assert.Equal(t, "7", attrs["av_products_detected"])
	assert.Equal(t, 7, winPowerShellCount(context.Background(), "dna-users-*.ps1", `(Get-LocalUser).Count`))

	require.Len(t, *calls, 2)
	for _, c := range *calls {
		assert.True(t, strings.EqualFold(filepath.Dir(c.file), base),
			"staged script %q must be directly in the staging base %q", c.file, base)
		assert.False(t, isUnderDir(c.file, os.TempDir()),
			"staged script %q must not be under the system temporary directory", c.file)
		assert.True(t, c.fileExists, "the staged script must exist when PowerShell runs")
	}
}

// TestSecurityCollectors_RefuseBaseOwnedByUsers (REQUIRED, #5628): with a
// staging base owned by BUILTIN\Users, EnsureAdminOnlyDir refuses it, so
// PowerShell never runs and the collectors return their fallback values.
func TestSecurityCollectors_RefuseBaseOwnedByUsers(t *testing.T) {
	base := stagingBaseOwnedBy(t, "O:BU")
	calls := recordPowerShell(t, "7")

	attrs := map[string]string{}
	(&WindowsSecurityCollector{}).collectAVProducts(context.Background(), attrs)
	assert.Equal(t, "none", attrs["av_products_detected"])
	assert.Equal(t, 0, winPowerShellCount(context.Background(), "dna-groups-*.ps1", `(Get-LocalGroup).Count`))

	assert.Empty(t, *calls, "PowerShell must not run when the staging base cannot be secured")
	entries, err := os.ReadDir(base)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing may be staged in a refused base")
}

// TestSecurityCollectors_RemoveStagedScriptAfterRun (REQUIRED, #5628): after a
// successful run the staged file no longer exists in the staging base.
func TestSecurityCollectors_RemoveStagedScriptAfterRun(t *testing.T) {
	base := stagingBaseOwnedBy(t, "O:BA")
	calls := recordPowerShell(t, "3")

	attrs := map[string]string{}
	(&WindowsSecurityCollector{}).collectAVProducts(context.Background(), attrs)
	assert.Equal(t, 3, winPowerShellCount(context.Background(), "dna-users-*.ps1", `(Get-LocalUser).Count`))

	require.Len(t, *calls, 2)
	for _, c := range *calls {
		_, err := os.Stat(c.file)
		assert.True(t, os.IsNotExist(err), "staged script %q must be removed after the run", c.file)
	}
	entries, err := os.ReadDir(base)
	require.NoError(t, err)
	assert.Empty(t, entries, "the staging base must be empty after the runs")
}

func TestDefaultDNAStagingBase(t *testing.T) {
	t.Setenv("ProgramData", `D:\PD`)
	assert.Equal(t, `D:\PD\cfgms\dna-staging`, defaultDNAStagingBase())
	t.Setenv("ProgramData", "")
	assert.Equal(t, `C:\ProgramData\cfgms\dna-staging`, defaultDNAStagingBase())
}
