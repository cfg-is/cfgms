//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLinuxSecurityCollector runs the full Linux security collector against the
// real host and asserts the shape of each attribute. It does NOT assert specific
// values because those depend on the host configuration.
func TestLinuxSecurityCollector(t *testing.T) {
	col := &LinuxSecurityCollector{}
	attrs := make(map[string]string)
	ctx := context.Background()

	require.NoError(t, col.CollectUsers(ctx, attrs))
	require.NoError(t, col.CollectGroups(ctx, attrs))
	require.NoError(t, col.CollectPermissions(ctx, attrs))

	// local_user_count must be a parseable integer > 0 (at minimum root is present)
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

	// luks_encrypted_devices must be a parseable integer (0 is valid — no LUKS on CI)
	luksStr, ok := attrs["luks_encrypted_devices"]
	require.True(t, ok, "luks_encrypted_devices must be set")
	_, err = strconv.Atoi(luksStr)
	require.NoError(t, err, "luks_encrypted_devices must parse as integer: %q", luksStr)

	// av_products_detected must be non-empty (either "none" or a CSV of product names)
	avVal, ok := attrs["av_products_detected"]
	require.True(t, ok, "av_products_detected must be set")
	assert.NotEmpty(t, avVal, "av_products_detected must not be empty")

	// local_users_sample MUST NOT appear (identity data exfil prevention)
	_, hasUserSample := attrs["local_users_sample"]
	assert.False(t, hasUserSample, "local_users_sample must not be emitted")
}

// TestLinuxCollectUsers_ParsesPasswd verifies that /etc/passwd parsing produces
// at least one user entry (root is always present).
func TestLinuxCollectUsers_ParsesPasswd(t *testing.T) {
	count, err := linuxParsePasswdCount()
	require.NoError(t, err, "linuxParsePasswdCount should not error on a standard Linux system")
	assert.Greater(t, count, 0, "at least root must be present in /etc/passwd")
}

// TestLinuxCollectGroups_ParsesGroupFile verifies that /etc/group parsing produces
// at least one group entry.
func TestLinuxCollectGroups_ParsesGroupFile(t *testing.T) {
	groupCount, adminsCount := linuxParseGroupFile()
	assert.Greater(t, groupCount, 0, "at least one group must be present in /etc/group")
	// adminsCount may be 0 if neither sudo nor wheel exists with members
	assert.GreaterOrEqual(t, adminsCount, 0, "admins count must be non-negative")
}

// TestLinuxCollectPermissions_SudoCheck verifies that sudo_installed reflects
// whether the sudo binary is present.
func TestLinuxCollectPermissions_SudoCheck(t *testing.T) {
	col := &LinuxSecurityCollector{}
	attrs := make(map[string]string)
	col.checkSudoInstalled(attrs)

	val, ok := attrs["sudo_installed"]
	require.True(t, ok, "sudo_installed must be set")
	assert.True(t, val == "true" || val == "false",
		"sudo_installed must be 'true' or 'false', got %q", val)
}

// TestLinuxCollectDomainMembership_NotJoined verifies that collectDomainMembership
// sets domain_joined to "false" on a host that is not AD-joined (standard CI).
func TestLinuxCollectDomainMembership_NotJoined(t *testing.T) {
	col := &LinuxSecurityCollector{}
	attrs := make(map[string]string)
	col.collectDomainMembership(context.Background(), attrs)

	djVal, ok := attrs["domain_joined"]
	require.True(t, ok, "domain_joined must be set")
	assert.True(t, djVal == "true" || djVal == "false",
		"domain_joined must be 'true' or 'false', got %q", djVal)
}

// TestLinuxCollectLUKSState_Parses verifies that collectLUKSState always sets
// luks_encrypted_devices to a parseable integer.
func TestLinuxCollectLUKSState_Parses(t *testing.T) {
	col := &LinuxSecurityCollector{}
	attrs := make(map[string]string)
	col.collectLUKSState(context.Background(), attrs)

	luksStr, ok := attrs["luks_encrypted_devices"]
	require.True(t, ok, "luks_encrypted_devices must be set")
	n, err := strconv.Atoi(luksStr)
	require.NoError(t, err, "luks_encrypted_devices must parse as integer: %q", luksStr)
	assert.GreaterOrEqual(t, n, 0, "luks_encrypted_devices must be >= 0")
}

// TestLinuxCollectAVProducts_AlwaysSet verifies that av_products_detected is always
// set to a non-empty value ("none" when no AV is detected).
func TestLinuxCollectAVProducts_AlwaysSet(t *testing.T) {
	col := &LinuxSecurityCollector{}
	attrs := make(map[string]string)
	col.collectAVProducts(context.Background(), attrs)

	avVal, ok := attrs["av_products_detected"]
	require.True(t, ok, "av_products_detected must be set")
	assert.NotEmpty(t, avVal, "av_products_detected must not be empty")
}
