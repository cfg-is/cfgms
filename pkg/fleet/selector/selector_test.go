// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package selector

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Parser tests ─────────────────────────────────────────────────────────────

func TestParse_Empty_IsRejected(t *testing.T) {
	_, err := Parse("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty selector")
}

func TestParse_Whitespace_IsRejected(t *testing.T) {
	_, err := Parse("   ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty selector")
}

func TestParse_All_ReturnsEmptyFilter(t *testing.T) {
	f, err := Parse("all")
	require.NoError(t, err)
	assert.Equal(t, fleet.Filter{}, f)
}

func TestParse_Name(t *testing.T) {
	f, err := Parse("name:my-server")
	require.NoError(t, err)
	assert.Equal(t, "my-server", f.Hostname)
}

func TestParse_Name_TrailingGlob(t *testing.T) {
	f, err := Parse("name:es-hv0*")
	require.NoError(t, err)
	assert.Equal(t, "es-hv0*", f.Hostname)
}

func TestParse_OS(t *testing.T) {
	f, err := Parse("os:linux")
	require.NoError(t, err)
	assert.Equal(t, "linux", f.OS)
}

func TestParse_OS_Quoted(t *testing.T) {
	f, err := Parse(`os:"windows server"`)
	require.NoError(t, err)
	assert.Equal(t, "windows server", f.OS)
}

func TestParse_Platform(t *testing.T) {
	f, err := Parse("platform:debian")
	require.NoError(t, err)
	assert.Equal(t, "debian", f.Platform)
}

func TestParse_Platform_Quoted(t *testing.T) {
	f, err := Parse(`platform:"ubuntu 22.04"`)
	require.NoError(t, err)
	assert.Equal(t, "ubuntu 22.04", f.Platform)
}

func TestParse_Arch(t *testing.T) {
	f, err := Parse("arch:arm64")
	require.NoError(t, err)
	assert.Equal(t, "arm64", f.Architecture)
}

func TestParse_Tag_Single(t *testing.T) {
	f, err := Parse("tag:prod")
	require.NoError(t, err)
	assert.Equal(t, []string{"prod"}, f.Tags)
}

func TestParse_Tag_Repeatable(t *testing.T) {
	f, err := Parse("tag:prod tag:web tag:db")
	require.NoError(t, err)
	assert.Equal(t, []string{"prod", "web", "db"}, f.Tags)
}

func TestParse_DNAKey(t *testing.T) {
	f, err := Parse("dna.arch:arm64")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"arch": "arm64"}, f.DNAAttributes)
}

func TestParse_DNAKey_Repeatable(t *testing.T) {
	f, err := Parse("dna.zone:us-east dna.tier:premium")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"zone": "us-east", "tier": "premium"}, f.DNAAttributes)
}

func TestParse_DNAKey_Quoted(t *testing.T) {
	f, err := Parse(`dna.label:"web server"`)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"label": "web server"}, f.DNAAttributes)
}

func TestParse_Combined(t *testing.T) {
	f, err := Parse(`name:es-hv0* os:"windows server" tag:prod dna.arch:arm64`)
	require.NoError(t, err)
	assert.Equal(t, "es-hv0*", f.Hostname)
	assert.Equal(t, "windows server", f.OS)
	assert.Equal(t, []string{"prod"}, f.Tags)
	assert.Equal(t, map[string]string{"arch": "arm64"}, f.DNAAttributes)
	assert.Empty(t, f.Platform)
	assert.Empty(t, f.Architecture)
}

func TestParse_UnknownKey_IsError(t *testing.T) {
	_, err := Parse("typo:value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown selector key")
	assert.Contains(t, err.Error(), "typo")
}

func TestParse_MissingColon_IsError(t *testing.T) {
	_, err := Parse("namevalue")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key:value")
}

func TestParse_EmptyDNASubkey_IsError(t *testing.T) {
	_, err := Parse("dna.:value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty DNA attribute key")
}

func TestParse_EmptyValue_IsError(t *testing.T) {
	_, err := Parse("os: name:foo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty value")
}

func TestParse_UnclosedQuote_IsError(t *testing.T) {
	_, err := Parse(`os:"windows server`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated quoted value")
}

func TestParse_KeyWithSpace_IsError(t *testing.T) {
	_, err := Parse("bad key:value")
	require.Error(t, err)
}

// ── Resolution tests ──────────────────────────────────────────────────────────

// staticProvider backs MemoryQuery with a fixed steward list.
type staticProvider struct {
	stewards []fleet.StewardData
}

func (p *staticProvider) GetAllStewards() []fleet.StewardData {
	return p.stewards
}

func makeSteward(id, status string, attrs map[string]string) fleet.StewardData {
	return fleet.StewardData{
		ID:            id,
		TenantID:      "tenant-a",
		Status:        status,
		LastHeartbeat: time.Now(),
		DNAAttributes: attrs,
	}
}

// seedData is the fixed fleet used by all resolution tests.
var seedData = []fleet.StewardData{
	makeSteward("s-linux-arm64", "online", map[string]string{
		"hostname": "es-hv01",
		"os":       "linux",
		"platform": "ubuntu",
		"arch":     "arm64",
		"tags":     "prod,web",
		"zone":     "us-east",
	}),
	makeSteward("s-linux-amd64", "online", map[string]string{
		"hostname": "es-hv02",
		"os":       "linux",
		"platform": "ubuntu",
		"arch":     "amd64",
		"tags":     "prod,db",
		"zone":     "us-east",
	}),
	makeSteward("s-windows", "online", map[string]string{
		"hostname": "win-srv-01",
		"os":       "windows server",
		"platform": "server 2022",
		"arch":     "amd64",
		"tags":     "prod",
		"zone":     "eu-west",
	}),
	makeSteward("s-staging", "offline", map[string]string{
		"hostname": "stage-hv01",
		"os":       "linux",
		"platform": "debian",
		"arch":     "amd64",
		"tags":     "staging",
		"zone":     "us-east",
	}),
}

func resolveIDs(t *testing.T, expr string) []string {
	t.Helper()
	filter, err := Parse(expr)
	require.NoError(t, err)

	q := fleet.NewMemoryQuery(&staticProvider{stewards: seedData})
	results, err := q.Search(context.Background(), filter)
	require.NoError(t, err)

	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.ID
	}
	return ids
}

func TestResolve_All_MatchesEverySteward(t *testing.T) {
	ids := resolveIDs(t, "all")
	assert.Len(t, ids, len(seedData))
}

func TestResolve_NameGlob_MatchesPrefix(t *testing.T) {
	ids := resolveIDs(t, "name:es-hv0*")
	assert.ElementsMatch(t, []string{"s-linux-arm64", "s-linux-amd64"}, ids)
}

func TestResolve_NameGlob_NoMatch(t *testing.T) {
	ids := resolveIDs(t, "name:no-match*")
	assert.Empty(t, ids)
}

func TestResolve_NameExact_SubstringMatch(t *testing.T) {
	ids := resolveIDs(t, "name:win-srv")
	assert.Equal(t, []string{"s-windows"}, ids)
}

func TestResolve_OS_Linux(t *testing.T) {
	ids := resolveIDs(t, "os:linux")
	assert.ElementsMatch(t, []string{"s-linux-arm64", "s-linux-amd64", "s-staging"}, ids)
}

func TestResolve_OS_Quoted(t *testing.T) {
	ids := resolveIDs(t, `os:"windows server"`)
	assert.Equal(t, []string{"s-windows"}, ids)
}

func TestResolve_Arch(t *testing.T) {
	ids := resolveIDs(t, "arch:arm64")
	assert.Equal(t, []string{"s-linux-arm64"}, ids)
}

func TestResolve_Tag(t *testing.T) {
	ids := resolveIDs(t, "tag:prod")
	assert.ElementsMatch(t, []string{"s-linux-arm64", "s-linux-amd64", "s-windows"}, ids)
}

func TestResolve_Tag_Multiple_AND(t *testing.T) {
	ids := resolveIDs(t, "tag:prod tag:web")
	assert.Equal(t, []string{"s-linux-arm64"}, ids)
}

func TestResolve_DNAKey(t *testing.T) {
	ids := resolveIDs(t, "dna.zone:us-east")
	assert.ElementsMatch(t, []string{"s-linux-arm64", "s-linux-amd64", "s-staging"}, ids)
}

func TestResolve_Combined_ExactSteward(t *testing.T) {
	// name glob + os + arch must narrow to exactly one steward.
	ids := resolveIDs(t, "name:es-hv0* os:linux arch:arm64")
	assert.Equal(t, []string{"s-linux-arm64"}, ids)
}
