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
	_, _, err := Parse("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty selector")
}

func TestParse_Whitespace_IsRejected(t *testing.T) {
	_, _, err := Parse("   ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty selector")
}

func TestParse_All_ReturnsEmptyFilter(t *testing.T) {
	f, tp, err := Parse("all")
	require.NoError(t, err)
	assert.Equal(t, fleet.Filter{}, f)
	assert.Empty(t, tp)
}

func TestParse_Name(t *testing.T) {
	f, _, err := Parse("name:my-server")
	require.NoError(t, err)
	assert.Equal(t, "my-server", f.Name)
}

func TestParse_Name_TrailingGlob(t *testing.T) {
	f, _, err := Parse("name:es-hv0*")
	require.NoError(t, err)
	assert.Equal(t, "es-hv0*", f.Name)
}

func TestParse_Name_LeadingGlob(t *testing.T) {
	f, _, err := Parse("name:*web")
	require.NoError(t, err)
	assert.Equal(t, "*web", f.Name)
}

func TestParse_Name_MidStringGlob(t *testing.T) {
	f, _, err := Parse("name:web*1")
	require.NoError(t, err)
	assert.Equal(t, "web*1", f.Name)
}

func TestParse_OS(t *testing.T) {
	f, _, err := Parse("os:linux")
	require.NoError(t, err)
	assert.Equal(t, "linux", f.OS)
}

func TestParse_OS_Quoted(t *testing.T) {
	f, _, err := Parse(`os:"windows server"`)
	require.NoError(t, err)
	assert.Equal(t, "windows server", f.OS)
}

func TestParse_Platform(t *testing.T) {
	f, _, err := Parse("platform:debian")
	require.NoError(t, err)
	assert.Equal(t, "debian", f.Platform)
}

func TestParse_Platform_Quoted(t *testing.T) {
	f, _, err := Parse(`platform:"ubuntu 22.04"`)
	require.NoError(t, err)
	assert.Equal(t, "ubuntu 22.04", f.Platform)
}

func TestParse_Arch(t *testing.T) {
	f, _, err := Parse("arch:arm64")
	require.NoError(t, err)
	assert.Equal(t, "arm64", f.Architecture)
}

func TestParse_Tag_Single(t *testing.T) {
	f, _, err := Parse("tag:prod")
	require.NoError(t, err)
	assert.Equal(t, []string{"prod"}, f.Tags)
}

func TestParse_Tag_Repeatable(t *testing.T) {
	f, _, err := Parse("tag:prod tag:web tag:db")
	require.NoError(t, err)
	assert.Equal(t, []string{"prod", "web", "db"}, f.Tags)
}

func TestParse_DNAKey(t *testing.T) {
	f, _, err := Parse("dna.arch:arm64")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"arch": "arm64"}, f.DNAAttributes)
}

func TestParse_DNAKey_Repeatable(t *testing.T) {
	f, _, err := Parse("dna.zone:us-east dna.tier:premium")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"zone": "us-east", "tier": "premium"}, f.DNAAttributes)
}

func TestParse_DNAKey_Quoted(t *testing.T) {
	f, _, err := Parse(`dna.label:"web server"`)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"label": "web server"}, f.DNAAttributes)
}

func TestParse_Combined(t *testing.T) {
	f, _, err := Parse(`name:es-hv0* os:"windows server" tag:prod dna.arch:arm64`)
	require.NoError(t, err)
	assert.Equal(t, "es-hv0*", f.Name)
	assert.Equal(t, "windows server", f.OS)
	assert.Equal(t, []string{"prod"}, f.Tags)
	assert.Equal(t, map[string]string{"arch": "arm64"}, f.DNAAttributes)
	assert.Empty(t, f.Platform)
	assert.Empty(t, f.Architecture)
}

func TestParse_UnknownKey_IsError(t *testing.T) {
	_, _, err := Parse("typo:value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown selector key")
	assert.Contains(t, err.Error(), "typo")
}

func TestParse_BareToken_ParsesAsNameExact(t *testing.T) {
	// A token without key: syntax maps to an implicit name: term (bare hostname match).
	f, _, err := Parse("namevalue")
	require.NoError(t, err)
	assert.Equal(t, "namevalue", f.Name)
}

func TestParse_BareToken_Glob_ParsesAsNameGlob(t *testing.T) {
	f, _, err := Parse("web*")
	require.NoError(t, err)
	assert.Equal(t, "web*", f.Name)
}

func TestParse_BareToken_Combined_BeforeKeyedTerm(t *testing.T) {
	f, _, err := Parse("web os:linux")
	require.NoError(t, err)
	assert.Equal(t, "web", f.Name)
	assert.Equal(t, "linux", f.OS)
}

func TestParse_BareToken_Combined_AfterKeyedTerm(t *testing.T) {
	f, _, err := Parse("os:linux web")
	require.NoError(t, err)
	assert.Equal(t, "linux", f.OS)
	assert.Equal(t, "web", f.Name)
}

func TestParse_EmptyDNASubkey_IsError(t *testing.T) {
	_, _, err := Parse("dna.:value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty DNA attribute key")
}

func TestParse_EmptyValue_IsError(t *testing.T) {
	_, _, err := Parse("os: name:foo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty value")
}

func TestParse_UnclosedQuote_IsError(t *testing.T) {
	_, _, err := Parse(`os:"windows server`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unterminated quoted value")
}

func TestParse_KeyWithSpace_IsError(t *testing.T) {
	_, _, err := Parse("bad key:value")
	require.Error(t, err)
}

// ── Tenant prefix tests ───────────────────────────────────────────────────────

func TestParse_TenantPrefix_ForwardSlash(t *testing.T) {
	f, tp, err := Parse("msp-a/client-1/name:web*")
	require.NoError(t, err)
	assert.Equal(t, "msp-a/client-1", tp)
	assert.Equal(t, "web*", f.Name)
}

func TestParse_TenantPrefix_Backslash(t *testing.T) {
	f, tp, err := Parse(`msp-a\client-1\name:web*`)
	require.NoError(t, err)
	assert.Equal(t, "msp-a/client-1", tp, "backslash must be normalized to forward slash")
	assert.Equal(t, "web*", f.Name)
}

func TestParse_TenantPrefix_NormalizedIdentically(t *testing.T) {
	_, tp1, err1 := Parse("msp-a/client-1/name:web*")
	_, tp2, err2 := Parse(`msp-a\client-1\name:web*`)
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.Equal(t, tp1, tp2, "forward slash and backslash must produce the same tenant path")
}

func TestParse_TenantPrefix_MultiSegment(t *testing.T) {
	f, tp, err := Parse("msp-a/client-1/servers/web/os:linux")
	require.NoError(t, err)
	assert.Equal(t, "msp-a/client-1/servers/web", tp)
	assert.Equal(t, "linux", f.OS)
}

func TestParse_TenantPrefix_WithAll(t *testing.T) {
	f, tp, err := Parse("msp-a/client-1/all")
	require.NoError(t, err)
	assert.Equal(t, "msp-a/client-1", tp)
	assert.Equal(t, fleet.Filter{}, f)
}

func TestParse_TenantPrefix_SingleSegment(t *testing.T) {
	f, tp, err := Parse("msp-a/name:web*")
	require.NoError(t, err)
	assert.Equal(t, "msp-a", tp)
	assert.Equal(t, "web*", f.Name)
}

func TestParse_TenantPrefix_MixedSeparators(t *testing.T) {
	f, tp, err := Parse(`msp-a/client-1\name:web*`)
	require.NoError(t, err)
	assert.Equal(t, "msp-a/client-1", tp)
	assert.Equal(t, "web*", f.Name)
}

func TestParse_NoTenantPrefix_PlainSelector(t *testing.T) {
	f, tp, err := Parse("name:web*")
	require.NoError(t, err)
	assert.Empty(t, tp)
	assert.Equal(t, "web*", f.Name)
}

func TestParse_NoTenantPrefix_All(t *testing.T) {
	_, tp, err := Parse("all")
	require.NoError(t, err)
	assert.Empty(t, tp)
}

func TestParse_TenantPrefix_EmptySelectorAfterPrefix_IsRejected(t *testing.T) {
	_, _, err := Parse("msp-a/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty selector")
}

func TestParse_TenantPrefix_MultipleTermsAfterPrefix(t *testing.T) {
	f, tp, err := Parse("msp-a/client-1/os:linux name:web*")
	require.NoError(t, err)
	assert.Equal(t, "msp-a/client-1", tp)
	assert.Equal(t, "linux", f.OS)
	assert.Equal(t, "web*", f.Name)
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
	filter, _, err := Parse(expr)
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

func TestResolve_Name_ExactMatch(t *testing.T) {
	// path.Match requires the full hostname; "win-srv" does not match "win-srv-01".
	ids := resolveIDs(t, "name:win-srv-01")
	assert.Equal(t, []string{"s-windows"}, ids)
}

func TestResolve_Name_ExactNoMatch(t *testing.T) {
	// Without a glob, path.Match is an exact match — a partial name returns nothing.
	ids := resolveIDs(t, "name:win-srv")
	assert.Empty(t, ids)
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

// ── id: selector tests ────────────────────────────────────────────────────────

func TestParse_ID_Single(t *testing.T) {
	f, _, err := Parse("id:s-linux-arm64")
	require.NoError(t, err)
	assert.Equal(t, []string{"s-linux-arm64"}, f.IDs)
}

func TestParse_ID_MultiValue(t *testing.T) {
	f, _, err := Parse("id:s-linux-arm64,s-windows")
	require.NoError(t, err)
	assert.Equal(t, []string{"s-linux-arm64", "s-windows"}, f.IDs)
}

func TestParse_UnknownKey_ErrorIncludesID(t *testing.T) {
	_, _, err := Parse("typo:value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id")
}

func TestResolve_ID_ExactMatch(t *testing.T) {
	ids := resolveIDs(t, "id:s-linux-arm64")
	assert.Equal(t, []string{"s-linux-arm64"}, ids)
}

func TestResolve_ID_NoMatch(t *testing.T) {
	ids := resolveIDs(t, "id:nonexistent-steward")
	assert.Empty(t, ids)
}

func TestResolve_ID_MultiValue_OR(t *testing.T) {
	ids := resolveIDs(t, "id:s-linux-arm64,s-windows")
	assert.ElementsMatch(t, []string{"s-linux-arm64", "s-windows"}, ids)
}

func TestResolve_ID_Combined_AND_WithOS(t *testing.T) {
	// s-linux-arm64 is linux; combining with os:windows yields no match.
	ids := resolveIDs(t, `id:s-linux-arm64 os:"windows server"`)
	assert.Empty(t, ids)
}

func TestResolve_ID_Combined_AND_Matches(t *testing.T) {
	// id:s-linux-arm64 AND os:linux — s-linux-arm64 is linux, so exactly one match.
	ids := resolveIDs(t, "id:s-linux-arm64 os:linux")
	assert.Equal(t, []string{"s-linux-arm64"}, ids)
}

// ── Bare-token and case-insensitive hostname tests (Issue #2440) ──────────────

// TestResolve_BareToken_CaseInsensitiveExact is the REQUIRED TEST from Issue #2440:
// a bare token matches hostnames case-insensitively and exactly (no implicit wildcards).
func TestResolve_BareToken_CaseInsensitiveExact(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-web-upper", "online", map[string]string{"hostname": "WEB"}),
		makeSteward("s-web-lower", "online", map[string]string{"hostname": "web"}),
		makeSteward("s-web-01", "online", map[string]string{"hostname": "web-01"}),
		makeSteward("s-other", "online", map[string]string{"hostname": "db-01"}),
	}
	// "web" must match WEB and web (exact, case-insensitive) but not web-01.
	ids := resolveIDsFrom(t, stewards, "web")
	assert.ElementsMatch(t, []string{"s-web-upper", "s-web-lower"}, ids)
}

// TestResolve_BareToken_AND_Composition verifies bare token composes via AND with other terms.
func TestResolve_BareToken_AND_Composition(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-linux-web", "online", map[string]string{"hostname": "web", "os": "linux"}),
		makeSteward("s-win-web", "online", map[string]string{"hostname": "web", "os": "windows"}),
		makeSteward("s-linux-db", "online", map[string]string{"hostname": "db", "os": "linux"}),
	}
	// "web os:linux" must narrow to exactly the linux web host.
	ids := resolveIDsFrom(t, stewards, "web os:linux")
	assert.Equal(t, []string{"s-linux-web"}, ids)
}

// TestResolve_BareToken_GlobCaseInsensitive verifies a bare glob token remains a glob
// and is also case-insensitive.
func TestResolve_BareToken_GlobCaseInsensitive(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-web01", "online", map[string]string{"hostname": "WEB-01"}),
		makeSteward("s-web02", "online", map[string]string{"hostname": "WEB-02"}),
		makeSteward("s-db01", "online", map[string]string{"hostname": "DB-01"}),
	}
	// bare "web*" globs and is case-insensitive — matches WEB-01 and WEB-02.
	ids := resolveIDsFrom(t, stewards, "web*")
	assert.ElementsMatch(t, []string{"s-web01", "s-web02"}, ids)
}

// TestResolve_Name_CaseInsensitive verifies name: key matching is case-insensitive.
func TestResolve_Name_CaseInsensitive(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-web", "online", map[string]string{"hostname": "web"}),
		makeSteward("s-db", "online", map[string]string{"hostname": "db"}),
	}
	// name:WEB must match hostname "web" case-insensitively.
	ids := resolveIDsFrom(t, stewards, "name:WEB")
	assert.Equal(t, []string{"s-web"}, ids)
}

// TestResolve_Name_GlobCaseInsensitive verifies glob patterns via name: are case-insensitive.
func TestResolve_Name_GlobCaseInsensitive(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-web01", "online", map[string]string{"hostname": "web-01"}),
		makeSteward("s-web02", "online", map[string]string{"hostname": "web-02"}),
		makeSteward("s-db01", "online", map[string]string{"hostname": "db-01"}),
	}
	// name:WEB* glob is case-insensitive — matches web-01 and web-02.
	ids := resolveIDsFrom(t, stewards, "name:WEB*")
	assert.ElementsMatch(t, []string{"s-web01", "s-web02"}, ids)
}

// TestResolve_ID_CaseSensitive_Unchanged verifies id: matching stays case-sensitive.
// Device IDs are not hostnames and must not be lowercased.
func TestResolve_ID_CaseSensitive_Unchanged(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-linux-arm64", "online", map[string]string{"hostname": "host1"}),
	}
	// id:S-LINUX-ARM64 (uppercase) must NOT match steward with ID "s-linux-arm64".
	ids := resolveIDsFrom(t, stewards, "id:S-LINUX-ARM64")
	assert.Empty(t, ids, "id: matching must remain case-sensitive")
}

// resolveIDsFrom is like resolveIDs but uses a caller-supplied steward list.
func resolveIDsFrom(t *testing.T, stewards []fleet.StewardData, expr string) []string {
	t.Helper()
	filter, _, err := Parse(expr)
	require.NoError(t, err)
	q := fleet.NewMemoryQuery(&staticProvider{stewards: stewards})
	results, err := q.Search(context.Background(), filter)
	require.NoError(t, err)
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.ID
	}
	return ids
}

// TestResolve_Name_LeadingGlob verifies that name:*web matches hostnames ending in
// "web" via path.Match. Previously broken: Filter.Hostname used prefix-glob only
// (strings.HasSuffix(v,"*")), so "*web" fell through to a literal substring search
// that never matched anything useful.
func TestResolve_Name_LeadingGlob(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-appweb", "online", map[string]string{"hostname": "app-web"}),
		makeSteward("s-db", "online", map[string]string{"hostname": "db-01"}),
	}
	ids := resolveIDsFrom(t, stewards, "name:*web")
	assert.Equal(t, []string{"s-appweb"}, ids)
}

// TestResolve_Name_MidStringGlob verifies that name:web*1 matches hostnames like
// "web-01" via path.Match. Previously broken: Filter.Hostname's HasSuffix("*") check
// failed for mid-string globs, so "web*1" fell through to a literal substring search.
func TestResolve_Name_MidStringGlob(t *testing.T) {
	stewards := []fleet.StewardData{
		makeSteward("s-web01", "online", map[string]string{"hostname": "web-01"}),
		makeSteward("s-web02", "online", map[string]string{"hostname": "web-02"}),
		makeSteward("s-db01", "online", map[string]string{"hostname": "db-01"}),
	}
	ids := resolveIDsFrom(t, stewards, "name:web*1")
	assert.Equal(t, []string{"s-web01"}, ids)
}

// TestParse_TableCoverage is the required table test covering every selector shape
// both legacy parsers (selector.Parse and fleet.ParseTargetSelector) handled.
func TestParse_TableCoverage(t *testing.T) {
	cases := []struct {
		name    string
		expr    string
		want    fleet.Filter
		wantErr string
	}{
		{
			name: "bare token (no colon) is implicit name",
			expr: "web",
			want: fleet.Filter{Name: "web"},
		},
		{
			name: "bare glob token is implicit name glob",
			expr: "web*",
			want: fleet.Filter{Name: "web*"},
		},
		{
			name: "id comma-OR",
			expr: "id:a,b",
			want: fleet.Filter{IDs: []string{"a", "b"}},
		},
		{
			name: "quoted tag with space",
			expr: `tag:"prod east"`,
			want: fleet.Filter{Tags: []string{"prod east"}},
		},
		{
			name: "name trailing glob",
			expr: "name:web*",
			want: fleet.Filter{Name: "web*"},
		},
		{
			name: "name leading glob (previously broken via Filter.Hostname)",
			expr: "name:*web",
			want: fleet.Filter{Name: "*web"},
		},
		{
			name: "name mid-string glob (previously broken via Filter.Hostname)",
			expr: "name:web*1",
			want: fleet.Filter{Name: "web*1"},
		},
		{
			name: "dna attribute",
			expr: "dna.role:db",
			want: fleet.Filter{DNAAttributes: map[string]string{"role": "db"}},
		},
		{
			name: "all returns empty filter",
			expr: "all",
			want: fleet.Filter{},
		},
		{
			name:    "empty string rejected",
			expr:    "",
			wantErr: "empty selector",
		},
		{
			name:    "unknown key rejected",
			expr:    "unknown:val",
			wantErr: "unknown selector key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := Parse(tc.expr)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
