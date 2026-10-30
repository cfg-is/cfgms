// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/entitygraph/writers/dnasync"
)

// staticDirectoryAuthority is the real, table-backed DirectoryAuthority: peer →
// domains it is authoritative for. It counts calls so batch caching is observable.
type staticDirectoryAuthority struct {
	grants map[string][]string
	calls  int
}

func (s *staticDirectoryAuthority) IsDirectoryAuthority(peer, domain string) bool {
	s.calls++
	for _, d := range s.grants[peer] {
		if d == domain {
			return true
		}
	}
	return false
}

func dirPayload(domain string) map[string]interface{} {
	return map[string]interface{}{types.PayloadDirectoryDomain: domain, "module_authority": "enforcing-module:ad"}
}

func TestResolve_DirectoryBranch_VerifiedPeerGetsDirectoryEID(t *testing.T) {
	auth := &staticDirectoryAuthority{grants: map[string][]string{"dc-1": {"corp.example.com"}}}
	tx := types.DefaultTaxonomy()

	eid, src, cs, err := dnasync.ResolveSubjectEID("directory_user", "dc-1", "directory_user:guid-1",
		dirPayload("CORP.Example.com."), tx, nil, auth)
	require.NoError(t, err)
	assert.Equal(t, "directory:corp.example.com/user:guid-1", eid.String())
	assert.Equal(t, "dc-1", src, "attributed to the peer")
	assert.Nil(t, cs)

	eid, _, _, err = dnasync.ResolveSubjectEID("directory_group", "dc-1", "directory_group:guid-2",
		dirPayload("corp.example.com"), tx, nil, auth)
	require.NoError(t, err)
	assert.Equal(t, "directory:corp.example.com/group:guid-2", eid.String())
}

func TestResolve_DirectoryBranch_UnverifiedDomainIsDroppedNotHostScoped(t *testing.T) {
	granted := &staticDirectoryAuthority{grants: map[string][]string{"dc-1": {"corp.example.com"}}}
	cases := []struct {
		name    string
		peer    string
		payload map[string]interface{}
		auth    dnasync.DirectoryAuthority
		reason  dnasync.DirectoryDropReason
	}{
		{"nil verifier", "dc-1", dirPayload("corp.example.com"), nil, dnasync.DropNoVerifier},
		{"other tenant peer", "dc-2", dirPayload("corp.example.com"), granted, dnasync.DropNotAuthority},
		{"unknown domain", "dc-1", dirPayload("other.example.com"), granted, dnasync.DropNotAuthority},
		{"missing domain", "dc-1", map[string]interface{}{}, granted, dnasync.DropMalformedDomain},
		{"nil payload", "dc-1", nil, granted, dnasync.DropMalformedDomain},
		{"slash in domain", "dc-1", dirPayload("corp.example.com/host:dc-2"), granted, dnasync.DropMalformedDomain},
		{"empty label", "dc-1", dirPayload("corp..example.com"), granted, dnasync.DropMalformedDomain},
		{"control char", "dc-1", dirPayload("corp.exa\nmple.com"), granted, dnasync.DropMalformedDomain},
		{"too long", "dc-1", dirPayload(strings.Repeat("a", 64) + ".com"), granted, dnasync.DropMalformedDomain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := dnasync.ResolveSubjectEID("directory_user", tc.peer, "directory_user:g",
				tc.payload, types.DefaultTaxonomy(), nil, tc.auth)
			require.Error(t, err)
			var drop *dnasync.DirectoryDropError
			require.ErrorAs(t, err, &drop)
			assert.Equal(t, tc.reason, drop.Reason)
			assert.True(t, dnasync.IsDirectoryDrop(err))
		})
	}

	t.Run("kind not in taxonomy", func(t *testing.T) {
		_, _, _, err := dnasync.ResolveSubjectEID("directory_user", "dc-1", "directory_user:g",
			dirPayload("corp.example.com"), &types.Taxonomy{}, nil, granted)
		var drop *dnasync.DirectoryDropError
		require.ErrorAs(t, err, &drop)
		assert.Equal(t, dnasync.DropKindNotInTaxonomy, drop.Reason)
	})

	t.Run("writer skips and never host-scopes", func(t *testing.T) {
		p := newTestProvider(t)
		w, err := dnasync.New(p) // no verifier wired
		require.NoError(t, err)
		frag := &commonpb.Fragment{
			FragmentId:     "directory_user:g1",
			Authority:      "enforcing-module:ad",
			CanonicalBytes: makeTestCanonBytes(map[string]string{types.PayloadDirectoryDomain: "corp.example.com"}),
		}
		require.NoError(t, w.WriteFragmentDelta(context.Background(), "dc-1", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))
		page, err := p.QueryEntities(context.Background(), interfaces.EntityFilter{}, interfaces.PageToken{})
		require.NoError(t, err)
		assert.Empty(t, page.Entities, "an unverified directory fragment must write nothing, host-scoped or otherwise")
	})
}

func TestResolve_StewardFragmentCannotClaimM365Authority(t *testing.T) {
	auth := &staticDirectoryAuthority{grants: map[string][]string{"dc-1": {"m365", "tenant.onmicrosoft.com"}}}
	tx := types.DefaultTaxonomy()
	for _, kind := range []string{"directory_user", "directory_group", "user", "group", "directory"} {
		for _, domain := range []string{"m365", "m365:tenant", "tenant.onmicrosoft.com"} {
			eid, _, _, err := dnasync.ResolveSubjectEID(kind, "dc-1", kind+":abc", dirPayload(domain), tx, nil, auth)
			if err != nil {
				continue
			}
			assert.NotEqual(t, "m365", eid.AuthorityType(), "kind %s domain %s", kind, domain)
		}
	}
}

func TestResolve_DirectoryFragmentEdgeKeyIsIgnored(t *testing.T) {
	p := newTestProviderWithResolver(t, staticTenantResolver{"dc-1": "root/tenant-a"})
	auth := &staticDirectoryAuthority{grants: map[string][]string{"dc-1": {"corp.example.com"}}}
	w, err := dnasync.New(p, dnasync.WithDirectoryAuthority(auth))
	require.NoError(t, err)

	frag := &commonpb.Fragment{
		FragmentId: "directory_user:u1",
		Authority:  "enforcing-module:ad",
		CanonicalBytes: makeEdgesCanonBytes(map[string]interface{}{
			types.PayloadDirectoryDomain: "corp.example.com",
			"__entitygraph_edges": []interface{}{
				map[string]interface{}{"type": "member-of", "to": "directory_group:g1"},
			},
		}),
	}
	require.NoError(t, w.WriteFragmentDelta(context.Background(), "dc-1", []*commonpb.Fragment{frag}, nil, types.DefaultTaxonomy()))

	assert.Empty(t, outboundEdges(t, p, "directory:corp.example.com/user:u1"), "no edge may be written from a directory fragment")
	ref, err := types.ParseEID("directory:corp.example.com/user:u1")
	require.NoError(t, err)
	view, err := p.GetEntity(context.Background(), ref, interfaces.GetEntityOpts{TenantFilter: "root/tenant-a"})
	require.NoError(t, err)
	_, hasKey := view.Sources[0].Payload["__entitygraph_edges"]
	assert.False(t, hasKey, "the edge key must not be stored as an attribute")
}

func TestWriter_DirectoryAuthorityCachedPerBatch(t *testing.T) {
	p := newTestProviderWithResolver(t, staticTenantResolver{"dc-1": "root/tenant-a"})
	auth := &staticDirectoryAuthority{grants: map[string][]string{"dc-1": {"corp.example.com"}}}
	w, err := dnasync.New(p, dnasync.WithDirectoryAuthority(auth))
	require.NoError(t, err)

	var frags []*commonpb.Fragment
	for _, id := range []string{"a", "b", "c"} {
		frags = append(frags, &commonpb.Fragment{
			FragmentId:     "directory_user:" + id,
			CanonicalBytes: makeTestCanonBytes(map[string]string{types.PayloadDirectoryDomain: "corp.example.com"}),
		})
	}
	require.NoError(t, w.WriteFragmentsPartial(context.Background(), "dc-1", frags, nil, types.DefaultTaxonomy()))
	assert.Equal(t, 1, auth.calls, "one verifier lookup per (peer, domain) per batch")
}
