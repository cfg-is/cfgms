// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ReportTemplateStoreContract is the conformance suite every ReportTemplateStore provider
// must pass (Issue #5527). The store must be empty on entry. Test tenants and template IDs
// are unique per subtest, so subtests do not interfere with one another.
func ReportTemplateStoreContract(t *testing.T, store ReportTemplateStore) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Millisecond)
	past := base.Add(-time.Hour)
	future := base.Add(time.Hour)

	newTemplate := func(tenant, id string) *ReportTemplate {
		return &ReportTemplate{
			ID: id, Name: "name-" + id, Description: "desc",
			Definition: json.RawMessage(`{"query":{"type":"compliance"},"parameters":[{"name":"p"}]}`),
			TenantID:   tenant, CreatedBy: "alice", CreatedAt: base, UpdatedAt: base,
			Tags: []string{"a", "b"}, Category: "cat", Version: "1", UsageCount: 3,
		}
	}
	share := func(tenant string, expires *time.Time) ReportTemplateShare {
		return ReportTemplateShare{
			TenantID: tenant, SharedBy: "alice", SharedAt: base,
			Permissions: []string{"read", "execute"}, ExpiresAt: expires,
		}
	}
	mustSave := func(t *testing.T, tenant string, tpl *ReportTemplate) {
		t.Helper()
		require.NoError(t, store.Save(ctx, tenant, tpl))
	}
	ids := func(list []*ReportTemplate) []string {
		out := make([]string, 0, len(list))
		for _, x := range list {
			out = append(out, x.ID)
		}
		return out
	}

	t.Run("save and get round trip", func(t *testing.T) {
		tpl := newTemplate("rt-owner", "rt-roundtrip")
		lastUsed := base.Add(-time.Minute)
		tpl.LastUsed = &lastUsed
		tpl.IsShared = true
		tpl.SharedWith = []ReportTemplateShare{share("rt-peer", &future)}
		mustSave(t, "rt-owner", tpl)

		got, err := store.GetByID(ctx, "rt-owner", "rt-roundtrip")
		require.NoError(t, err)
		assert.Equal(t, "name-rt-roundtrip", got.Name)
		assert.Equal(t, "desc", got.Description)
		assert.JSONEq(t, string(tpl.Definition), string(got.Definition))
		assert.Equal(t, "rt-owner", got.TenantID)
		assert.Equal(t, "alice", got.CreatedBy)
		assert.True(t, base.Equal(got.CreatedAt))
		assert.True(t, base.Equal(got.UpdatedAt))
		assert.True(t, got.IsShared)
		assert.Equal(t, []string{"a", "b"}, got.Tags)
		assert.Equal(t, "cat", got.Category)
		assert.Equal(t, "1", got.Version)
		assert.Equal(t, 3, got.UsageCount)
		require.NotNil(t, got.LastUsed)
		assert.True(t, lastUsed.Equal(*got.LastUsed))
		require.Len(t, got.SharedWith, 1)
		assert.Equal(t, "rt-peer", got.SharedWith[0].TenantID)
		assert.Equal(t, "alice", got.SharedWith[0].SharedBy)
		assert.Equal(t, []string{"read", "execute"}, got.SharedWith[0].Permissions)
		require.NotNil(t, got.SharedWith[0].ExpiresAt)
		assert.True(t, future.Equal(*got.SharedWith[0].ExpiresAt))
	})

	t.Run("save is an upsert for the owner", func(t *testing.T) {
		tpl := newTemplate("rt-up", "rt-upsert")
		mustSave(t, "rt-up", tpl)
		tpl.Name = "renamed"
		tpl.UsageCount = 9
		mustSave(t, "rt-up", tpl)
		got, err := store.GetByID(ctx, "rt-up", "rt-upsert")
		require.NoError(t, err)
		assert.Equal(t, "renamed", got.Name)
		assert.Equal(t, 9, got.UsageCount)
		owned, err := store.ListOwned(ctx, "rt-up")
		require.NoError(t, err)
		assert.Len(t, owned, 1)
	})

	t.Run("a template is invisible to a tenant that neither owns nor holds a share", func(t *testing.T) {
		mustSave(t, "rt-a", newTemplate("rt-a", "rt-iso"))
		_, err := store.GetByID(ctx, "rt-b", "rt-iso")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound)
		owned, err := store.ListOwned(ctx, "rt-b")
		require.NoError(t, err)
		assert.Empty(t, owned)
		shared, err := store.ListSharedWith(ctx, "rt-b")
		require.NoError(t, err)
		assert.Empty(t, shared)
		_, err = store.GetByID(ctx, "rt-a", "rt-missing")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound)
	})

	t.Run("a share grants read access and the recipient sees only its own share", func(t *testing.T) {
		tpl := newTemplate("rt-s-owner", "rt-shared")
		tpl.IsShared = true
		tpl.SharedWith = []ReportTemplateShare{share("rt-s-r1", nil), share("rt-s-r2", nil)}
		mustSave(t, "rt-s-owner", tpl)

		got, err := store.GetByID(ctx, "rt-s-r1", "rt-shared")
		require.NoError(t, err)
		assert.Equal(t, "rt-s-owner", got.TenantID)
		require.Len(t, got.SharedWith, 1)
		assert.Equal(t, "rt-s-r1", got.SharedWith[0].TenantID)

		shared, err := store.ListSharedWith(ctx, "rt-s-r2")
		require.NoError(t, err)
		assert.Equal(t, []string{"rt-shared"}, ids(shared))
		owned, err := store.ListOwned(ctx, "rt-s-r2")
		require.NoError(t, err)
		assert.Empty(t, owned, "a share is not ownership")

		full, err := store.GetByID(ctx, "rt-s-owner", "rt-shared")
		require.NoError(t, err)
		assert.Len(t, full.SharedWith, 2, "the owner sees every share")
		sharedWithOwner, err := store.ListSharedWith(ctx, "rt-s-owner")
		require.NoError(t, err)
		assert.Empty(t, sharedWithOwner)
	})

	t.Run("ListSharedWith honours share expiry and an expired share cannot be fetched", func(t *testing.T) {
		tpl := newTemplate("rt-e-owner", "rt-expiring")
		tpl.SharedWith = []ReportTemplateShare{share("rt-e-old", &past), share("rt-e-new", &future)}
		mustSave(t, "rt-e-owner", tpl)

		_, err := store.GetByID(ctx, "rt-e-old", "rt-expiring")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound)
		expired, err := store.ListSharedWith(ctx, "rt-e-old")
		require.NoError(t, err)
		assert.Empty(t, expired)

		got, err := store.GetByID(ctx, "rt-e-new", "rt-expiring")
		require.NoError(t, err)
		assert.Equal(t, "rt-expiring", got.ID)
		live, err := store.ListSharedWith(ctx, "rt-e-new")
		require.NoError(t, err)
		assert.Equal(t, []string{"rt-expiring"}, ids(live))
	})

	t.Run("owner-only delete", func(t *testing.T) {
		tpl := newTemplate("rt-d-owner", "rt-delete")
		tpl.SharedWith = []ReportTemplateShare{share("rt-d-r", nil)}
		mustSave(t, "rt-d-owner", tpl)

		assert.ErrorIs(t, store.Delete(ctx, "rt-d-r", "rt-delete"), ErrReportTemplateNotFound, "share recipient")
		assert.ErrorIs(t, store.Delete(ctx, "rt-d-other", "rt-delete"), ErrReportTemplateNotFound, "unrelated tenant")
		_, err := store.GetByID(ctx, "rt-d-owner", "rt-delete")
		require.NoError(t, err, "template survives non-owner deletes")

		require.NoError(t, store.Delete(ctx, "rt-d-owner", "rt-delete"))
		_, err = store.GetByID(ctx, "rt-d-owner", "rt-delete")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound)
		_, err = store.GetByID(ctx, "rt-d-r", "rt-delete")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound)
		assert.ErrorIs(t, store.Delete(ctx, "rt-d-owner", "rt-delete"), ErrReportTemplateNotFound)
	})

	t.Run("owner-only sharing update", func(t *testing.T) {
		tpl := newTemplate("rt-u-owner", "rt-sharing")
		tpl.SharedWith = []ReportTemplateShare{share("rt-u-r", nil)}
		mustSave(t, "rt-u-owner", tpl)

		err := store.UpdateSharing(ctx, "rt-u-r", "rt-sharing", []ReportTemplateShare{share("rt-u-evil", nil)})
		assert.ErrorIs(t, err, ErrReportTemplateNotFound, "share recipient")
		err = store.UpdateSharing(ctx, "rt-u-other", "rt-sharing", []ReportTemplateShare{share("rt-u-evil", nil)})
		assert.ErrorIs(t, err, ErrReportTemplateNotFound, "unrelated tenant")
		_, err = store.GetByID(ctx, "rt-u-evil", "rt-sharing")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound)

		require.NoError(t, store.UpdateSharing(ctx, "rt-u-owner", "rt-sharing", []ReportTemplateShare{share("rt-u-new", nil)}))
		_, err = store.GetByID(ctx, "rt-u-r", "rt-sharing")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound, "the old recipient lost access")
		_, err = store.GetByID(ctx, "rt-u-new", "rt-sharing")
		require.NoError(t, err)

		require.NoError(t, store.UpdateSharing(ctx, "rt-u-owner", "rt-sharing", nil))
		_, err = store.GetByID(ctx, "rt-u-new", "rt-sharing")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound)
		got, err := store.GetByID(ctx, "rt-u-owner", "rt-sharing")
		require.NoError(t, err)
		assert.Empty(t, got.SharedWith)
		assert.Equal(t, "name-rt-sharing", got.Name, "sharing update leaves the rest of the record alone")

		assert.ErrorIs(t, store.UpdateSharing(ctx, "rt-u-owner", "rt-nope", nil), ErrReportTemplateNotFound)
		assert.Error(t, store.UpdateSharing(ctx, "rt-u-owner", "rt-sharing", []ReportTemplateShare{share("root/../x", nil)}))
	})

	t.Run("tenant B saving a template tenant A owns fails and leaves it unchanged", func(t *testing.T) {
		orig := newTemplate("rt-x-a", "rt-owned")
		orig.SharedWith = []ReportTemplateShare{share("rt-x-b", nil)}
		mustSave(t, "rt-x-a", orig)
		before, err := store.GetByID(ctx, "rt-x-a", "rt-owned")
		require.NoError(t, err)

		hijack := newTemplate("rt-x-b", "rt-owned")
		hijack.Name = "hijacked"
		assert.ErrorIs(t, store.Save(ctx, "rt-x-b", hijack), ErrReportTemplateExists, "even a share recipient cannot write")
		hijack.TenantID = "rt-x-a"
		assert.Error(t, store.Save(ctx, "rt-x-b", hijack), "claiming the owner's tenant ID does not help")

		after, err := store.GetByID(ctx, "rt-x-a", "rt-owned")
		require.NoError(t, err)
		assert.Equal(t, before, after)
		owned, err := store.ListOwned(ctx, "rt-x-b")
		require.NoError(t, err)
		assert.Empty(t, owned)
	})

	t.Run("save with a mismatched or empty tenant writes nothing", func(t *testing.T) {
		cases := []struct {
			name, argTenant, tplTenant string
		}{
			{"mismatch", "rt-m-a", "rt-m-b"},
			{"empty argument", "", "rt-m-a"},
			{"empty template tenant", "rt-m-a", ""},
			{"both empty", "", ""},
		}
		for i, c := range cases {
			id := fmt.Sprintf("rt-mismatch-%d", i)
			tpl := newTemplate(c.tplTenant, id)
			assert.Error(t, store.Save(ctx, c.argTenant, tpl), c.name)
			for _, tenant := range []string{"rt-m-a", "rt-m-b"} {
				_, err := store.GetByID(ctx, tenant, id)
				assert.ErrorIs(t, err, ErrReportTemplateNotFound, c.name)
			}
		}
		assert.Error(t, store.Save(ctx, "rt-m-a", nil))
		bad := newTemplate("rt-m-a", "rt-bad-def")
		bad.Definition = json.RawMessage(`{not json`)
		assert.Error(t, store.Save(ctx, "rt-m-a", bad))
	})

	t.Run("concurrent saves do not corrupt the record", func(t *testing.T) {
		const workers = 16
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				tpl := newTemplate("rt-c", "rt-concurrent")
				tpl.Name = fmt.Sprintf("writer-%d", i)
				tpl.UsageCount = i
				errs <- store.Save(ctx, "rt-c", tpl)
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		got, err := store.GetByID(ctx, "rt-c", "rt-concurrent")
		require.NoError(t, err)
		var n int
		_, scanErr := fmt.Sscanf(got.Name, "writer-%d", &n)
		require.NoError(t, scanErr)
		assert.Equal(t, n, got.UsageCount, "name and usage count come from the same writer")
		assert.JSONEq(t, string(newTemplate("", "").Definition), string(got.Definition))
		owned, err := store.ListOwned(ctx, "rt-c")
		require.NoError(t, err)
		assert.Len(t, owned, 1)
	})

	t.Run("traversal-shaped identifiers are rejected", func(t *testing.T) {
		badTenants := []string{"", "root/../x", "..", "root/./x", "/root", "root/", "root//x", `root\x`, "root\x00x"}
		for _, bad := range badTenants {
			tpl := newTemplate(bad, "rt-trav")
			assert.Error(t, store.Save(ctx, bad, tpl), "save tenant %q", bad)
			_, err := store.GetByID(ctx, bad, "rt-trav")
			assert.Error(t, err, "get tenant %q", bad)
			assert.NotErrorIs(t, err, ErrReportTemplateNotFound, "get tenant %q is invalid input, not a miss", bad)
			_, err = store.ListOwned(ctx, bad)
			assert.Error(t, err, "list owned %q", bad)
			_, err = store.ListSharedWith(ctx, bad)
			assert.Error(t, err, "list shared %q", bad)
			assert.Error(t, store.Delete(ctx, bad, "rt-trav"), "delete tenant %q", bad)
			assert.Error(t, store.UpdateSharing(ctx, bad, "rt-trav", nil), "update tenant %q", bad)
		}
		badIDs := []string{"", "..", ".", "a/b", `a\b`, "a\x00b", "../etc/passwd", "/abs"}
		for _, bad := range badIDs {
			tpl := newTemplate("rt-trav-t", bad)
			assert.Error(t, store.Save(ctx, "rt-trav-t", tpl), "save id %q", bad)
			_, err := store.GetByID(ctx, "rt-trav-t", bad)
			assert.Error(t, err, "get id %q", bad)
			assert.Error(t, store.Delete(ctx, "rt-trav-t", bad), "delete id %q", bad)
			assert.Error(t, store.UpdateSharing(ctx, "rt-trav-t", bad, nil), "update id %q", bad)
		}
		for _, bad := range []string{"root/../x", "..", "", `a\b`} {
			tpl := newTemplate("rt-trav-t", "rt-trav-share")
			tpl.SharedWith = []ReportTemplateShare{share(bad, nil)}
			assert.Error(t, store.Save(ctx, "rt-trav-t", tpl), "save share recipient %q", bad)
		}
		_, err := store.GetByID(ctx, "rt-trav-t", "rt-trav-share")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound, "a rejected save wrote nothing")
		owned, err := store.ListOwned(ctx, "rt-trav-t")
		require.NoError(t, err)
		assert.Empty(t, owned)
	})

	t.Run("hierarchical tenant IDs round-trip", func(t *testing.T) {
		const owner, parent, child = "root/msp-a/client-1", "root/msp-a", "root/msp-a/client-1/servers"
		tpl := newTemplate(owner, "rt-hier")
		tpl.SharedWith = []ReportTemplateShare{share(child, nil)}
		mustSave(t, owner, tpl)
		sibling := newTemplate(parent, "rt-hier-parent")
		mustSave(t, parent, sibling)

		got, err := store.GetByID(ctx, owner, "rt-hier")
		require.NoError(t, err)
		assert.Equal(t, owner, got.TenantID)
		owned, err := store.ListOwned(ctx, owner)
		require.NoError(t, err)
		assert.Equal(t, []string{"rt-hier"}, ids(owned), "a parent's templates do not leak into a child's listing")
		parentOwned, err := store.ListOwned(ctx, parent)
		require.NoError(t, err)
		assert.Equal(t, []string{"rt-hier-parent"}, ids(parentOwned))

		shared, err := store.ListSharedWith(ctx, child)
		require.NoError(t, err)
		assert.Equal(t, []string{"rt-hier"}, ids(shared))
		viaShare, err := store.GetByID(ctx, child, "rt-hier")
		require.NoError(t, err)
		assert.Equal(t, owner, viaShare.TenantID)
		_, err = store.GetByID(ctx, parent, "rt-hier")
		assert.ErrorIs(t, err, ErrReportTemplateNotFound, "a share names one tenant, not its ancestors")
	})

	t.Run("listing is limited to the tenant", func(t *testing.T) {
		mustSave(t, "rt-l-a", newTemplate("rt-l-a", "rt-l-1"))
		mustSave(t, "rt-l-a", newTemplate("rt-l-a", "rt-l-2"))
		mustSave(t, "rt-l-b", newTemplate("rt-l-b", "rt-l-3"))
		a, err := store.ListOwned(ctx, "rt-l-a")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"rt-l-1", "rt-l-2"}, ids(a))
		b, err := store.ListOwned(ctx, "rt-l-b")
		require.NoError(t, err)
		assert.Equal(t, []string{"rt-l-3"}, ids(b))
	})
}
