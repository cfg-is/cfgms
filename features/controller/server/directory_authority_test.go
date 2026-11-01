// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// dirFixture is the real controller-side stack the directory authority decides
// from: real config store and config service, a real steward registry, and a real
// sqlite entity graph that resolves tenants through that registry.
type dirFixture struct {
	svc  *service.ConfigurationServiceV2
	ctrl *service.ControllerService
	eg   *egsqlite.SQLiteEntityGraphProvider
	srv  *Server
	ctx  context.Context
}

func newDirFixture(t *testing.T) *dirFixture {
	t.Helper()
	ctx := ctxkeys.WithSystem(context.Background())
	sm := pkgtesting.SetupTestStorage(t)
	for _, id := range []string{"tenant-a", "tenant-b"} {
		require.NoError(t, sm.GetTenantStore().CreateTenant(ctx,
			&business.TenantData{ID: id, Name: id, Status: business.TenantStatusActive}))
	}
	logger := logging.NewNoopLogger()
	ctrl := service.NewControllerService(logger)
	for steward, tenant := range map[string]string{"dc-a": "tenant-a", "member-a": "tenant-a", "dc-b": "tenant-b"} {
		require.NoError(t, ctrl.RegisterSteward(steward, tenant, "", "online"))
	}
	svc := service.NewConfigurationServiceV2(logger, sm, ctrl)
	t.Cleanup(svc.Close)

	eg, err := egsqlite.NewSQLiteEntityGraphProvider(filepath.Join(t.TempDir(), "eg.db"), egsqlite.WithTenantResolver(ctrl))
	require.NoError(t, err)
	t.Cleanup(func() { _ = eg.Close() })

	srv := &Server{egProvider: eg, configService: svc, controllerService: ctrl, logger: logger}
	return &dirFixture{svc: svc, ctrl: ctrl, eg: eg, srv: srv, ctx: ctx}
}

func (f *dirFixture) declare(t *testing.T, tenant, steward string, domains ...string) {
	t.Helper()
	cfg := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: steward},
		Modules: map[string]string{service.DirectoryDomainModule: service.DirectoryDomainModule},
	}
	for i, d := range domains {
		cfg.Resources = append(cfg.Resources, stewardtypes.ResourceConfig{
			Name: "domain-" + string(rune('a'+i)), Module: service.DirectoryDomainModule,
			Config: map[string]interface{}{"domain": d},
		})
	}
	require.NoError(t, f.svc.SetConfiguration(f.ctx, tenant, steward, cfg))
}

func canonStrings(fields map[string]string) []byte {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf := binary.BigEndian.AppendUint32(nil, uint32(len(keys)))
	for _, k := range keys {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(k)))
		buf = append(buf, k...)
		buf = append(buf, 'S')
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(fields[k])))
		buf = append(buf, fields[k]...)
	}
	return buf
}

func dirFrag(kind, id, domain string) *commonpb.Fragment {
	return &commonpb.Fragment{
		FragmentId: kind + ":" + id,
		Authority:  "enforcing-module:activedirectory",
		CanonicalBytes: canonStrings(map[string]string{
			egtypes.PayloadDirectoryDomain: domain, "display_name": id,
		}),
	}
}

func (f *dirFixture) visibleTo(t *testing.T, tenant, subject string) bool {
	t.Helper()
	eid, err := egtypes.ParseEID(subject)
	require.NoError(t, err)
	v, err := f.eg.GetEntity(f.ctx, eid, eginterfaces.GetEntityOpts{TenantFilter: tenant})
	return err == nil && v != nil
}

func TestVerifier_SameTenantPeerWithoutDomainResource_Denied(t *testing.T) {
	f := newDirFixture(t)
	f.declare(t, "tenant-a", "dc-a", "corp.example.com")
	auth := f.srv.directoryAuthorityVerifier()
	require.NotNil(t, auth)

	assert.True(t, auth.IsDirectoryAuthority("dc-a", "corp.example.com"), "the declaring DC is the authority")
	assert.False(t, auth.IsDirectoryAuthority("member-a", "corp.example.com"),
		"a same-tenant steward that does not declare the domain is denied")
	assert.False(t, auth.IsDirectoryAuthority("dc-b", "corp.example.com"), "another tenant's steward is denied")
	assert.False(t, auth.IsDirectoryAuthority("unregistered", "corp.example.com"), "an unknown peer is denied")
	assert.False(t, auth.IsDirectoryAuthority("dc-a", "other.example.com"), "an unregistered domain is denied")

	// A steward that declares a domain the registry gave to someone else is denied:
	// declaration alone is not ownership. (Seeded by writing the cfg straight to the
	// store, bypassing the save-time registry check.)
	f.declare(t, "tenant-b", "dc-b", "b-corp.example.com")
	require.NoError(t, f.ctrl.RegisterSteward("rogue-b", "tenant-b", "", "online"))
	assert.False(t, auth.IsDirectoryAuthority("rogue-b", "corp.example.com"))
}

func TestDomainRelease_RetractsEntitiesAndAllowsNewOwner(t *testing.T) {
	f := newDirFixture(t)
	w, err := f.srv.buildDNAEntityGraphWriter() // also wires the release handler
	require.NoError(t, err)
	tx := egtypes.DefaultTaxonomy()

	f.declare(t, "tenant-a", "dc-a", "corp.example.com")
	require.NoError(t, w.WriteFragmentDelta(f.ctx, "dc-a", []*commonpb.Fragment{
		dirFrag("directory_user", "u1", "corp.example.com"),
		dirFrag("directory_group", "g1", "corp.example.com"),
	}, nil, tx))

	const user = "directory:corp.example.com/user:u1"
	const group = "directory:corp.example.com/group:g1"
	require.True(t, f.visibleTo(t, "tenant-a", user))
	require.True(t, f.visibleTo(t, "tenant-a", group))
	assert.False(t, f.visibleTo(t, "tenant-b", user), "directory entities are tenant-scoped")

	// Tenant B cannot write the domain while A owns it: dc-b is not the authority.
	require.NoError(t, w.WriteFragmentDelta(f.ctx, "dc-b", []*commonpb.Fragment{
		dirFrag("directory_user", "u1", "corp.example.com"),
	}, nil, tx))
	assert.False(t, f.visibleTo(t, "tenant-b", user))

	// A drops its declaration: the domain is released and A's entities retracted.
	f.declare(t, "tenant-a", "dc-a")
	assert.False(t, f.visibleTo(t, "tenant-a", user), "released domain's inventory must be retracted")
	assert.False(t, f.visibleTo(t, "tenant-a", group))

	// B now declares it and owns new entities, which owner immutability no longer blocks.
	f.declare(t, "tenant-b", "dc-b", "corp.example.com")
	require.NoError(t, w.WriteFragmentDelta(f.ctx, "dc-b", []*commonpb.Fragment{
		dirFrag("directory_user", "u1", "corp.example.com"),
	}, nil, tx))
	assert.True(t, f.visibleTo(t, "tenant-b", user))
	assert.False(t, f.visibleTo(t, "tenant-a", user))
}

func TestDirectoryWriter_NoVerifierWired_DropsFragments(t *testing.T) {
	f := newDirFixture(t)
	f.srv.configService = nil // controller lacks the state to decide: deny everything
	w, err := f.srv.buildDNAEntityGraphWriter()
	require.NoError(t, err)
	require.NoError(t, w.WriteFragmentDelta(f.ctx, "dc-a", []*commonpb.Fragment{
		dirFrag("directory_user", "u1", "corp.example.com"),
	}, nil, egtypes.DefaultTaxonomy()))
	page, err := f.eg.QueryEntities(f.ctx, eginterfaces.EntityFilter{}, eginterfaces.PageToken{})
	require.NoError(t, err)
	assert.Empty(t, page.Entities)
}
