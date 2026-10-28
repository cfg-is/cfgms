// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func newDirectoryTestService(t *testing.T, tenants ...string) *ConfigurationServiceV2 {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	ctx := ctxkeys.WithSystem(context.Background())
	for _, id := range tenants {
		require.NoError(t, sm.GetTenantStore().CreateTenant(ctx,
			&business.TenantData{ID: id, Name: id, Status: business.TenantStatusActive}))
	}
	svc := NewConfigurationServiceV2(logging.NewNoopLogger(), sm, nil)
	t.Cleanup(svc.Close)
	return svc
}

func domainCfg(stewardID string, domains ...string) *stewardtypes.StewardConfig {
	cfg := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: stewardID},
		Modules: map[string]string{"activedirectory.domain": "activedirectory.domain"},
	}
	for i, d := range domains {
		cfg.Resources = append(cfg.Resources, stewardtypes.ResourceConfig{
			Name:   "domain-" + string(rune('a'+i)),
			Module: DirectoryDomainModule,
			Config: map[string]interface{}{"domain": d},
		})
	}
	return cfg
}

func validationFields(t *testing.T, err error) map[string]string {
	t.Helper()
	var vfe *ValidationFailedError
	require.ErrorAs(t, err, &vfe)
	out := map[string]string{}
	for _, e := range vfe.Errors {
		out[e.Field] = e.Code
	}
	return out
}

func TestDirectoryConfig_PasswordFieldRejected(t *testing.T) {
	svc := newDirectoryTestService(t, "tenant-a")
	ctx := ctxkeys.WithSystem(context.Background())

	for _, tc := range []struct{ module, field string }{
		{"activedirectory.user", "password"},
		{"activedirectory.user", "password_profile"},
		{"activedirectory.user", "initial_password"},
		{"m365-entra-user", "password_profile"},
		{"m365-entra-user", "PASSWORD"},
	} {
		t.Run(tc.module+"/"+tc.field, func(t *testing.T) {
			cfg := &stewardtypes.StewardConfig{
				Steward: stewardtypes.StewardSettings{ID: "dc-1"},
				Resources: []stewardtypes.ResourceConfig{{
					Name: "acct", Module: tc.module,
					Config: map[string]interface{}{"name": "x", tc.field: "hunter2"},
				}},
			}
			err := svc.SetConfiguration(ctx, "tenant-a", "dc-1", cfg)
			require.Error(t, err)
			fields := validationFields(t, err)
			assert.Equal(t, CodeDirectoryForbiddenField, fields["resources[0].config."+tc.field])
		})
	}

	t.Run("nested", func(t *testing.T) {
		errs := CheckDirectoryDeclarations(config.LevelDevice, &stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{{
				Name: "acct", Module: "activedirectory.user",
				Config: map[string]interface{}{"profile": map[string]interface{}{"initial_password": "x"}},
			}},
		})
		require.Len(t, errs, 1)
		assert.Equal(t, "resources[0].config.profile.initial_password", errs[0].Field)
	})

	t.Run("other modules unaffected", func(t *testing.T) {
		errs := CheckDirectoryDeclarations(config.LevelDevice, &stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{{
				Name: "svc", Module: "service", Config: map[string]interface{}{"password": "x"},
			}},
		})
		assert.Empty(t, errs)
	})

	t.Run("reserved names", func(t *testing.T) {
		for _, name := range []string{"directory_user", "directory_group", "Directory_User"} {
			errs := CheckDirectoryDeclarations(config.LevelDevice, &stewardtypes.StewardConfig{
				Resources: []stewardtypes.ResourceConfig{{Name: name, Module: "file"}},
			})
			require.Len(t, errs, 1, name)
			assert.Equal(t, "resources[0].name", errs[0].Field)
			assert.Equal(t, CodeDirectoryReservedName, errs[0].Code)
		}
	})
}

func TestDirectoryConfig_NonDeviceLevelDeclarationRejected(t *testing.T) {
	cfg := domainCfg("x", "corp.example.com")
	for _, level := range []config.InheritanceLevel{config.LevelMSP, config.LevelClient, config.LevelGroup} {
		errs := CheckDirectoryDeclarations(level, cfg)
		require.Len(t, errs, 1, "level %d", level)
		assert.Equal(t, "resources[0].module", errs[0].Field)
		assert.Equal(t, CodeDirectoryNonDeviceLevel, errs[0].Code)
	}
	assert.Empty(t, CheckDirectoryDeclarations(config.LevelDevice, cfg))

	// Malformed domains are rejected at the domain field.
	for _, bad := range []string{"", "corp..com", "a/b", strings.Repeat("a", 300)} {
		errs := CheckDirectoryDeclarations(config.LevelDevice, domainCfg("x", bad))
		require.Len(t, errs, 1, "domain %q", bad)
		assert.Equal(t, "resources[0].config.domain", errs[0].Field)
	}
}

func TestDirectoryConfig_RejectedOnEverySavePath(t *testing.T) {
	svc := newDirectoryTestService(t, "tenant-a")
	ctx := ctxkeys.WithSystem(context.Background())
	bad := &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: "dc-1"},
		Resources: []stewardtypes.ResourceConfig{{
			Name: "acct", Module: "activedirectory.user",
			Config: map[string]interface{}{"password": "x"},
		}},
	}

	t.Run("SetConfiguration", func(t *testing.T) {
		err := svc.SetConfiguration(ctx, "tenant-a", "dc-1", bad)
		assert.Equal(t, CodeDirectoryForbiddenField, validationFields(t, err)["resources[0].config.password"])
	})

	t.Run("BatchSetConfigurations", func(t *testing.T) {
		err := svc.BatchSetConfigurations(ctx, []*config.BatchConfigurationEntry{
			{TenantID: "tenant-a", StewardID: "dc-1", Config: bad},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resources[0].config.password")
	})

	t.Run("ValidateConfig", func(t *testing.T) {
		raw, err := json.Marshal(bad)
		require.NoError(t, err)
		tctx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-a")
		resp, err := svc.ValidateConfig(tctx, &controllerpb.ConfigValidationRequest{Version: "1", Config: raw})
		require.NoError(t, err)
		var found bool
		for _, e := range resp.Errors {
			if e.Field == "resources[0].config.password" && e.Code == CodeDirectoryForbiddenField {
				found = true
			}
		}
		assert.True(t, found, "ValidateConfig must report the forbidden field: %+v", resp.Errors)
	})

	t.Run("push handler path", func(t *testing.T) {
		// The config push handler (handlers_stewards.go) stores through
		// SetConfiguration; this pins that it is the only store call it makes, so a
		// rejection there is a rejection of the push.
		err := svc.SetConfiguration(ctx, "tenant-a", "dc-1", bad)
		var vfe *ValidationFailedError
		require.True(t, errors.As(err, &vfe))
		_, getErr := svc.configManager.GetConfiguration(ctx, "tenant-a", "dc-1")
		assert.Error(t, getErr, "a rejected push must store nothing")
	})
}

func TestDomainRegistry_SecondTenantDeclaringSameDomainIsRejectedAtSave(t *testing.T) {
	svc := newDirectoryTestService(t, "tenant-a", "tenant-b")
	ctx := ctxkeys.WithSystem(context.Background())

	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", "dc-a", domainCfg("dc-a", "Corp.Example.com.")))
	owner, found, err := svc.DirectoryDomains().Owner(ctx, "corp.example.com")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "tenant-a", owner, "registry key is the normalized name")

	err = svc.SetConfiguration(ctx, "tenant-b", "dc-b", domainCfg("dc-b", "corp.example.com"))
	require.Error(t, err)
	fields := validationFields(t, err)
	assert.Equal(t, CodeDirectoryDomainConflict, fields["resources[0].config.domain"])
	assert.NotContains(t, err.Error(), "tenant-a", "the other tenant must not be named")

	// Batch path rejects too, and stores nothing.
	err = svc.BatchSetConfigurations(ctx, []*config.BatchConfigurationEntry{
		{TenantID: "tenant-b", StewardID: "dc-b", Config: domainCfg("dc-b", "corp.example.com")},
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "tenant-a")

	// Same tenant, second DC: allowed.
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", "dc-a2", domainCfg("dc-a2", "corp.example.com")))

	// Owner unchanged.
	owner, _, _ = svc.DirectoryDomains().Owner(ctx, "corp.example.com")
	assert.Equal(t, "tenant-a", owner)
}

func TestDomainRegistry_RemovalReleasesDomain(t *testing.T) {
	svc := newDirectoryTestService(t, "tenant-a", "tenant-b")
	ctx := ctxkeys.WithSystem(context.Background())

	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", "dc-a", domainCfg("dc-a", "corp.example.com")))
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", "dc-a2", domainCfg("dc-a2", "corp.example.com")))

	// One DC drops the declaration: the other still holds the domain.
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", "dc-a", domainCfg("dc-a")))
	_, found, err := svc.DirectoryDomains().Owner(ctx, "corp.example.com")
	require.NoError(t, err)
	assert.True(t, found, "a remaining declarer keeps the domain")
	require.Error(t, svc.SetConfiguration(ctx, "tenant-b", "dc-b", domainCfg("dc-b", "corp.example.com")))

	// The last declaration goes (here by deleting the cfg): the domain is released.
	require.NoError(t, svc.DeleteConfiguration(ctx, "tenant-a", "dc-a2"))
	_, found, err = svc.DirectoryDomains().Owner(ctx, "corp.example.com")
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, svc.SetConfiguration(ctx, "tenant-b", "dc-b", domainCfg("dc-b", "corp.example.com")))
	owner, found, err := svc.DirectoryDomains().Owner(ctx, "corp.example.com")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "tenant-b", owner)
}
