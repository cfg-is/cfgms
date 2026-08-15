// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestTagStore creates a real SQLite tag store for service-level tests.
func newTestTagStore(t *testing.T) *tagstore.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "tags.db")
	store, err := tagstore.NewFromDSN("file:"+dbPath, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(context.Background()))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// storeRoleConfig writes a role config JSON entry into the config store under role-policies.
func storeRoleConfig(t *testing.T, cs cfgconfig.ConfigStore, tenantID, name, selectorExpr string, frag stewardtypes.StewardConfig) {
	t.Helper()
	rc := storedRoleConfig{
		Name:     name,
		Selector: selectorExpr,
		Fragment: frag,
	}
	data, err := json.Marshal(rc)
	require.NoError(t, err)
	checksum := fmt.Sprintf("%x", sha256.Sum256(data))
	now := time.Now().UTC()
	require.NoError(t, cs.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:       &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "role-policies", Name: name},
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		Checksum:  checksum,
		CreatedAt: now,
		UpdatedAt: now,
	}))
}

// TestGetConfiguration_TaggedStewardReceivesRoleResource is the REQUIRED TEST from AC:
// a steward tagged github-runner whose DNA os=windows resolves a role config with selector
// "os:windows tag:github-runner"; its github_runner resource appears in the effective config.
// A non-matching steward does not receive it.
func TestGetConfiguration_TaggedStewardReceivesRoleResource(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)
	ts := newTestTagStore(t)

	// Seed a single-tenant hierarchy so InheritanceResolver can walk it.
	require.NoError(t, sm.GetTenantStore().CreateTenant(ctx,
		&business.TenantData{ID: "tenant-a", Name: "Tenant A", Status: business.TenantStatusActive}))

	// Set up a ControllerService with the tag store wired in.
	controllerSvc := NewControllerService(logger)
	controllerSvc.SetTagStore(ts)

	// Register two stewards: steward-win (windows, tagged) and steward-linux (linux, no tag).
	// Tenant ID is carried via context (set by auth middleware in production).
	tenantCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-a")

	winDNA := makeTestDNA("steward-win", map[string]string{"os": "windows", "hostname": "win-host", "arch": "amd64"})
	linuxDNA := makeTestDNA("steward-linux", map[string]string{"os": "linux", "hostname": "linux-host", "arch": "amd64"})

	respWin, err := controllerSvc.AcceptRegistration(tenantCtx, &controllerpb.RegisterRequest{
		InitialDna: winDNA,
	})
	require.NoError(t, err)
	winID := respWin.StewardId

	respLinux, err := controllerSvc.AcceptRegistration(tenantCtx, &controllerpb.RegisterRequest{
		InitialDna: linuxDNA,
	})
	require.NoError(t, err)
	linuxID := respLinux.StewardId

	// Tag winID with "github-runner"; leave linuxID untagged.
	require.NoError(t, ts.Set(ctx, winID, []string{"github-runner"}))

	// Store the role config targeting "os:windows tag:github-runner".
	storeRoleConfig(t, sm.GetConfigStore(), "tenant-a", "github-runner-role",
		"os:windows tag:github-runner",
		stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "github-runner-resource", Module: "github_runner",
					Config: map[string]interface{}{"runner": "true"}},
			},
		},
	)

	// Store device-level configs so GetConfiguration finds sources at each level.
	svc := NewConfigurationServiceV2(logger, sm, controllerSvc)
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", winID, &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: winID, Mode: stewardtypes.ModeController},
		Modules: map[string]string{"github_runner": "github_runner"},
	}))
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-a", linuxID, &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: linuxID, Mode: stewardtypes.ModeController},
	}))

	// winID: GetConfiguration must include the role's github_runner resource.
	cfgRespWin, err := svc.GetConfiguration(ctx, &controllerpb.ConfigRequest{StewardId: winID})
	require.NoError(t, err)
	require.Equal(t, "OK", cfgRespWin.Status.Code.String(), "steward-win config must succeed")

	winCfg, err := stewardtypes.FromProto(cfgRespWin.Config.Config)
	require.NoError(t, err)

	winResourceNames := make(map[string]bool)
	for _, r := range winCfg.Resources {
		winResourceNames[r.Name] = true
	}
	assert.True(t, winResourceNames["github-runner-resource"],
		"github_runner resource must appear in windows steward effective config (selector matches)")

	// linuxID: GetConfiguration must NOT include the role's resource (selector mismatch).
	cfgRespLinux, err := svc.GetConfiguration(ctx, &controllerpb.ConfigRequest{StewardId: linuxID})
	require.NoError(t, err)
	require.Equal(t, "OK", cfgRespLinux.Status.Code.String(), "steward-linux config must succeed")

	linuxCfg, err := stewardtypes.FromProto(cfgRespLinux.Config.Config)
	require.NoError(t, err)

	for _, r := range linuxCfg.Resources {
		assert.NotEqual(t, "github-runner-resource", r.Name,
			"github_runner resource must NOT appear in linux steward effective config (selector mismatch)")
	}
}

// TestGetConfiguration_UntaggingRemovesRoleResource verifies that removing a tag causes
// the role's resources to be absent on the next GetConfiguration call.
func TestGetConfiguration_UntaggingRemovesRoleResource(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)
	ts := newTestTagStore(t)

	require.NoError(t, sm.GetTenantStore().CreateTenant(ctx,
		&business.TenantData{ID: "tenant-b", Name: "Tenant B", Status: business.TenantStatusActive}))

	controllerSvc := NewControllerService(logger)
	controllerSvc.SetTagStore(ts)

	tenantCtxB := context.WithValue(ctx, ctxkeys.TenantID, "tenant-b")
	regResp, err := controllerSvc.AcceptRegistration(tenantCtxB, &controllerpb.RegisterRequest{
		InitialDna: makeTestDNA("steward-tag-test", map[string]string{"os": "linux", "hostname": "tag-test-host"}),
	})
	require.NoError(t, err)
	stewardID := regResp.StewardId

	require.NoError(t, ts.Set(ctx, stewardID, []string{"web-server"}))

	storeRoleConfig(t, sm.GetConfigStore(), "tenant-b", "web-role", "tag:web-server",
		stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "web-resource", Module: "file"},
			},
		},
	)

	svc := NewConfigurationServiceV2(logger, sm, controllerSvc)
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-b", stewardID, &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: stewardID, Mode: stewardtypes.ModeController},
		Modules: map[string]string{"file": "file"},
	}))

	// Tagged: role resource must appear.
	respTagged, err := svc.GetConfiguration(ctx, &controllerpb.ConfigRequest{StewardId: stewardID})
	require.NoError(t, err)
	cfgTagged, err := stewardtypes.FromProto(respTagged.Config.Config)
	require.NoError(t, err)

	taggedNames := make(map[string]bool)
	for _, r := range cfgTagged.Resources {
		taggedNames[r.Name] = true
	}
	assert.True(t, taggedNames["web-resource"], "web-resource must appear when steward is tagged web-server")

	// Untag: clear the tag list; next resolve must not include the role resource.
	require.NoError(t, ts.Set(ctx, stewardID, []string{}))

	respUntagged, err := svc.GetConfiguration(ctx, &controllerpb.ConfigRequest{StewardId: stewardID})
	require.NoError(t, err)
	cfgUntagged, err := stewardtypes.FromProto(respUntagged.Config.Config)
	require.NoError(t, err)

	for _, r := range cfgUntagged.Resources {
		assert.NotEqual(t, "web-resource", r.Name,
			"web-resource must be absent after untagging the steward")
	}
}

// findResource returns the resource with the given name from resources, failing the test
// if it is absent.
func findResource(t *testing.T, resources []stewardtypes.ResourceConfig, name string) stewardtypes.ResourceConfig {
	t.Helper()
	for _, r := range resources {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("resource %q not found in effective config", name)
	return stewardtypes.ResourceConfig{}
}

// TestGetConfiguration_RolePrecedence_DeviceBeatsRoleBeatsCluster verifies the cascade
// precedence for a single resource name shared across cluster-policies, role-policies and
// device level: device beats role, role beats cluster. Exercised end-to-end through the
// real roleConfigAdapter + clusterRegistryAdapter wired by NewConfigurationServiceV2
// (Issue #2546 — no test stubs; real components only).
func TestGetConfiguration_RolePrecedence_DeviceBeatsRoleBeatsCluster(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)
	ts := newTestTagStore(t)

	require.NoError(t, sm.GetTenantStore().CreateTenant(ctx,
		&business.TenantData{ID: "tenant-c", Name: "Tenant C", Status: business.TenantStatusActive}))

	controllerSvc := NewControllerService(logger)
	controllerSvc.SetTagStore(ts)

	tenantCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-c")

	// Both stewards are tagged "shared-role" so the role selector matches.
	regDev, err := controllerSvc.AcceptRegistration(tenantCtx, &controllerpb.RegisterRequest{
		InitialDna: makeTestDNA("steward-dev", map[string]string{"os": "linux", "hostname": "dev-host"}),
	})
	require.NoError(t, err)
	devID := regDev.StewardId

	regNoDev, err := controllerSvc.AcceptRegistration(tenantCtx, &controllerpb.RegisterRequest{
		InitialDna: makeTestDNA("steward-nodev", map[string]string{"os": "linux", "hostname": "nodev-host"}),
	})
	require.NoError(t, err)
	noDevID := regNoDev.StewardId

	require.NoError(t, ts.Set(ctx, devID, []string{"shared-role"}))
	require.NoError(t, ts.Set(ctx, noDevID, []string{"shared-role"}))

	// Cluster-policies sets shared=cluster.
	require.NoError(t, sm.GetConfigStore().StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "tenant-c", Namespace: "cluster-policies", Name: "my-cluster"},
		Data: marshalStewardConfigYAML(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "shared", Module: "file", Config: map[string]interface{}{"value": "cluster"}},
			},
		}),
		Format: cfgconfig.ConfigFormatYAML,
	}))

	// Role-policies sets shared=role, matched via tag:shared-role.
	storeRoleConfig(t, sm.GetConfigStore(), "tenant-c", "shared-role", "tag:shared-role",
		stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "shared", Module: "file", Config: map[string]interface{}{"value": "role"}},
			},
		},
	)

	svc := NewConfigurationServiceV2(logger, sm, controllerSvc)

	// steward-dev: device-level sets shared=device → device must win over role and cluster.
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-c", devID, &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: devID, Mode: stewardtypes.ModeController},
		Modules: map[string]string{"file": "file"},
		Resources: []stewardtypes.ResourceConfig{
			{Name: "shared", Module: "file", Config: map[string]interface{}{"value": "device"}},
		},
	}))
	// steward-nodev: no device-level "shared" resource.
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-c", noDevID, &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: noDevID, Mode: stewardtypes.ModeController},
	}))

	effDev, err := svc.GetEffectiveConfiguration(ctx, "tenant-c", devID)
	require.NoError(t, err)
	sharedDev := findResource(t, effDev.Config.Resources, "shared")
	assert.Equal(t, "device", sharedDev.Config["value"],
		"device-level must win over both role and cluster for the same resource name")

	effNoDev, err := svc.GetEffectiveConfiguration(ctx, "tenant-c", noDevID)
	require.NoError(t, err)
	sharedNoDev := findResource(t, effNoDev.Config.Resources, "shared")
	assert.Equal(t, "role", sharedNoDev.Config["value"],
		"role-level must win over cluster-policies when no device config is present")
}

// TestGetConfiguration_MalformedRoleConfig_IsNonFatal verifies that a malformed role-policies
// entry is skipped by the real roleConfigAdapter without failing resolution: a valid sibling
// role still applies and device-level config still appears. This is the real-component
// equivalent of the resolver's "role provider hiccup is non-fatal" contract (Issue #2546).
func TestGetConfiguration_MalformedRoleConfig_IsNonFatal(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)
	ts := newTestTagStore(t)

	require.NoError(t, sm.GetTenantStore().CreateTenant(ctx,
		&business.TenantData{ID: "tenant-d", Name: "Tenant D", Status: business.TenantStatusActive}))

	controllerSvc := NewControllerService(logger)
	controllerSvc.SetTagStore(ts)

	tenantCtx := context.WithValue(ctx, ctxkeys.TenantID, "tenant-d")
	reg, err := controllerSvc.AcceptRegistration(tenantCtx, &controllerpb.RegisterRequest{
		InitialDna: makeTestDNA("steward-d", map[string]string{"os": "linux", "hostname": "steward-d-host"}),
	})
	require.NoError(t, err)
	stewardID := reg.StewardId
	require.NoError(t, ts.Set(ctx, stewardID, []string{"good-role"}))

	// Malformed role-policies entry: not valid JSON. The adapter must skip it (logged warn),
	// not fail resolution.
	require.NoError(t, sm.GetConfigStore().StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "tenant-d", Namespace: "role-policies", Name: "broken-role"},
		Data:   []byte("{{{not valid json"),
		Format: cfgconfig.ConfigFormatJSON,
	}))

	// Valid sibling role config matching the steward's tag.
	storeRoleConfig(t, sm.GetConfigStore(), "tenant-d", "good-role", "tag:good-role",
		stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "good-resource", Module: "file"},
			},
		},
	)

	svc := NewConfigurationServiceV2(logger, sm, controllerSvc)
	require.NoError(t, svc.SetConfiguration(ctx, "tenant-d", stewardID, &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{ID: stewardID, Mode: stewardtypes.ModeController},
		Modules: map[string]string{"file": "file"},
		Resources: []stewardtypes.ResourceConfig{
			{Name: "device-resource", Module: "file", Config: map[string]interface{}{"path": "/tmp/x"}},
		},
	}))

	eff, err := svc.GetEffectiveConfiguration(ctx, "tenant-d", stewardID)
	require.NoError(t, err, "malformed role config must not fail resolution")

	names := make(map[string]bool)
	for _, r := range eff.Config.Resources {
		names[r.Name] = true
	}
	assert.True(t, names["device-resource"],
		"device-level resource must appear despite malformed role config")
	assert.True(t, names["good-resource"],
		"valid sibling role resource must still apply despite the malformed sibling")
}

// TestFlattenDNAFragments_SelectorRelevantKeys verifies that the selector-relevant
// keys used by MatchingRoleFragments (os, arch, runtime_os) are correctly extracted
// from DNA fragments. This is the required AC test for the flattenDNAFragments helper
// added by Issue #3325.
func TestFlattenDNAFragments_SelectorRelevantKeys(t *testing.T) {
	frags := []*commonpb.Fragment{
		mustFragment("host:os", map[string]interface{}{
			"os":         "linux",
			"runtime_os": "linux",
		}),
		mustFragment("host:cpu", map[string]interface{}{
			"arch":     "amd64",
			"cpu_arch": "x86_64",
		}),
	}

	flat := flattenDNAFragments(&commonpb.DNA{Fragments: frags})

	assert.Equal(t, "linux", flat["os"], "os key must be flattened from host:os fragment")
	assert.Equal(t, "linux", flat["runtime_os"], "runtime_os key must be flattened from host:os fragment")
	assert.Equal(t, "amd64", flat["arch"], "arch key must be flattened from host:cpu fragment")
	assert.Equal(t, "x86_64", flat["cpu_arch"], "cpu_arch key must be flattened from host:cpu fragment")
}
