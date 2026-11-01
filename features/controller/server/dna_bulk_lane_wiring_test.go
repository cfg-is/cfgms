// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	modulecache "github.com/cfgis/cfgms/features/controller/modules/cache"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// bulkWiringCP is the control plane under both the heartbeat service and the
// command publisher: it hands the test the heartbeat handler and records every
// command the publisher sends.
type bulkWiringCP struct {
	cpinterfaces.ControlPlaneProvider
	mu       sync.Mutex
	hbHandle cpinterfaces.HeartbeatHandler
	sent     []*cpTypes.SignedCommand
}

func (p *bulkWiringCP) SubscribeHeartbeats(_ context.Context, h cpinterfaces.HeartbeatHandler) error {
	p.hbHandle = h
	return nil
}

func (p *bulkWiringCP) SendCommand(_ context.Context, c *cpTypes.SignedCommand) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, c)
	return nil
}

func (p *bulkWiringCP) commands() []*cpTypes.SignedCommand {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*cpTypes.SignedCommand(nil), p.sent...)
}

type wiringTenants map[string]string

func (m wiringTenants) TenantForDevice(id string) (string, bool) { t, ok := m[id]; return t, ok }

func perObjectCache(t *testing.T) *modulecache.ModuleCache {
	t.Helper()
	c := makeListObservableCache(t)
	b := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher: "cfgms", Name: "directory", Version: "0.1.0",
		Executors: []string{"steward"},
		ManifestExtra: "always_pull: true\nowns:\n" +
			"  - kind: directory_user\n    per_object: true\n" +
			"  - kind: directory_group\n    per_object: true\n" +
			"  - kind: host_flag\n",
		Platforms:     []string{"linux-amd64"},
		BinaryContent: map[string][]byte{"linux-amd64": []byte("binary directory")},
	}).Bundle
	putApproved(t, c, b)
	return c
}

func TestModuleManifestAdapter_ListPerObjectKinds(t *testing.T) {
	adapter := &moduleManifestAdapter{cache: perObjectCache(t)}
	kinds, err := adapter.ListPerObjectKinds("tenant-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"directory_group", "directory_user"}, kinds,
		"only PerObject Owns entries of approved manifests are per-object kinds")

	pending := makeListObservableCache(t)
	b := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher: "cfgms", Name: "directory", Version: "0.1.0", Executors: []string{"steward"},
		ManifestExtra: "always_pull: true\nowns:\n  - kind: directory_user\n    per_object: true\n",
		Platforms:     []string{"linux-amd64"},
		BinaryContent: map[string][]byte{"linux-amd64": []byte("binary pending")},
	}).Bundle
	putPending(t, pending, b)
	kinds, err = (&moduleManifestAdapter{cache: pending}).ListPerObjectKinds("tenant-1")
	require.NoError(t, err)
	assert.Empty(t, kinds, "an unapproved manifest owns nothing")
}

// A heartbeat carrying dna_bulk_root, through the real heartbeat service, reaches
// the bulk handler wired by Start's wiring step, and the handler's request leaves
// through the real signed command publisher.
func TestWireDNABulkLane_HeartbeatReachesHandlerAndCommandIsPublished(t *testing.T) {
	cp := &bulkWiringCP{}
	hb, err := heartbeat.New(&heartbeat.Config{ControlPlane: cp, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	require.NoError(t, hb.Start(context.Background()))
	t.Cleanup(func() { _ = hb.Stop(context.Background()) })
	pub, err := commands.New(&commands.Config{ControlPlane: cp, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)

	cs := newWiringConfigStore(t)
	srv := &Server{
		logger:                  logging.NewNoopLogger(),
		storageManager:          interfaces.NewStorageManagerFromStores(cs, nil, nil, nil, nil, nil, nil, nil, nil, nil),
		commandPublisher:        pub,
		heartbeatService:        hb,
		observeManifestProvider: &moduleManifestAdapter{cache: perObjectCache(t)},
	}

	h := controllerTransport.NewDNAHandler(logging.NewNoopLogger(), controllerTransport.NewTenantQueue(), nil).
		WithTenantResolver(wiringTenants{"steward-1": "tenant-1"})
	srv.wireDNABulkLane(h)

	require.NotNil(t, cp.hbHandle)
	require.NoError(t, cp.hbHandle(context.Background(), &cpTypes.Heartbeat{
		StewardID: "steward-1", Status: cpTypes.StatusHealthy, Timestamp: time.Now(),
		DNABulkRoot: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}))

	sent := cp.commands()
	require.Len(t, sent, 1, "the bulk root must start exactly one round")
	assert.Equal(t, cpTypes.CommandSyncDNA, sent[0].Command.Type)
	assert.Equal(t, cpTypes.SyncDNABulkBuckets, sent[0].Command.Params[cpTypes.SyncDNAParamBulk])
	assert.Equal(t, "steward-1", sent[0].Command.StewardID)
}

func TestWireDNABulkLane_MissingDependencyLeavesLaneOff(t *testing.T) {
	cp := &bulkWiringCP{}
	hb, err := heartbeat.New(&heartbeat.Config{ControlPlane: cp, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)
	require.NoError(t, hb.Start(context.Background()))
	t.Cleanup(func() { _ = hb.Stop(context.Background()) })

	srv := &Server{logger: logging.NewNoopLogger(), heartbeatService: hb} // no storage, no publisher
	h := controllerTransport.NewDNAHandler(logging.NewNoopLogger(), controllerTransport.NewTenantQueue(), nil)
	srv.wireDNABulkLane(h)

	require.NoError(t, cp.hbHandle(context.Background(), &cpTypes.Heartbeat{
		StewardID: "steward-1", Status: cpTypes.StatusHealthy, Timestamp: time.Now(),
		DNABulkRoot: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}))
	assert.Empty(t, cp.commands())
}

func newWiringConfigStore(t *testing.T) cfgconfig.ConfigStore {
	t.Helper()
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)
	cs, err := p.CreateConfigStore(map[string]interface{}{"root": t.TempDir()})
	require.NoError(t, err)
	return cs
}
