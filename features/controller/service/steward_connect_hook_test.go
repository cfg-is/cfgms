// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestStewardRegistryConnectHook_UpsertsAbsentStewardOnConnect drives the real
// connect-hook path (the same OnConnect the gRPC provider calls on session
// establishment) and proves an absent-but-durably-known steward is repopulated
// with its authoritative tenant (Issue #2008 PRIMARY fix).
func TestStewardRegistryConnectHook_UpsertsAbsentStewardOnConnect(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))
	require.NoError(t, storage.SetDeviceTenant(ctx, "dev-1", "tenant-a"))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	hook := NewStewardRegistryConnectHook(svc, logging.NewNoopLogger())

	_, found := svc.GetStewardInfo("dev-1")
	require.False(t, found, "precondition: steward absent before connect")

	// Same call the gRPC provider makes: stewardID is the mTLS-authenticated CN.
	require.NoError(t, hook.OnConnect(ctx, "dev-1"))

	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok, "connect hook must upsert the absent steward")
	assert.Equal(t, "active", info.Status)
	assert.Equal(t, "tenant-a", info.TenantID)
}

// TestStewardRegistryConnectHook_Idempotent proves repeated connects (the normal
// reconnect cadence) do not duplicate the registry entry.
func TestStewardRegistryConnectHook_Idempotent(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()
	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))
	require.NoError(t, storage.SetDeviceTenant(ctx, "dev-1", "tenant-a"))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	hook := NewStewardRegistryConnectHook(svc, logging.NewNoopLogger())

	require.NoError(t, hook.OnConnect(ctx, "dev-1"))
	require.NoError(t, hook.OnConnect(ctx, "dev-1"))

	assert.Equal(t, 1, svc.GetStewardCount(), "repeated connects must not duplicate the steward")
}

// stubHook is a minimal in-package StewardOnConnectHook used to exercise the
// composite ordering and error handling. It is a test double for an arbitrary
// hook, not a mock of any CFGMS component.
type stubHook struct {
	calls *[]string
	name  string
	err   error
}

func (s *stubHook) OnConnect(_ context.Context, _ string) error {
	*s.calls = append(*s.calls, s.name)
	return s.err
}

// TestCompositeOnConnectHook_RunsAllHooksInOrder proves the composite drives
// every chained hook so the signing-cert refresh and admin-registry upsert both
// fire on a single connect.
func TestCompositeOnConnectHook_RunsAllHooksInOrder(t *testing.T) {
	var calls []string
	h1 := &stubHook{calls: &calls, name: "first"}
	h2 := &stubHook{calls: &calls, name: "second"}

	composite := NewCompositeOnConnectHook(logging.NewNoopLogger(), h1, h2)
	require.NoError(t, composite.OnConnect(context.Background(), "dev-1"))

	assert.Equal(t, []string{"first", "second"}, calls)
}

// TestCompositeOnConnectHook_ContinuesAfterError proves one hook's failure does
// not skip later hooks (e.g. a signing-push failure must not prevent the
// registry upsert), and the first error is surfaced for fail-open logging.
func TestCompositeOnConnectHook_ContinuesAfterError(t *testing.T) {
	var calls []string
	boom := errors.New("boom")
	h1 := &stubHook{calls: &calls, name: "failing", err: boom}
	h2 := &stubHook{calls: &calls, name: "registry"}

	composite := NewCompositeOnConnectHook(logging.NewNoopLogger(), h1, h2)
	err := composite.OnConnect(context.Background(), "dev-1")

	require.ErrorIs(t, err, boom)
	assert.Equal(t, []string{"failing", "registry"}, calls, "later hooks must run even after an earlier hook errors")
}

// TestCompositeOnConnectHook_SkipsNilHooks proves nil hooks passed to the
// constructor are filtered (server.go composes optionally-constructed hooks).
func TestCompositeOnConnectHook_SkipsNilHooks(t *testing.T) {
	var calls []string
	h := &stubHook{calls: &calls, name: "only"}

	composite := NewCompositeOnConnectHook(logging.NewNoopLogger(), nil, h, nil)
	require.NoError(t, composite.OnConnect(context.Background(), "dev-1"))

	assert.Equal(t, []string{"only"}, calls)
}

// TestCompositeOnConnectHook_RealRegistryHookFiresAfterEarlierError proves the
// production wiring's fail-open contract end-to-end: with a REAL
// StewardRegistryConnectHook (real SQLite storage, durable tenant seeded) as the
// SECOND element behind a FIRST hook that errors (mirroring a signing-cert push
// failure), the registry upsert still fires AND the first hook's error is
// surfaced — the stream is never refused. This is the scenario that matters at
// runtime: a signing-rotation failure must not leave a reconnecting steward
// invisible to list/status/exec.
func TestCompositeOnConnectHook_RealRegistryHookFiresAfterEarlierError(t *testing.T) {
	storage := newTestFleetStorage(t)
	ctx := context.Background()

	dna := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	require.NoError(t, storage.Store(ctx, "dev-1", dna, &fleetStorage.StoreOptions{TenantID: "tenant-a", Status: "registered"}))
	require.NoError(t, storage.SetDeviceTenant(ctx, "dev-1", "tenant-a"))

	svc := NewControllerServiceWithStorage(logging.NewNoopLogger(), storage)
	realRegistryHook := NewStewardRegistryConnectHook(svc, logging.NewNoopLogger())

	var calls []string
	firstErr := errors.New("signing push failed")
	failing := &stubHook{calls: &calls, name: "signing", err: firstErr}

	composite := NewCompositeOnConnectHook(logging.NewNoopLogger(), failing, realRegistryHook)

	_, found := svc.GetStewardInfo("dev-1")
	require.False(t, found, "precondition: steward absent before connect")

	err := composite.OnConnect(ctx, "dev-1")

	// (b) the first hook's error is surfaced (fail-open: logged by the provider,
	// stream not refused).
	require.ErrorIs(t, err, firstErr, "the earlier hook's error must be surfaced")

	// (a) the registry upsert still fired despite the earlier error.
	info, ok := svc.GetStewardInfo("dev-1")
	require.True(t, ok, "registry upsert must fire even when an earlier hook errors")
	assert.Equal(t, "active", info.Status)
	assert.Equal(t, "tenant-a", info.TenantID)
}
