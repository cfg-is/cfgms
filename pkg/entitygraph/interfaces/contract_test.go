// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package interfaces_test contains contract tests for the EntityGraphProvider.
//
// RunEntityGraphContractTests is the shared harness; each round story adds
// subtests here. Parallel stories may produce rebase conflicts on this file —
// resolve by merging both diffs, never by re-serializing the rounds.
//
// Usage:
//
//	func TestMyProvider_ContractSuite(t *testing.T) {
//		interfaces.RunEntityGraphContractTests(t, func(t *testing.T) interfaces.EntityGraphProvider {
//			return myProvider
//		})
//	}
package interfaces_test

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EntityGraphProviderFactory creates an EntityGraphProvider under test.
type EntityGraphProviderFactory func(t *testing.T) interfaces.EntityGraphProvider

// RunEntityGraphContractTests runs the full EntityGraphProvider contract test suite.
// Each contract is a subtest for granular reporting. Grown incrementally as each
// round story lands.
func RunEntityGraphContractTests(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()

	t.Run("ProviderIdentity", func(t *testing.T) {
		testEGProviderIdentity(t, factory)
	})
	t.Run("ProviderAvailable", func(t *testing.T) {
		testEGProviderAvailable(t, factory)
	})
}

func testEGProviderIdentity(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	assert.NotEmpty(t, p.Name(), "provider name must not be empty")
	assert.NotEmpty(t, p.Description(), "provider description must not be empty")
}

func testEGProviderAvailable(t *testing.T, factory EntityGraphProviderFactory) {
	t.Helper()
	p := factory(t)
	// Available must not error — the noop provider is always available.
	ok, err := p.Available()
	assert.NoError(t, err)
	assert.True(t, ok)
}

// --- Registry tests ---

func TestRegistry_RegisterAndLookup(t *testing.T) {
	// Use unique names to avoid collisions with other tests.
	p1 := &noopProvider{name: "reg-test-alpha"}
	p2 := &noopProvider{name: "reg-test-beta"}

	require.NoError(t, interfaces.RegisterEntityGraphProvider(p1))
	require.NoError(t, interfaces.RegisterEntityGraphProvider(p2))

	got1, err := interfaces.GetEntityGraphProvider("reg-test-alpha")
	require.NoError(t, err)
	assert.Equal(t, p1.Name(), got1.Name())

	got2, err := interfaces.GetEntityGraphProvider("reg-test-beta")
	require.NoError(t, err)
	assert.Equal(t, p2.Name(), got2.Name())

	t.Cleanup(func() {
		interfaces.UnregisterEntityGraphProvider("reg-test-alpha")
		interfaces.UnregisterEntityGraphProvider("reg-test-beta")
	})
}

func TestRegistry_DuplicateNameRejected(t *testing.T) {
	p := &noopProvider{name: "reg-test-dup"}
	require.NoError(t, interfaces.RegisterEntityGraphProvider(p))
	t.Cleanup(func() { interfaces.UnregisterEntityGraphProvider("reg-test-dup") })

	dup := &noopProvider{name: "reg-test-dup"}
	err := interfaces.RegisterEntityGraphProvider(dup)
	require.Error(t, err, "registering a duplicate name must return an error")
}

func TestRegistry_LookupMissing(t *testing.T) {
	_, err := interfaces.GetEntityGraphProvider("no-such-provider-xyzzy")
	require.Error(t, err)
}

// --- Compile-time assertion ---

// Verify that noopProvider satisfies the full EntityGraphProvider interface.
// This is not a real provider — house rule: no memory-only storage for durable
// features. It exists only to enforce the interface at compile time.
var _ interfaces.EntityGraphProvider = (*noopProvider)(nil)

// noopProvider is a minimal stub that satisfies EntityGraphProvider at compile
// time. All methods return zero values or ErrNotImplemented.
type noopProvider struct {
	name string
}

func (n *noopProvider) Name() string        { return n.name }
func (n *noopProvider) Description() string { return "noop provider for compile-time assertion" }
func (n *noopProvider) Available() (bool, error) {
	return true, nil
}

func (n *noopProvider) GetEntity(_ context.Context, _ interfaces.EIDRef, _ interfaces.GetEntityOpts) (*types.EntityView, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetDesiredState(_ context.Context, _ interfaces.EIDRef) (*types.DesiredStateView, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetDriftState(_ context.Context, _ interfaces.EIDRef) (*interfaces.DriftState, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) QueryEntities(_ context.Context, _ interfaces.EntityFilter, _ interfaces.PageToken) (*interfaces.EntityPage, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetEdges(_ context.Context, _ interfaces.EdgeFilter) ([]*interfaces.EdgeView, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetNeighborhood(_ context.Context, _ interfaces.EIDRef, _ []string, _ types.TraversalDirection, _ int) (*types.Neighborhood, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetHistory(_ context.Context, _ interfaces.EIDRef, _ interfaces.TimeRange) ([]*interfaces.ObservationRecord, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) Diff(_ context.Context, _ interfaces.EIDRef, _ interfaces.TimeRange) (*interfaces.StateDiff, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) GetTimeline(_ context.Context, _ []interfaces.EIDRef, _ interfaces.TimeRange) ([]*interfaces.TimelineEvent, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) ListDrifted(_ context.Context, _ interfaces.DriftFilter) ([]*interfaces.DriftState, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) Watch(_ context.Context, _ interfaces.WatchFilter, _ string) (<-chan interfaces.WatchEvent, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) ResolveIdentity(_ context.Context, _ interfaces.IdentityClaims) ([]interfaces.EIDRef, error) {
	return nil, interfaces.ErrNotImplemented
}
func (n *noopProvider) ReportObservations(_ context.Context, _ interfaces.ObservationBatch) error {
	return interfaces.ErrNotImplemented
}
func (n *noopProvider) UpdateDriftLifecycle(_ context.Context, _ interfaces.DriftLifecycleUpdate) error {
	return interfaces.ErrNotImplemented
}
