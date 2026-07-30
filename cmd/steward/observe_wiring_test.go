// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// Wiring tests for the Tier-2 whole-domain observe sweep (Issue #3104,
// ADR-024 Amendment 1 §3). These cover the production loader the steward binary
// threads into client.TransportConfig.ObserveModuleLoader.

package main

import (
	"testing"

	"github.com/cfgis/cfgms/features/steward/client"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The production observe loader must satisfy the client's loader contract; if the
// interface changes this fails at compile time rather than silently leaving the
// sweep unwired.
var _ client.ObserveModuleLoader = newObserveModuleLoader("steward-1", nil, logging.NewLogger("error"))

func TestNewObserveModuleLoader_LoadsRealBuiltinModule(t *testing.T) {
	loader := newObserveModuleLoader("steward-1", nil, logging.NewLogger("error"))
	require.NotNil(t, loader)

	mod, err := loader.LoadModule("file")
	require.NoError(t, err, "the observe loader must resolve built-in modules through the factory load path")
	require.NotNil(t, mod)
}

func TestNewObserveModuleLoader_CachesLoadedInstance(t *testing.T) {
	loader := newObserveModuleLoader("steward-1", nil, logging.NewLogger("error"))

	first, err := loader.LoadModule("file")
	require.NoError(t, err)
	second, err := loader.LoadModule("file")
	require.NoError(t, err)

	assert.Same(t, first, second,
		"a module already active must be reused, not re-instantiated on every sweep")
}

func TestNewObserveModuleLoader_UnknownModuleReturnsError(t *testing.T) {
	loader := newObserveModuleLoader("steward-1", nil, logging.NewLogger("error"))

	_, err := loader.LoadModule("no-such-observe-module")
	require.Error(t, err, "an unresolvable module name must surface an error so the sweep can skip it")
}

// TestObserveSweepCadence_DefaultIsActive pins the cadence the steward binary
// applies when no local config file declares observe_sweep_n: the production
// default must be a live cadence, not 0 (sweep disabled).
func TestObserveSweepCadence_DefaultIsActive(t *testing.T) {
	assert.Positive(t, stewardconfig.DefaultObserveSweepN,
		"the shipped Tier-2 cadence default must enable the observe sweep")
	assert.Equal(t, 10, stewardconfig.DefaultObserveSweepN,
		"steward-operating-model.md documents a default of 10 convergence ticks")
}
