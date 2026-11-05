// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/commands"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

func TestBakedRootReason(t *testing.T) {
	setBaked(t, "")
	assert.Equal(t, cpTypes.ReasonCodeLockedNoBakedRoot, bakedRootReason())

	setBaked(t, "not-a-fingerprint")
	assert.Equal(t, cpTypes.ReasonCodeLockedBakedRootMalformed, bakedRootReason())

	root, _ := makeCert(t, "root", true, nil, nil)
	setBaked(t, fpOf(root))
	assert.Equal(t, "", bakedRootReason())
}

func TestLockedToolsConfig_UsesTheBakedListOnly(t *testing.T) {
	root, _ := makeCert(t, "root", true, nil, nil)
	planted, _ := makeCert(t, "planted", true, nil, nil)
	setBaked(t, fpOf(root))

	cfg := lockedToolsConfig()
	require.NotNil(t, cfg.MatchesBakedRoot)
	assert.True(t, cfg.MatchesBakedRoot(root))
	assert.False(t, cfg.MatchesBakedRoot(planted))
	assert.Equal(t, "", cfg.BakedRootReason())

	setBaked(t, "")
	assert.False(t, cfg.MatchesBakedRoot(root), "no baked root accepts nothing")
	assert.Equal(t, cpTypes.ReasonCodeLockedNoBakedRoot, cfg.BakedRootReason())
}

// The repair path verifies its signer through commands.VerifyLockedSigner, which
// must use this binary's baked list: with none baked it accepts nothing.
func TestVerifyLockedSignerUsesTheBinarysBakedList(t *testing.T) {
	setBaked(t, "")
	assert.Error(t, commands.VerifyLockedSigner([]byte("chain"), []byte("sig"), []byte("data")))
}
