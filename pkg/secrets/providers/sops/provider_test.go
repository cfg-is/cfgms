// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSOPSProvider_ClusterCapable_False(t *testing.T) {
	p := &SOPSProvider{}
	assert.False(t, p.ClusterCapable(), "SOPSProvider must not be cluster-capable (git-backed file store cannot serve as shared state across controller nodes)")
}
