// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalProofContextRoundTrip(t *testing.T) {
	_, ok := TerminalProofFromContext(context.Background())
	assert.False(t, ok, "an empty context carries no proof")

	_, ok = TerminalProofFromContext(WithTerminalProof(context.Background(), nil))
	assert.False(t, ok, "a nil proof is not a proof")

	p := &TerminalProof{StewardID: "s", TenantID: "t", TerminalShell: "bash"}
	got, ok := TerminalProofFromContext(WithTerminalProof(context.Background(), p))
	require.True(t, ok)
	assert.Same(t, p, got)
}
