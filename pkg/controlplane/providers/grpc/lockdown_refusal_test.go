// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

// The typed lockdown refusal a tampered steward gets from a pull is not an
// identity rejection: the provider never records one and never starts the
// rejection episode that drives re-admission (Issue #5666).
func TestLockdownRefusal_IsNotAnIdentityRejection(t *testing.T) {
	refusal := interfaces.NewLockedDownError()
	require.True(t, interfaces.IsLockedDown(refusal))

	assert.False(t, isIdentityRejection(refusal))
	assert.False(t, isIdentityRejection(fmt.Errorf("pull failed: %w", refusal)))

	p := New(ModeClient)
	called := make(chan error, 1)
	p.onIdentityRejected = func(err error) { called <- err }
	p.noteStreamRefusal(refusal, p.credGen.Load())

	assert.False(t, p.IdentityRejectionActive(), "no rejection episode may start")
	select {
	case <-p.rejectedCh:
		t.Fatal("markIdentityRejected must not be called")
	default:
	}
	select {
	case err := <-called:
		t.Fatalf("identity-rejected callback ran: %v", err)
	default:
	}
}
