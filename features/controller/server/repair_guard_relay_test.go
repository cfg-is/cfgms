// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// The relay does nothing until the API server is bound.
func TestRepairGuardRelay_UnboundDoesNothing(t *testing.T) {
	g := &repairGuardRelay{logger: logging.NewNoopLogger()}
	ctx := context.Background()
	g.ObserveRevokedPeer(ctx, "s1", "1")
	g.ObserveAdmittedPeer(ctx, "s1", "1")
	g.ObserveIdentityConflict(ctx, "s1")
	g.HandleRepairHeartbeat(ctx, "s1", "1", nil)
}

func TestRepairGuardRelay_LooksAtEachAdmittedSerialOncePerNode(t *testing.T) {
	g := &repairGuardRelay{}
	assert.True(t, g.firstAdmission("s1", "100"))
	assert.False(t, g.firstAdmission("s1", "100"), "a reconnect on the same serial is not looked at again")
	assert.True(t, g.firstAdmission("s1", "101"), "a new serial is")
	assert.True(t, g.firstAdmission("s2", "100"))
}

func TestRepairGuardRelay_RevokedAttemptsAreRateLimitedPerSteward(t *testing.T) {
	g := &repairGuardRelay{}
	now := time.Now()
	assert.True(t, g.allowRevoked("s1", now))
	assert.False(t, g.allowRevoked("s1", now.Add(repairGuardRevokedInterval-time.Second)))
	assert.True(t, g.allowRevoked("s2", now), "another steward is independent")
	assert.True(t, g.allowRevoked("s1", now.Add(repairGuardRevokedInterval)))
}

func TestRepairGuardRelay_TablesAreBounded(t *testing.T) {
	g := &repairGuardRelay{}
	for i := 0; i < repairGuardMaxTracked+10; i++ {
		g.firstAdmission("s", string(rune('a'+i%26))+time.Duration(i).String())
		g.allowRevoked(time.Duration(i).String(), time.Now())
	}
	assert.LessOrEqual(t, len(g.admitted), repairGuardMaxTracked)
	assert.LessOrEqual(t, len(g.lastRevoked), repairGuardMaxTracked)
}

var (
	_ grpcCP.PeerCredentialObserver = (*repairGuardRelay)(nil)
	_ revokedPeerObserver           = (*repairGuardRelay)(nil)
	_ repairConflictGuard           = (*repairGuardRelay)(nil)
)

// recordingConflictGuard records the stewards told about a conflict.
type recordingConflictGuard struct{ ids []string }

func (r *recordingConflictGuard) ObserveIdentityConflict(_ context.Context, id string) {
	r.ids = append(r.ids, id)
}

// The audit observer tells the repair guard about a conflict, once per rate
// limit interval, whether or not it writes the audit event.
func TestIdentityConflictObserver_TellsTheRepairGuard(t *testing.T) {
	am, err := audit.NewManager(pkgtesting.SetupTestStorage(t).GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = am.Stop(context.Background()) })
	guard := &recordingConflictGuard{}
	obs := newIdentityConflictAuditObserver(am, logging.NewNoopLogger()).withRepairGuard(guard)

	conflict := grpcCP.IdentityConflict{StewardID: "s1", TenantID: "t1", DetectedAt: time.Now()}
	obs.ObserveIdentityConflict(context.Background(), conflict)
	obs.ObserveIdentityConflict(context.Background(), conflict)
	assert.Equal(t, []string{"s1"}, guard.ids, "the second inside the interval is dropped")

	noAudit := newIdentityConflictAuditObserver(nil, logging.NewNoopLogger()).withRepairGuard(guard)
	noAudit.ObserveIdentityConflict(context.Background(), grpcCP.IdentityConflict{StewardID: "s2"})
	assert.Equal(t, []string{"s1", "s2"}, guard.ids)
}
