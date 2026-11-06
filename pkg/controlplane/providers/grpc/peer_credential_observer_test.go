// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// recordingPeerObserver records the serials it is told about.
type recordingPeerObserver struct {
	mu       sync.Mutex
	revoked  []string
	admitted []string
}

func (r *recordingPeerObserver) ObserveRevokedPeer(_ context.Context, stewardID, serial string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, stewardID+"|"+serial)
}

func (r *recordingPeerObserver) ObserveAdmittedPeer(_ context.Context, stewardID, serial string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.admitted = append(r.admitted, stewardID+"|"+serial)
}

func (r *recordingPeerObserver) snapshot() (revoked, admitted []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.revoked...), append([]string(nil), r.admitted...)
}

func TestPeerCredentialObserver_RevokedSerialIsReportedAndRefused(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	obs := &recordingPeerObserver{}
	server, _ := env.startServer(t, WithRevocationChecker(env.mgr), WithPeerCredentialObserver(obs))
	tlsCfg, serial := env.clientTLS(t, "steward-obs-revoked")
	require.NoError(t, env.mgr.Revoke(serial))

	_, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-obs-revoked", 2*time.Second)
	require.Error(t, err)

	require.Eventually(t, func() bool { r, _ := obs.snapshot(); return len(r) > 0 }, 5*time.Second, 10*time.Millisecond)
	revoked, admitted := obs.snapshot()
	assert.Equal(t, "steward-obs-revoked|"+serial, revoked[0])
	assert.Empty(t, admitted, "a refused connection is never reported as admitted")
}

func TestPeerCredentialObserver_AdmittedSerialIsReportedAndHeartbeatsCarryIt(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	obs := &recordingPeerObserver{}
	server, _ := env.startServer(t, WithRevocationChecker(env.mgr), WithPeerCredentialObserver(obs))
	got := make(chan *controlplaneTypes.Heartbeat, 1)
	require.NoError(t, server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *controlplaneTypes.Heartbeat) error {
		select {
		case got <- hb:
		default:
		}
		return nil
	}))
	tlsCfg, serial := env.clientTLS(t, "steward-obs-ok")

	client, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-obs-ok", 0)
	require.NoError(t, err)
	require.Eventually(t, func() bool { _, a := obs.snapshot(); return len(a) > 0 }, 5*time.Second, 10*time.Millisecond)
	revoked, admitted := obs.snapshot()
	assert.Empty(t, revoked)
	assert.Equal(t, "steward-obs-ok|"+serial, admitted[0])

	require.NoError(t, client.SendHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
		StewardID: "steward-obs-ok", Status: controlplaneTypes.StatusHealthy, Timestamp: time.Now(),
		PeerSerial: "forged-by-the-steward",
	}))
	select {
	case hb := <-got:
		assert.Equal(t, serial, hb.PeerSerial, "the controller stamps the serial of the authenticated stream")
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat not received")
	}
}
