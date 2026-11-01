// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package client

// End-to-end proof of the cluster signing identity (Issue #4798, epic #4687):
// three controller nodes over shared stores and stewards running their real
// command and push handlers. See signing_identity_cluster_helpers_test.go for the
// harness and why it lives in this package.

import (
	"context"
	"encoding/base64"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// sharedSerial is the serial all three nodes sign with, after asserting they agree.
func (c *signingCluster) sharedSerial() string {
	c.t.Helper()
	want := c.currentSerial(0)
	require.NotEmpty(c.t, want)
	for i := range c.nodes {
		require.Equal(c.t, want, c.currentSerial(i), "node %d must sign with the shared serial", i+1)
	}
	return want
}

func (c *signingCluster) requireSharedMode() {
	c.t.Helper()
	for i, n := range c.nodes {
		mode, err := n.mgr.SigningIdentityMode(context.Background())
		require.NoError(c.t, err)
		require.Equal(c.t, cert.SigningIdentityShared, mode, "node %d", i+1)
	}
}

// requireAcceptsFromEveryNode asserts the steward accepts a command and a config
// signed through each of the three nodes.
func (c *signingCluster) requireAcceptsFromEveryNode(st *clusterSteward) {
	c.t.Helper()
	for i := range c.nodes {
		assert.True(c.t, c.sendCommand(i, st), "steward %s must accept a command signed via node %d", st.id, i+1)
		assert.True(c.t, c.acceptsConfig(i, st), "steward %s must accept a config signed via node %d", st.id, i+1)
	}
}

// TestClusterSigning_FreshClusterStewardWorksThroughEveryNode: a steward enrolled
// through node 1 accepts commands and configs signed via node 2 and node 3.
func TestClusterSigning_FreshClusterStewardWorksThroughEveryNode(t *testing.T) {
	c := newSigningCluster(t, clusterOpts{})
	c.requireSharedMode()
	shared := c.sharedSerial()

	// Enrolled through node 1: it receives the shared certificate there.
	st := c.newSteward("steward-fresh", c.certPEM(0, shared))
	c.connect(st, 0)
	st.awaitTrust(t, "trusts the shared certificate", c.fingerprintOfSerial(0, shared))

	c.requireAcceptsFromEveryNode(st)

	// No node holds the shared signing key on disk.
	for i, n := range c.nodes {
		assert.Empty(t, signingKeyFiles(t, n.dir), "node %d must not keep a signing key.pem", i+1)
	}

	// The steward moves between nodes without losing anything.
	c.disconnect(st)
	c.connect(st, 2)
	c.requireAcceptsFromEveryNode(st)
	assert.Equal(t, []string{c.fingerprintOfSerial(2, shared)}, st.trust())
}

// TestClusterSigning_OfflineRotationReconnectsThroughAnotherNode: a steward that is
// offline for a rotation performed through node 2 reconnects through node 3 and
// accepts commands and configs after the on-connect push.
func TestClusterSigning_OfflineRotationReconnectsThroughAnotherNode(t *testing.T) {
	c := newSigningCluster(t, clusterOpts{})
	runOfflineRotation(t, c)
}

func runOfflineRotation(t *testing.T, c *signingCluster) {
	t.Helper()
	ctx := context.Background()
	original := c.sharedSerial()
	st := c.newSteward("steward-offline", c.certPEM(0, original))
	c.connect(st, 0)
	st.awaitTrust(t, "enrolled on the original certificate", c.fingerprintOfSerial(0, original))
	c.disconnect(st)

	transitionsBefore := c.cursor.count()
	res, err := c.nodes[1].rotation.Rotate(rootCtx(), "operator-serial", 7, false)
	require.NoError(t, err)
	assert.Equal(t, original, res.OldSerial)
	assert.NotEqual(t, original, res.NewSerial, "one new serial")
	assert.Equal(t, "node-2", res.NodeID)

	// One cluster-wide cursor transition, one new certificate in the shared store.
	assert.Equal(t, transitionsBefore+1, c.cursor.count(), "exactly one cursor transition")
	cursor, err := c.stores.cursor.LoadCursor(ctx)
	require.NoError(t, err)
	assert.Equal(t, res.NewSerial, cursor.CurrentSerial)
	assert.Equal(t, original, cursor.RotatingSerial)
	serials, err := c.keyStore.ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{original, res.NewSerial}, serials)
	c.awaitAllNodesCurrent(res.NewSerial)

	// The offline steward still trusts only the original certificate.
	assert.Equal(t, []string{c.fingerprintOfSerial(0, original)}, st.trust())

	// Reconnect through node 3: the on-connect push delivers the new certificate.
	c.connect(st, 2)
	st.awaitTrust(t, "trusts original and new after the on-connect push",
		c.fingerprintOfSerial(2, original), c.fingerprintOfSerial(2, res.NewSerial))
	c.requireAcceptsFromEveryNode(st)
}

// TestClusterSigning_MigrationMovesEveryStewardToTheElectedCertificate: a cluster
// whose three nodes each hold a different local signer, with stewards trusting
// different node keys, migrates to the elected shared certificate.
func TestClusterSigning_MigrationMovesEveryStewardToTheElectedCertificate(t *testing.T) {
	ctx := context.Background()
	c := newSigningCluster(t, clusterOpts{legacy: true})

	for i, n := range c.nodes {
		mode, err := n.mgr.SigningIdentityMode(ctx)
		require.NoError(t, err)
		require.Equal(t, cert.SigningIdentityLegacyLocal, mode, "node %d starts on its own local signer", i+1)
		require.Len(t, signingKeyFiles(t, n.dir), 1, "node %d holds its local signing key", i+1)
	}
	require.NotEqual(t, c.nodes[0].localSerial, c.nodes[1].localSerial)
	require.NotEqual(t, c.nodes[1].localSerial, c.nodes[2].localSerial)

	// Each steward trusts a different node's key and is connected to another node.
	stewards := []*clusterSteward{
		c.newSteward("steward-trusts-1", c.nodes[0].localPEM),
		c.newSteward("steward-trusts-2", c.nodes[1].localPEM),
		c.newSteward("steward-trusts-3", c.nodes[2].localPEM),
	}
	c.connect(stewards[0], 2)
	c.connect(stewards[1], 0)
	c.connect(stewards[2], 1)

	// Election: the operator names node 1's certificate. Every node promotes it
	// and removes its local key.
	elected := c.nodes[0].localSerial
	_, created, err := c.nodes[0].mgr.ElectSharedSigningSerial(ctx, elected)
	require.NoError(t, err)
	require.True(t, created)
	for _, n := range c.nodes {
		require.NoError(t, n.local.Run(ctx))
	}
	c.requireSharedMode()
	// A node caches the identity it resolved for a few seconds, so the nodes reach
	// the elected serial within that bound.
	c.awaitAllNodesCurrent(elected)

	// The transition window: until a steward confirms, one that trusts only a
	// legacy node key other than the elected one rejects what the cluster signs now.
	assert.False(t, c.sendCommand(1, stewards[1]), "a legacy-only steward rejects a command signed by the shared key")
	assert.False(t, c.acceptsConfig(1, stewards[1]))

	for _, n := range c.nodes {
		n.migration.Start(ctx)
	}

	// Every connected steward is confirmed in the acknowledgement store.
	require.Eventually(t, func() bool {
		for _, st := range stewards {
			ack, aerr := c.stores.acks.GetAck(ctx, st.id, elected)
			if aerr != nil || ack == nil {
				return false
			}
		}
		return true
	}, 30*time.Second, 20*time.Millisecond, "every connected steward is confirmed")
	acked, err := c.stores.acks.ListAcked(ctx, elected)
	require.NoError(t, err)
	assert.Len(t, acked, len(stewards))

	// Each steward trusts only the shared certificate.
	sharedFP := c.fingerprintOfSerial(0, elected)
	for _, st := range stewards {
		st.awaitTrust(t, st.id+" trusts the shared certificate only", sharedFP)
	}

	// Commands and configs signed via any node are accepted.
	for _, st := range stewards {
		c.requireAcceptsFromEveryNode(st)
	}

	// No signing key.pem remains in any node certificate directory.
	for i, n := range c.nodes {
		assert.Empty(t, signingKeyFiles(t, n.dir), "node %d must not keep a signing key.pem", i+1)
	}
}

// TestClusterSigning_RetirementRemovesSupersededCertificate: after the overlap
// window ends the superseded certificate is removed from stewards — connected ones
// by the sweep, a reconnecting one by its on-connect push.
func TestClusterSigning_RetirementRemovesSupersededCertificate(t *testing.T) {
	ctx := context.Background()
	c := newSigningCluster(t, clusterOpts{})
	original := c.sharedSerial()

	online := c.newSteward("steward-online", c.certPEM(0, original))
	away := c.newSteward("steward-away", c.certPEM(0, original))
	c.connect(online, 0)
	c.connect(away, 1)
	online.awaitTrust(t, "online enrolled", c.fingerprintOfSerial(0, original))
	away.awaitTrust(t, "away enrolled", c.fingerprintOfSerial(0, original))
	c.disconnect(away)

	// Zero overlap: the window is closed as soon as the rotation commits.
	res, err := c.nodes[1].rotation.Rotate(rootCtx(), "operator-serial", 0, false)
	require.NoError(t, err)
	c.awaitAllNodesCurrent(res.NewSerial)
	newFP := c.fingerprintOfSerial(0, res.NewSerial)
	oldFP := c.fingerprintOfSerial(0, original)
	online.awaitTrust(t, "online holds both until the sweep", oldFP, newFP)

	// Before the sweep nothing is retired.
	assert.Equal(t, []string{oldFP}, away.trust())

	// The sweep runs on node 3: the connected steward drops the old certificate.
	notified, err := c.nodes[2].retire.Sweep(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, notified, "only the connected steward is reached")
	online.awaitTrust(t, "online trusts only the new certificate", newFP)
	cursor, err := c.stores.cursor.LoadCursor(ctx)
	require.NoError(t, err)
	require.NotNil(t, cursor.RetiredAt, "the cursor records the retirement")

	// A second sweep on another node has nothing left to do.
	notified, err = c.nodes[0].retire.Sweep(ctx)
	require.NoError(t, err)
	assert.Zero(t, notified)

	// The steward that was away reconnects through node 1: one on-connect push
	// carries the new certificate and the retirement.
	assert.Equal(t, []string{oldFP}, away.trust())
	c.connect(away, 0)
	away.awaitTrust(t, "away trusts only the new certificate after reconnecting", newFP)

	c.requireAcceptsFromEveryNode(online)
	c.requireAcceptsFromEveryNode(away)
}

// TestClusterSigning_EmergencyRevokeWithdrawsSerialAndNeverSignsAgain: a named
// signing serial is withdrawn from stewards and never used for signing afterwards;
// revoking the current serial is refused.
func TestClusterSigning_EmergencyRevokeWithdrawsSerialAndNeverSignsAgain(t *testing.T) {
	c := newSigningCluster(t, clusterOpts{})
	original := c.sharedSerial()

	online := c.newSteward("steward-online", c.certPEM(0, original))
	away := c.newSteward("steward-away", c.certPEM(0, original))
	c.connect(online, 0)
	c.connect(away, 1)
	c.disconnect(away)

	// A rotation with a long overlap leaves the original as the rotating serial.
	res, err := c.nodes[0].rotation.Rotate(rootCtx(), "operator-serial", 30, false)
	require.NoError(t, err)
	c.awaitAllNodesCurrent(res.NewSerial)
	oldFP := c.fingerprintOfSerial(0, original)
	newFP := c.fingerprintOfSerial(0, res.NewSerial)
	online.awaitTrust(t, "online holds both during the overlap", oldFP, newFP)

	// The current serial cannot be revoked.
	_, err = c.nodes[1].retire.Revoke(rootCtx(), "operator-serial", res.NewSerial, "attempt")
	require.ErrorIs(t, err, cert.ErrRevokeCurrentSigningCert)
	revoked, err := c.nodes[0].mgr.IsRevoked(res.NewSerial)
	require.NoError(t, err)
	assert.False(t, revoked, "a refused revoke records nothing")

	// Revoke the original through node 3.
	out, err := c.nodes[2].retire.Revoke(rootCtx(), "operator-serial", original, "key exposure")
	require.NoError(t, err)
	assert.Equal(t, 1, out.StewardsNotified, "only the connected steward is reached")
	assert.True(t, out.RetiredFromCursor)
	online.awaitTrust(t, "online no longer trusts the revoked serial", newFP)

	// Every node sees the revocation, and none signs with the revoked key again.
	revokedVerifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: c.certPEM(0, original)})
	require.NoError(t, err)
	payload := []byte("after-revoke")
	for i, n := range c.nodes {
		isRevoked, rerr := n.mgr.IsRevoked(original)
		require.NoError(t, rerr)
		assert.True(t, isRevoked, "node %d sees the revocation", i+1)
		sig, serr := n.signer.Sign(payload)
		require.NoError(t, serr)
		assert.Error(t, revokedVerifier.Verify(payload, sig), "node %d must not sign with the revoked key", i+1)
	}
	c.requireAcceptsFromEveryNode(online)

	// The steward that was away reconnects through node 2. It trusts only the
	// revoked serial, so the one delivery that retires it is signed with it; after
	// that the steward holds the new certificate alone.
	assert.Equal(t, []string{oldFP}, away.trust())
	c.connect(away, 1)
	away.awaitTrust(t, "away trusts only the new certificate after reconnecting", newFP)
	c.requireAcceptsFromEveryNode(away)
}

// TestClusterSigning_ForeignCAPushRefusedAndRepeatedPushesDoNotGrowTrust: the
// steward hardening holds in the cluster flow.
func TestClusterSigning_ForeignCAPushRefusedAndRepeatedPushesDoNotGrowTrust(t *testing.T) {
	ctx := context.Background()
	c := newSigningCluster(t, clusterOpts{})
	original := c.sharedSerial()
	st := c.newSteward("steward-hardening", c.certPEM(0, original))
	c.connect(st, 0)

	res, err := c.nodes[1].rotation.Rotate(rootCtx(), "operator-serial", 7, false)
	require.NoError(t, err)
	c.awaitAllNodesCurrent(res.NewSerial)
	want := []string{c.fingerprintOfSerial(0, original), c.fingerprintOfSerial(0, res.NewSerial)}
	st.awaitTrust(t, "holds original and new", want...)

	// A certificate from a foreign CA, pushed in a command signed by a key the
	// steward trusts, is refused.
	foreign := newCodeSigningCertBase64(t, newTestCA(t))
	foreignCmd, err := c.nodes[2].pub.PublishCommand(ctx, st.id, cpTypes.CommandPushSigningCert, map[string]interface{}{
		"cert_pem": foreign,
	})
	require.NoError(t, err)
	st.mu.Lock()
	_, authFailed := st.rejected[foreignCmd]
	st.mu.Unlock()
	require.False(t, authFailed, "the command itself is authentic: the refusal below is the steward's chain check")
	foreignFP := fingerprintOfPEM(t, mustDecodeBase64(t, foreign))
	require.Never(t, func() bool {
		for _, fp := range st.trust() {
			if fp == foreignFP {
				return true
			}
		}
		return false
	}, 500*time.Millisecond, 20*time.Millisecond, "a foreign-CA certificate must never enter the trust set")
	assert.Equal(t, sortedCopy(want), st.trust())

	// Repeated on-connect pushes, through every node, do not grow the trust set.
	for i := 0; i < 6; i++ {
		c.disconnect(st)
		c.connect(st, i%3)
	}
	require.Never(t, func() bool { return len(st.trust()) != len(want) },
		500*time.Millisecond, 20*time.Millisecond, "the trust set must not grow")
	assert.Equal(t, sortedCopy(want), st.trust())
	c.requireAcceptsFromEveryNode(st)
}

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return b
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// TestClusterSigning_OfflineRotationWithPostgresStores runs the offline-rotation
// scenario over PostgreSQL cursor, acknowledgement and revocation stores. It skips
// without CFGMS_TEST_DB_*.
func TestClusterSigning_OfflineRotationWithPostgresStores(t *testing.T) {
	stores := pgClusterStores(t)
	c := newSigningCluster(t, clusterOpts{stores: &stores})
	runOfflineRotation(t, c)
}
