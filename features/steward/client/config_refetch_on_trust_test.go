// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the config re-fetch that follows a signing-cert push
// when an earlier config transfer was signed by a cert the steward did not yet
// trust (Issue #4678).
//
// A steward that missed a rotation reconnects; its on-connect config pull is
// signed with the new cert, and the push_signing_cert carrying that cert is
// applied asynchronously. Without the re-fetch, losing that race leaves the
// steward on stale config until the next convergence tick.
package client

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/execution"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
)

// countingConfigSession returns a fixed config transfer and counts fetches.
type countingConfigSession struct {
	testDataPlaneSession
	transfer *dpTypes.ConfigTransfer
	fetches  atomic.Int32
}

func (s *countingConfigSession) ReceiveConfig(_ context.Context) (*dpTypes.ConfigTransfer, error) {
	s.fetches.Add(1)
	return s.transfer, nil
}

// newRotatedClient returns a client that trusts only oldPEM, a session serving
// config signed by a different (rotated-to) cert, and that cert's PEM.
func newRotatedClient(t *testing.T) (*TransportClient, *countingConfigSession, *eventCapture, string) {
	t.Helper()
	const stewardID = "steward-refetch-on-trust"
	_, _, oldPEM := newSigningCA(t)
	newCA, newSigner, newPEM := newSigningCA(t)

	configData := buildMinimalSignedConfigBytes(t, newSigner, stewardID)
	sess := &countingConfigSession{
		testDataPlaneSession: *newTestSession(),
		transfer:             buildSignedConfigTransfer(t, newSigner, configData, "v-rotated-1"),
	}

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, stewardID, "tenant-refetch-test")
	c.mu.Lock()
	c.signingCertPEMs = []string{oldPEM}
	c.mu.Unlock()
	// The client pins the CA that issued the cert it will later be pushed.
	pinCA(t, c, newCA)
	return c, sess, capture, newPEM
}

func pushSigningCert(t *testing.T, c *TransportClient, certPEM string) {
	t.Helper()
	require.NoError(t, c.handlePushSigningCert(context.Background(), &cpTypes.Command{
		ID:        "cmd-push-rotated-cert",
		Type:      cpTypes.CommandPushSigningCert,
		StewardID: c.stewardID,
		Timestamp: time.Now(),
		Params:    map[string]interface{}{"cert_pem": base64.StdEncoding.EncodeToString([]byte(certPEM))},
	}))
}

func configApplied(capture *eventCapture) func() bool {
	return func() bool {
		select {
		case evt := <-capture.events:
			return evt.Type == cpTypes.EventConfigApplied
		default:
			return false
		}
	}
}

// A config transfer rejected as untrusted is fetched again, and applied, as
// soon as a push_signing_cert adds its signer to the trust set.
func TestConfigRefetchedAfterSigningCertPushTrustsItsSigner(t *testing.T) {
	c, sess, capture, newPEM := newRotatedClient(t)

	err := c.syncConfigNow(context.Background(), "on-connect", nil)
	require.Error(t, err, "config signed by an untrusted cert must be rejected")
	require.Equal(t, int32(1), sess.fetches.Load())

	pushSigningCert(t, c, newPEM)

	require.Eventually(t, configApplied(capture), 5*time.Second, 10*time.Millisecond,
		"the push must trigger a config re-fetch that now verifies and applies")
	assert.Equal(t, int32(2), sess.fetches.Load(), "exactly one re-fetch")
}

// A push that follows no rejected transfer — every rotation fan-out to a
// healthy steward — must not make the steward fetch its config.
func TestSigningCertPushWithoutRejectedConfigDoesNotRefetch(t *testing.T) {
	c, sess, _, newPEM := newRotatedClient(t)

	pushSigningCert(t, c, newPEM)

	assert.Never(t, func() bool { return sess.fetches.Load() > 0 }, 300*time.Millisecond, 10*time.Millisecond,
		"a push with no rejected config transfer must not trigger a fetch")
}

// If the trust set changed while a rejected transfer was being verified, the
// push that changed it has already run, so the re-fetch starts at once.
func TestConfigRefetchedAtOnceWhenTrustChangedDuringVerification(t *testing.T) {
	c, sess, capture, newPEM := newRotatedClient(t)

	c.mu.Lock()
	staleGen := c.signingTrustGen
	c.signingCertPEMs = append(c.signingCertPEMs, newPEM)
	c.signingTrustGen++
	c.mu.Unlock()

	c.refetchConfigWhenTrusted(staleGen)

	require.Eventually(t, configApplied(capture), 5*time.Second, 10*time.Millisecond,
		"a trust change during verification must re-fetch immediately")
	assert.Equal(t, int32(1), sess.fetches.Load())
	c.mu.RLock()
	defer c.mu.RUnlock()
	assert.False(t, c.refetchConfigOnTrustChange, "an immediate re-fetch leaves nothing pending")
}
