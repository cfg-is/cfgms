// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

const migrationTestTenant = "cluster-ca-tenant"

// sentPush is one published push_signing_cert as the steward side saw it.
type sentPush struct {
	stewardID    string
	signerSerial string // serial of the key that signed it
	retire       []string
	ackedAtSend  bool // the shared serial's confirmation was already recorded
	verified     bool // the steward trusted the signing key
}

// simSteward applies push_signing_cert the way the steward handler does: a command
// signed by an untrusted key is dropped silently; an accepted push adds the pushed
// certificate to the trust set and removes the serials named by retire_serials.
type simSteward struct {
	id    string
	delay time.Duration // before the completion event; negative = never completes

	mu      sync.Mutex
	trusted []*x509.Certificate
}

func (s *simSteward) trustedSerials() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, c := range s.trusted {
		out = append(out, c.SerialNumber.String())
	}
	sort.Strings(out)
	return out
}

// trustsOnly reports whether the steward's trust set is exactly the given serial.
// Retire pushes are applied asynchronously, after the push is recorded as sent.
func (s *simSteward) trustsOnly(serial string) bool {
	got := s.trustedSerials()
	return len(got) == 1 && got[0] == serial
}

// simControlPlane is the control plane of one node: SendCommand hands a command to
// the simulated stewards connected to that node and returns their completion
// events to that node's publisher.
type simControlPlane struct {
	cpinterfaces.ControlPlaneProvider
	acks         certinterfaces.SigningTrustAckStore
	sharedSerial func() string
	fingerprints map[string]string // key fingerprint -> serial

	mu       sync.Mutex
	pub      *commands.Publisher
	stewards map[string]*simSteward
	sent     []sentPush
	inFlight int
	maxSeen  int
}

func (c *simControlPlane) SendCommand(ctx context.Context, sc *types.SignedCommand) error {
	c.mu.Lock()
	st := c.stewards[sc.Command.StewardID]
	c.mu.Unlock()
	if st == nil {
		return assert.AnError
	}

	st.mu.Lock()
	verifier, err := signature.NewMultiVerifier(st.trusted)
	st.mu.Unlock()
	if err != nil {
		return err
	}
	bytes, err := types.CommandSigningBytes(&sc.Command, types.InterfaceParamsToStringMap(sc.Command.Params))
	if err != nil {
		return err
	}
	verified := verifier.Verify(bytes, sc.Signature) == nil

	var retire []string
	switch v := sc.Command.Params["retire_serials"].(type) {
	case []string:
		retire = v
	}
	ackSerial := ""
	if c.sharedSerial != nil {
		ackSerial = c.sharedSerial()
	}
	ack, _ := c.acks.GetAck(ctx, st.id, ackSerial)

	c.mu.Lock()
	c.sent = append(c.sent, sentPush{
		stewardID:    st.id,
		signerSerial: c.fingerprints[sc.Signature.KeyFingerprint],
		retire:       retire,
		ackedAtSend:  ack != nil,
		verified:     verified,
	})
	if verified {
		c.inFlight++
		if c.inFlight > c.maxSeen {
			c.maxSeen = c.inFlight
		}
	}
	c.mu.Unlock()

	if !verified {
		return nil // rejected silently
	}
	pemBytes, _ := base64.StdEncoding.DecodeString(sc.Command.Params["cert_pem"].(string))
	pushed, err := cert.ParseCertificateFromPEM(pemBytes)
	if err != nil {
		return err
	}
	deliver := func() {
		st.mu.Lock()
		have := false
		for _, t := range st.trusted {
			if t.Equal(pushed) {
				have = true
			}
		}
		if !have {
			st.trusted = append(st.trusted, pushed)
		}
		kept := st.trusted[:0:0]
		for _, t := range st.trusted {
			drop := false
			for _, r := range retire {
				if t.SerialNumber.String() == r && !t.Equal(pushed) {
					drop = true
				}
			}
			if !drop {
				kept = append(kept, t)
			}
		}
		st.trusted = kept
		st.mu.Unlock()

		c.mu.Lock()
		c.inFlight--
		pub := c.pub
		c.mu.Unlock()
		_ = pub.HandleEventUpdate(context.Background(), &types.Event{
			Type: types.EventCommandCompleted, StewardID: st.id, CommandID: sc.Command.ID,
		})
	}
	switch {
	case st.delay < 0:
		c.mu.Lock()
		c.inFlight--
		c.mu.Unlock()
	case st.delay == 0:
		go deliver()
	default:
		time.AfterFunc(st.delay, deliver)
	}
	return nil
}

func (c *simControlPlane) pushes(stewardID string) []sentPush {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []sentPush
	for _, p := range c.sent {
		if p.stewardID == stewardID {
			out = append(out, p)
		}
	}
	return out
}

func (c *simControlPlane) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

// migrationCluster is three controller nodes sharing one CA, secret store, signing
// cursor and acknowledgement store; each node held its own signing certificate
// before the shared store existed.
type migrationCluster struct {
	nodes   []*cert.Manager
	legacy  []*x509.Certificate // node i's own signing certificate
	serials []string
	acks    certinterfaces.SigningTrustAckStore
	fingers map[string]string
	elected string
	logger  logging.Logger
}

func newMigrationCluster(t *testing.T) *migrationCluster {
	t.Helper()
	ctx := context.Background()
	secrets := testutil.NewMemSecretStore()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)
	acks, err := cert.NewFileSigningTrustAckStore(t.TempDir())
	require.NoError(t, err)

	c := &migrationCluster{acks: acks, fingers: map[string]string{}, logger: logging.NewNoopLogger()}
	for i := 0; i < 3; i++ {
		dir := t.TempDir()
		build := func(withKeys bool) *cert.Manager {
			cfg := &cert.ManagerConfig{
				StoragePath:        dir,
				CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
				SigningCursorStore: cursor,
			}
			if withKeys {
				ks, err := cert.NewSecretStoreSigningKeyStore(secrets, migrationTestTenant, "")
				require.NoError(t, err)
				cfg.SigningKeyStore = ks
			}
			m, err := cert.NewManagerFromSecretStore(ctx, secrets, migrationTestTenant, "cluster-ca", cfg)
			require.NoError(t, err)
			return m
		}
		legacy := build(false)
		require.NoError(t, legacy.EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}))
		local, err := legacy.GetCurrentCertForPurpose(cert.PurposeSigning)
		require.NoError(t, err)
		x, err := cert.ParseCertificateFromPEM(local.CertificatePEM)
		require.NoError(t, err)
		v, err := signature.NewVerifierFromCertificate(x)
		require.NoError(t, err)

		node := build(true)
		results, err := node.ImportLocalSigningCertificates(ctx)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.True(t, results[0].Imported, results[0].Reason)

		c.nodes = append(c.nodes, node)
		c.legacy = append(c.legacy, x)
		c.serials = append(c.serials, local.SerialNumber)
		c.fingers[v.KeyFingerprint()] = local.SerialNumber
	}
	return c
}

// elect names node 0's certificate as the shared signing certificate.
func (c *migrationCluster) elect(t *testing.T) {
	t.Helper()
	_, created, err := c.nodes[0].ElectSharedSigningSerial(context.Background(), c.serials[0])
	require.NoError(t, err)
	require.True(t, created)
	c.elected = c.serials[0]
}

type migrationNode struct {
	svc   *StewardSigningMigrationService
	cp    *simControlPlane
	reg   *registry.InMemoryRegistry
	clock *atomic.Int64 // unix nanos added to time.Now
}

// newNode builds the migration service of node idx, with a control plane whose
// steward events come back to that node's publisher.
func (c *migrationCluster) newNode(t *testing.T, idx int) *migrationNode {
	t.Helper()
	cp := &simControlPlane{
		acks:         c.acks,
		sharedSerial: func() string { return c.elected },
		fingerprints: c.fingers,
		stewards:     map[string]*simSteward{},
	}
	pub, err := commands.New(&commands.Config{ControlPlane: cp, Logger: c.logger})
	require.NoError(t, err)
	cp.pub = pub

	svc := NewStewardSigningMigrationService(c.nodes[idx], c.acks, c.logger)
	reg := registry.NewRegistry()
	svc.SetPublisher(pub)
	svc.SetConnectedStewards(reg)
	svc.SetTimings(300*time.Millisecond, time.Hour, time.Hour)
	svc.planTTL = 10 * time.Millisecond

	n := &migrationNode{svc: svc, cp: cp, reg: reg, clock: &atomic.Int64{}}
	svc.now = func() time.Time { return time.Now().Add(time.Duration(n.clock.Load())) }
	t.Cleanup(svc.Stop)
	return n
}

type noopSender struct{}

func (noopSender) SendMsg(interface{}) error { return nil }

// connect attaches a simulated steward, trusting trusted, to the node.
func (n *migrationNode) connect(t *testing.T, id string, delay time.Duration, trusted ...*x509.Certificate) *simSteward {
	t.Helper()
	st := &simSteward{id: id, delay: delay, trusted: append([]*x509.Certificate{}, trusted...)}
	n.cp.mu.Lock()
	n.cp.stewards[id] = st
	n.cp.mu.Unlock()
	require.NoError(t, n.reg.Register(&registry.StewardConnection{StewardID: id, Sender: noopSender{}}))
	return st
}

func (c *migrationCluster) confirmed(id string) bool {
	if c.elected == "" {
		return false
	}
	ack, err := c.acks.GetAck(context.Background(), id, c.elected)
	return err == nil && ack != nil
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 20*time.Second, 20*time.Millisecond, what)
}

func TestStewardMigration_StewardTrustingSharedKeyUsesNoLegacySigner(t *testing.T) {
	c := newMigrationCluster(t)
	c.elect(t)
	n := c.newNode(t, 0)
	st := n.connect(t, "steward-shared", 0, c.legacy[0]) // legacy[0] is the shared certificate
	n.svc.Start(context.Background())
	require.NoError(t, n.svc.OnConnect(context.Background(), "steward-shared"))

	eventually(t, "retire push sent", func() bool {
		p := n.cp.pushes("steward-shared")
		return len(p) == 2 && p[1].retire != nil && st.trustsOnly(c.serials[0])
	})
	pushes := n.cp.pushes("steward-shared")
	for _, p := range pushes {
		assert.Equal(t, c.serials[0], p.signerSerial, "only the shared key signs")
		assert.True(t, p.verified)
	}
	assert.False(t, pushes[0].ackedAtSend)
	assert.True(t, pushes[1].ackedAtSend, "the retire push follows the recorded confirmation")
	assert.ElementsMatch(t, []string{c.serials[1], c.serials[2]}, pushes[1].retire)
	assert.True(t, c.confirmed("steward-shared"))
	assert.Equal(t, []string{c.serials[0]}, st.trustedSerials())
}

func TestStewardMigration_LegacyOnlyStewardEndsWithSharedCertificateOnly(t *testing.T) {
	c := newMigrationCluster(t)
	c.elect(t)
	n := c.newNode(t, 1)
	st := n.connect(t, "steward-legacy", 0, c.legacy[1])
	n.svc.Start(context.Background())
	require.NoError(t, n.svc.OnConnect(context.Background(), "steward-legacy"))

	eventually(t, "retire push sent", func() bool {
		p := n.cp.pushes("steward-legacy")
		return len(p) > 0 && p[len(p)-1].retire != nil && st.trustsOnly(c.serials[0])
	})
	pushes := n.cp.pushes("steward-legacy")
	require.Greater(t, len(pushes), 3)

	// First the shared key is tried and rejected; then the legacy keys; then the
	// confirmation by the shared key; then — only then — the retirement.
	assert.Equal(t, c.serials[0], pushes[0].signerSerial)
	assert.False(t, pushes[0].verified)
	last := len(pushes) - 1
	assert.Equal(t, c.serials[0], pushes[last].signerSerial)
	assert.Equal(t, c.serials[0], pushes[last-1].signerSerial, "confirmation push is signed by the shared key")
	assert.Equal(t, c.serials[1], pushes[last-2].signerSerial, "the legacy key the steward trusts delivered the certificate")
	for i, p := range pushes {
		if p.retire != nil {
			assert.True(t, p.ackedAtSend, "push %d retires before the confirmation is recorded", i)
		} else {
			assert.False(t, p.ackedAtSend, "push %d was sent after the confirmation", i)
		}
	}
	assert.True(t, c.confirmed("steward-legacy"))
	assert.Equal(t, []string{c.serials[0]}, st.trustedSerials(), "only the shared certificate stays trusted")
}

func TestStewardMigration_UnreachableStewardStaysUnconfirmedAndRespectsBackoff(t *testing.T) {
	c := newMigrationCluster(t)
	c.elect(t)
	n := c.newNode(t, 2)
	// The steward trusts a legacy key but never sends a completion event, so
	// every candidate attempt ends in the step timeout.
	n.connect(t, "steward-silent", -1, c.legacy[2])
	n.svc.SetTimings(100*time.Millisecond, time.Hour, 50*time.Millisecond)
	n.svc.Start(context.Background())
	require.NoError(t, n.svc.OnConnect(context.Background(), "steward-silent"))

	// shared key + each legacy signer (two legacy keys) = 3 attempts, then it gives up.
	eventually(t, "all candidates attempted", func() bool { return len(n.cp.pushes("steward-silent")) >= 3 })
	time.Sleep(600 * time.Millisecond) // several reconcile passes inside the backoff
	assert.Len(t, n.cp.pushes("steward-silent"), 3, "no retry inside the backoff")
	assert.False(t, c.confirmed("steward-silent"))
	for _, p := range n.cp.pushes("steward-silent") {
		assert.Nil(t, p.retire, "nothing is retired from an unconfirmed steward")
	}

	n.clock.Store(int64(2 * time.Hour))
	eventually(t, "retried after the backoff", func() bool { return len(n.cp.pushes("steward-silent")) >= 6 })
	assert.False(t, c.confirmed("steward-silent"))
}

func TestStewardMigration_ThreeNodesConfirmEveryConnectedSteward(t *testing.T) {
	c := newMigrationCluster(t)
	c.elect(t)
	nodes := []*migrationNode{c.newNode(t, 0), c.newNode(t, 1), c.newNode(t, 2)}

	var ids []string
	for i, n := range nodes {
		// Two stewards per node, each trusting only that node's legacy key.
		for j := 0; j < 2; j++ {
			id := "steward-" + string(rune('a'+i)) + string(rune('0'+j))
			n.connect(t, id, 0, c.legacy[i])
			ids = append(ids, id)
		}
		n.svc.Start(context.Background())
	}
	for i, n := range nodes {
		for j := 0; j < 2; j++ {
			require.NoError(t, n.svc.OnConnect(context.Background(), "steward-"+string(rune('a'+i))+string(rune('0'+j))))
		}
	}
	eventually(t, "every steward confirmed in the shared store", func() bool {
		for _, id := range ids {
			if !c.confirmed(id) {
				return false
			}
		}
		return true
	})
	acked, err := c.acks.ListAcked(context.Background(), c.elected)
	require.NoError(t, err)
	assert.Len(t, acked, len(ids))
}

func TestStewardMigration_OnConnectReturnsImmediatelyAndPoolIsCapped(t *testing.T) {
	c := newMigrationCluster(t)
	c.elect(t)
	n := c.newNode(t, 0)
	n.svc.SetMaxWorkers(2)

	const stewards = 12
	var ids []string
	for i := 0; i < stewards; i++ {
		id := "steward-cap-" + string(rune('a'+i))
		// Completes only after a delay, so concurrently worked stewards overlap.
		n.connect(t, id, 150*time.Millisecond, c.legacy[0])
		ids = append(ids, id)
	}
	n.svc.Start(context.Background())

	start := time.Now()
	for _, id := range ids {
		require.NoError(t, n.svc.OnConnect(context.Background(), id))
	}
	assert.Less(t, time.Since(start), 100*time.Millisecond, "OnConnect must not wait on any steward")

	eventually(t, "all confirmed", func() bool {
		for _, id := range ids {
			if !c.confirmed(id) {
				return false
			}
		}
		return true
	})
	n.cp.mu.Lock()
	defer n.cp.mu.Unlock()
	assert.LessOrEqual(t, n.cp.maxSeen, 2, "never more stewards in flight than workers")
	assert.GreaterOrEqual(t, n.cp.maxSeen, 1)
}

func TestStewardMigration_OnConnectDoesNotBlockOnSilentSteward(t *testing.T) {
	c := newMigrationCluster(t)
	c.elect(t)
	n := c.newNode(t, 0)
	n.connect(t, "steward-mute", -1, c.legacy[0])
	n.svc.SetTimings(5*time.Second, time.Hour, time.Hour)
	n.svc.Start(context.Background())

	start := time.Now()
	require.NoError(t, n.svc.OnConnect(context.Background(), "steward-mute"))
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}

func TestStewardMigration_ReconcilerMigratesAlreadyConnectedSteward(t *testing.T) {
	c := newMigrationCluster(t)
	n := c.newNode(t, 1)
	n.svc.SetTimings(300*time.Millisecond, time.Hour, 50*time.Millisecond)
	st := n.connect(t, "steward-early", 0, c.legacy[1])
	n.svc.Start(context.Background())

	// Not Shared yet: nothing is sent.
	time.Sleep(300 * time.Millisecond)
	assert.Zero(t, n.cp.total(), "migration only runs in Shared identity mode")

	c.elect(t)
	// The confirmation is recorded before the retire push is sent, so wait for the
	// steward to have applied the retirement, not merely for the confirmation.
	eventually(t, "reconciler confirmed and retired legacy trust on the already-connected steward", func() bool {
		return c.confirmed("steward-early") && st.trustsOnly(c.serials[0])
	})
	assert.Equal(t, []string{c.serials[0]}, st.trustedSerials())
}

func TestStewardMigration_ConfirmedStewardIsSkipped(t *testing.T) {
	c := newMigrationCluster(t)
	c.elect(t)
	n := c.newNode(t, 0)
	n.connect(t, "steward-done", 0, c.legacy[0])
	require.NoError(t, c.acks.RecordAck(context.Background(), "steward-done", c.elected))
	n.svc.Start(context.Background())
	require.NoError(t, n.svc.OnConnect(context.Background(), "steward-done"))
	time.Sleep(300 * time.Millisecond)
	assert.Zero(t, n.cp.total(), "a recorded confirmation means nothing is sent")
}
