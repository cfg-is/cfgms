// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// This file exercises the partial-sync SYNC_DNA dispatch (ADR-017 §7 step 2)
// against the REAL dispatch chain end to end: the controller's real command
// Publisher with a real signer, the real gRPC-over-QUIC ControlPlaneProvider
// (pkg/controlplane/providers/grpc) over real mTLS, and the real steward-side
// command Handler with a verifier configured. Nothing on the path is substituted.
//
// The steward handler is the reason the chain is assembled in full: it drops any
// command whose signature is missing or invalid (ErrUnauthenticatedCommand), so
// only a genuinely signed SYNC_DNA reaches the registered command function. A
// capture that merely records what the controller built cannot tell a signed
// dispatch from an unsigned one.
package transport

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	stewardcommands "github.com/cfgis/cfgms/features/steward/commands"
	stewarddna "github.com/cfgis/cfgms/features/steward/dna"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	cpgrpc "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// nonDispatchWindow is how long a test waits before concluding that no command was
// dispatched. HandleHeartbeatRoot publishes synchronously (PublishCommand →
// Provider.SendCommand → stream write) before it returns, so anything that was
// dispatched is already on the wire by then; this window only covers loopback QUIC
// delivery to the subscribed client.
const nonDispatchWindow = 500 * time.Millisecond

// realControlPlaneServer starts a real gRPC-over-QUIC control-plane provider in
// server mode on an ephemeral loopback port, backed by reg.
func realControlPlaneServer(t *testing.T, ca *cfgcert.CA, reg registry.Registry) *cpgrpc.Provider {
	t.Helper()

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	serverCert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	serverTLS, err := cfgcert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM, caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	server := cpgrpc.New(cpgrpc.ModeServer)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode":       "server",
		"addr":       "127.0.0.1:0",
		"tls_config": serverTLS,
		"registry":   reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	// ForceStop: GracefulStop blocks indefinitely on the long-lived
	// ControlChannel stream even after the client disconnects.
	t.Cleanup(server.ForceStop)
	return server
}

// realControlPlanePair starts a real control-plane server and connects a real
// client provider whose mTLS client certificate CN is stewardID. Both providers are
// stopped on test cleanup.
func realControlPlanePair(t *testing.T, ca *cfgcert.CA, stewardID string) (server, client *cpgrpc.Provider) {
	t.Helper()

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	reg := registry.NewRegistry()
	server = realControlPlaneServer(t, ca, reg)

	clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   stewardID,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	clientTLS, err := cfgcert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM, caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	clientTLS.NextProtos = []string{quictransport.ALPNProtocol}

	client = cpgrpc.New(cpgrpc.ModeClient)
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode":       "client",
		"addr":       server.ListenAddr(),
		"tls_config": clientTLS,
		"steward_id": stewardID,
	}))
	require.NoError(t, client.Start(context.Background()))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })

	require.Eventually(t, func() bool {
		_, ok := reg.Get(stewardID)
		return ok
	}, 10*time.Second, 10*time.Millisecond, "steward must register on the real control plane")

	return server, client
}

// newTestSigningPair issues one controller signing certificate from ca and returns
// the real signer built from its private key together with the real verifier built
// from its certificate — the same signer/verifier pair shape the controller and a
// steward hold in production.
func newTestSigningPair(t *testing.T, ca *cfgcert.CA) (signature.Signer, signature.Verifier) {
	t.Helper()
	signingCert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "controller-command-signing",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  signingCert.PrivateKeyPEM,
		CertificatePEM: signingCert.CertificatePEM,
	})
	require.NoError(t, err)

	verifier, err := signature.NewVerifier(&signature.VerifierConfig{
		CertificatePEM: signingCert.CertificatePEM,
	})
	require.NoError(t, err)

	return signer, verifier
}

// partialSyncEnv is the full real dispatch chain for the ADR-017 §7 step-2 tests.
//
// delivered receives every SignedCommand that arrived over the real wire (before
// steward-side authentication), executed receives every SYNC_DNA command the real
// steward handler ACCEPTED and dispatched to its command function, and handleErrs
// receives the steward handler's rejection for anything it refused.
type partialSyncEnv struct {
	stewardID  string
	server     *cpgrpc.Provider
	publisher  *commands.Publisher
	delivered  chan *cpTypes.SignedCommand
	executed   chan *cpTypes.Command
	handleErrs chan error
}

// newPartialSyncEnv wires a real control-plane pair, a real signing command
// Publisher, and a real steward command Handler with a verifier configured.
func newPartialSyncEnv(t *testing.T, stewardID string) *partialSyncEnv {
	t.Helper()

	ca := newTestCA(t)
	server, client := realControlPlanePair(t, ca, stewardID)
	signer, verifier := newTestSigningPair(t, ca)

	publisher, err := commands.New(&commands.Config{
		ControlPlane: server,
		Signer:       signer,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	env := &partialSyncEnv{
		stewardID:  stewardID,
		server:     server,
		publisher:  publisher,
		delivered:  make(chan *cpTypes.SignedCommand, 8),
		executed:   make(chan *cpTypes.Command, 8),
		handleErrs: make(chan error, 8),
	}

	stewardHandler, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: stewardID,
		Logger:    logging.NewNoopLogger(),
		Verifier:  verifier,
		OnStatus:  func(context.Context, *cpTypes.Event) {},
	})
	require.NoError(t, err)
	stewardHandler.RegisterHandler(cpTypes.CommandSyncDNA,
		func(_ context.Context, cmd *cpTypes.Command) error {
			env.executed <- cmd
			return nil
		})
	t.Cleanup(stewardHandler.Wait)

	require.NoError(t, client.SubscribeCommands(context.Background(), stewardID,
		func(ctx context.Context, sc *cpTypes.SignedCommand) error {
			env.delivered <- sc
			if hErr := stewardHandler.HandleCommand(ctx, sc); hErr != nil {
				env.handleErrs <- hErr
			}
			return nil
		}))

	return env
}

// handler returns a DNAHandler wired for partial sync against store and this
// environment's real signing publisher.
func (e *partialSyncEnv) handler(store FragmentDeltaStore) *DNAHandler {
	return NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, e.publisher)
}

// requireDispatched waits for one command to arrive over the real wire.
func (e *partialSyncEnv) requireDispatched(t *testing.T) *cpTypes.SignedCommand {
	t.Helper()
	select {
	case sc := <-e.delivered:
		return sc
	case <-time.After(10 * time.Second):
		t.Fatal("no command was delivered over the real control plane")
		return nil
	}
}

// requireNoDispatch asserts that no command reached the steward.
func (e *partialSyncEnv) requireNoDispatch(t *testing.T) {
	t.Helper()
	select {
	case sc := <-e.delivered:
		t.Fatalf("no command may be dispatched, got %s", sc.Command.Type)
	case <-time.After(nonDispatchWindow):
	}
}

// requireAccepted waits for the real steward handler to accept and dispatch the
// SYNC_DNA command. It fails on any steward-side rejection, which is what an
// unsigned dispatch would produce.
func (e *partialSyncEnv) requireAccepted(t *testing.T) *cpTypes.Command {
	t.Helper()
	select {
	case cmd := <-e.executed:
		return cmd
	case hErr := <-e.handleErrs:
		t.Fatalf("the real steward handler rejected the SYNC_DNA command: %v", hErr)
		return nil
	case <-time.After(10 * time.Second):
		t.Fatal("the real steward handler never dispatched the SYNC_DNA command")
		return nil
	}
}

// TestDNAHandler_HeartbeatRoot_RealChain_SignedSyncDNAAcceptedBySteward is the
// regression for the unsigned-dispatch gap: an aggregate-root mismatch must produce
// a SIGNED SYNC_DNA that a steward running with a verifier configured accepts and
// executes, with its fragment_ids intact.
//
// Before the fix the controller hand-built a SignedCommand with a nil Signature and
// handed it straight to the control-plane provider, bypassing the Publisher. That
// command travels the wire fine, so a wire-level assertion still passes — but the
// steward's Handler.HandleCommand returns ErrUnauthenticatedCommand and never runs
// it, so the requested delta would never arrive. This test fails in that state.
func TestDNAHandler_HeartbeatRoot_RealChain_SignedSyncDNAAcceptedBySteward(t *testing.T) {
	const stewardID = "steward-realcp-mismatch"
	env := newPartialSyncEnv(t, stewardID)

	manifest := fragmentsToManifest(makeTestFragments(3))
	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest(stewardID, manifest)
	h := env.handler(store)

	// A well-formed root that differs from the stored one.
	claimedRoot := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	h.HandleHeartbeatRoot(context.Background(), stewardID, claimedRoot)

	sent := env.requireDispatched(t)
	assert.Equal(t, cpTypes.CommandSyncDNA, sent.Command.Type)
	assert.Equal(t, stewardID, sent.Command.StewardID)
	require.NotNil(t, sent.Signature,
		"the dispatched SYNC_DNA must be signed; a steward with a verifier drops unsigned commands")
	assert.NotEmpty(t, sent.Command.ID, "the Publisher must assign a command ID for replay dedup")

	// The steward-side authentication path is the real gate: signature verified
	// against CommandSigningBytes, steward ID matched, timestamp fresh, ID unseen.
	accepted := env.requireAccepted(t)

	rawIDs, ok := accepted.Params["fragment_ids"]
	require.True(t, ok, "fragment_ids must survive the real wire round-trip")

	// Wire truth: command params travel as map[string]string and the gRPC provider
	// JSON-decodes any value that is valid JSON on arrival, so the marshalled ID
	// array is delivered as []interface{}, NOT as the string the controller sent.
	// The steward's parseFragmentIDs handles this shape; pinning it here keeps the
	// two sides from silently diverging.
	elems, ok := rawIDs.([]interface{})
	require.Truef(t, ok,
		"fragment_ids must arrive as []interface{} over the real control plane, got %T", rawIDs)
	ids := make([]string, 0, len(elems))
	for _, e := range elems {
		s, isString := e.(string)
		require.True(t, isString, "every fragment_ids element must decode as a string")
		ids = append(ids, s)
	}
	assert.ElementsMatch(t, []string{"frag-0", "frag-1", "frag-2"}, ids)

	// The claim and the requested ID set are retained for delta revalidation once
	// dispatch succeeded.
	storedRaw, ok := h.pendingDeltas.Load(stewardID)
	require.True(t, ok, "the delta request must be retained after a successful dispatch")
	pending, ok := storedRaw.(*deltaRequest)
	require.True(t, ok, "pendingDeltas must hold a *deltaRequest")
	assert.Equal(t, claimedRoot, pending.claimedRoot)
	assert.Equal(t, map[string]struct{}{"frag-0": {}, "frag-1": {}, "frag-2": {}}, pending.requestedIDs,
		"the requested ID set must be retained so the delta branch can reject unrequested fragments")
}

// TestPartialSyncDispatch_UnsignedCommandIsDropped pins the reason the SYNC_DNA
// dispatch must go through the signing Publisher, and proves the assertions above
// can tell the two apart: the same command, hand-built with a nil signature and
// pushed down the same real control plane, reaches the steward and is then refused.
//
// This is the failure mode the pre-fix code shipped — the command left the
// controller looking healthy and was silently discarded on arrival, so the requested
// fragment delta would never be sent and the steward's DNA would stay stale.
func TestPartialSyncDispatch_UnsignedCommandIsDropped(t *testing.T) {
	const stewardID = "steward-realcp-unsigned"
	env := newPartialSyncEnv(t, stewardID)

	require.NoError(t, env.server.SendCommand(context.Background(), &cpTypes.SignedCommand{
		Command: cpTypes.Command{
			ID:        "sync_dna_delta_unsigned",
			Type:      cpTypes.CommandSyncDNA,
			StewardID: stewardID,
			Timestamp: time.Now(),
			Params:    map[string]interface{}{"fragment_ids": `["frag-0"]`},
		},
	}))

	sent := env.requireDispatched(t)
	require.Nil(t, sent.Signature, "fixture precondition: this command is unsigned")

	select {
	case hErr := <-env.handleErrs:
		require.ErrorIs(t, hErr, stewardcommands.ErrUnauthenticatedCommand,
			"an unsigned command must be refused by a steward running with a verifier")
	case cmd := <-env.executed:
		t.Fatalf("an unsigned SYNC_DNA must never execute on the steward, got %s", cmd.ID)
	case <-time.After(10 * time.Second):
		t.Fatal("the steward handler neither accepted nor rejected the unsigned command")
	}
}

// TestDNAHandler_HeartbeatRoot_RealChain_NoStewardAssertedTenant is the regression
// for the tenant-laundering gap: the controller must not attach a tenant it never
// verified to the command it issues.
//
// The heartbeat that carries the aggregate root is steward-supplied, so a
// compromised steward can claim any tenant path. TenantID is inside the command
// signing payload (cpTypes.CommandSigningBytes), so a copied claim would be
// cryptographically attested by the controller. HandleHeartbeatRoot therefore takes
// no tenant argument at all and the dispatched command must carry none.
func TestDNAHandler_HeartbeatRoot_RealChain_NoStewardAssertedTenant(t *testing.T) {
	const stewardID = "steward-realcp-tenant"
	env := newPartialSyncEnv(t, stewardID)

	manifest := fragmentsToManifest(makeTestFragments(2))
	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest(stewardID, manifest)

	env.handler(store).HandleHeartbeatRoot(context.Background(), stewardID,
		"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")

	sent := env.requireDispatched(t)
	assert.Empty(t, sent.Command.TenantID,
		"the controller must not attest to a tenant it did not resolve from its own state")
	assert.Equal(t, stewardID, sent.Command.StewardID,
		"the command is addressed by the mTLS-verified steward identity alone")

	// The command is still accepted by the steward: an empty tenant is the shape
	// every other Publisher-issued command has.
	env.requireAccepted(t)
}

// TestDNAHandler_HeartbeatRoot_RealChain_MatchSendsNothing verifies that a matching
// root produces no traffic on the real control plane.
func TestDNAHandler_HeartbeatRoot_RealChain_MatchSendsNothing(t *testing.T) {
	const stewardID = "steward-realcp-match"
	env := newPartialSyncEnv(t, stewardID)

	manifest := fragmentsToManifest(makeTestFragments(3))
	storedRoot, err := stewarddna.AggregateRoot(manifest)
	require.NoError(t, err)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest(stewardID, manifest)
	h := env.handler(store)

	h.HandleHeartbeatRoot(context.Background(), stewardID, storedRoot)

	env.requireNoDispatch(t)
	_, ok := h.pendingDeltas.Load(stewardID)
	assert.False(t, ok, "no delta request is recorded when the root matches")
}

// TestDNAHandler_HeartbeatRoot_RealChain_NoStoredManifest_SendsNothing verifies that
// when the controller has no stored manifest for a steward, HandleHeartbeatRoot is a
// no-op (the existing full-sync path handles first-time syncs).
func TestDNAHandler_HeartbeatRoot_RealChain_NoStoredManifest_SendsNothing(t *testing.T) {
	const stewardID = "steward-realcp-new"
	env := newPartialSyncEnv(t, stewardID)

	h := env.handler(NewInMemoryFragmentDeltaStore()) // empty store

	// Root must be a valid 64-char hex string; the no-manifest path returns early regardless.
	h.HandleHeartbeatRoot(context.Background(), stewardID,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	env.requireNoDispatch(t)
	_, retained := h.pendingDeltas.Load(stewardID)
	assert.False(t, retained, "no delta request is recorded without a stored manifest")
}

// TestDNAHandler_HeartbeatRoot_RealChain_MalformedRoot_Rejected verifies that a
// steward-supplied aggregate root that is not exactly 64 lowercase hex chars is
// dropped at the boundary: no SYNC_DNA reaches the steward and nothing is retained
// in pendingDeltas (input validation, Story #396). Retaining arbitrary-length
// attacker-controlled strings per steward is a memory-amplification vector at 50k+
// steward scale, and the raw value must never reach the log sink.
func TestDNAHandler_HeartbeatRoot_RealChain_MalformedRoot_Rejected(t *testing.T) {
	const stewardID = "steward-realcp-malformed"
	env := newPartialSyncEnv(t, stewardID)
	manifest := fragmentsToManifest(makeTestFragments(3))

	validHex := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	malformed := map[string]string{
		"empty":               "",
		"too short":           validHex[:63],
		"too long":            validHex + "a",
		"uppercase hex":       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"non hex":             "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		"crlf injection":      "aaaa\r\nlevel=INFO msg=\"forged record\" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256 prefixed":     "sha256:" + validHex,
		"oversized amplifier": strings.Repeat("a", 1<<16),
	}

	for name, root := range malformed {
		t.Run(name, func(t *testing.T) {
			store := NewInMemoryFragmentDeltaStore()
			store.SetManifest(stewardID, manifest)
			h := env.handler(store)

			h.HandleHeartbeatRoot(context.Background(), stewardID, root)

			env.requireNoDispatch(t)
			_, retained := h.pendingDeltas.Load(stewardID)
			assert.False(t, retained,
				"a malformed aggregate root must never be retained in pendingDeltas")
		})
	}
}

// TestDNAHandler_HeartbeatRoot_RealChain_DispatchFailure_ClearsClaim verifies that
// when the SYNC_DNA dispatch fails, the recorded claim is dropped so a later delta
// cannot be validated against a root the steward was never actually asked about.
//
// The failure is the control plane's genuine one: the publisher is wired to a real
// control-plane server on which the steward has never connected, so
// Provider.SendCommand returns "steward not connected". No error is injected.
func TestDNAHandler_HeartbeatRoot_RealChain_DispatchFailure_ClearsClaim(t *testing.T) {
	const stewardID = "steward-realcp-sendfail"

	ca := newTestCA(t)
	server := realControlPlaneServer(t, ca, registry.NewRegistry()) // no steward connected
	signer, _ := newTestSigningPair(t, ca)
	publisher, err := commands.New(&commands.Config{
		ControlPlane: server,
		Signer:       signer,
		Logger:       logging.NewNoopLogger(),
	})
	require.NoError(t, err)

	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest(stewardID, fragmentsToManifest(makeTestFragments(2)))

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil).
		WithPartialSync(store, publisher)

	h.HandleHeartbeatRoot(context.Background(), stewardID,
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	_, retained := h.pendingDeltas.Load(stewardID)
	assert.False(t, retained, "claim must be cleared when the SYNC_DNA dispatch fails")
}

// TestDNAHandler_HeartbeatRoot_NoPublisher_SendsNothing verifies the fail-closed
// default: a handler built by NewDNAHandler alone (no WithPartialSync) never
// dispatches, so a heartbeat root on a server without partial sync configured is
// inert rather than producing an unroutable command.
func TestDNAHandler_HeartbeatRoot_NoPublisher_SendsNothing(t *testing.T) {
	store := NewInMemoryFragmentDeltaStore()
	store.SetManifest("steward-nopub", fragmentsToManifest(makeTestFragments(2)))

	h := NewDNAHandler(logging.NewNoopLogger(), NewTenantQueue(), nil)
	h.HandleHeartbeatRoot(context.Background(), "steward-nopub",
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

	_, retained := h.pendingDeltas.Load("steward-nopub")
	assert.False(t, retained, "nothing may be recorded when no publisher is wired")
}
