// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"

	cpinterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

// staticTermSource implements TermSource and returns a fixed term value.
type staticTermSource struct {
	term uint64
}

func (s *staticTermSource) GetTerm() uint64 { return s.term }

// newTestPublisher creates a Publisher backed by a real memory controlplane.
// The returned client provider can be used to observe sent commands.
func newTestPublisher(t *testing.T, termSource commands.TermSource) (*commands.Publisher, *memory.Provider) {
	t.Helper()
	ctx := context.Background()

	bus := memory.NewBus()

	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, server.Stop(stopCtx))
	})

	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{
		"bus":        bus,
		"steward_id": "steward-test",
	}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, client.Stop(stopCtx))
	})

	logger := logging.NewLogger("error")

	pub, err := commands.New(&commands.Config{
		ControlPlane: server,
		TermSource:   termSource,
		Logger:       logger,
	})
	require.NoError(t, err)

	return pub, client
}

// TestPublishCommand_StampsTermFromSource verifies that a configured TermSource
// causes PublishCommand to set Command.Term to the value returned by GetTerm().
func TestPublishCommand_StampsTermFromSource(t *testing.T) {
	const wantTerm uint64 = 42

	pub, client := newTestPublisher(t, &staticTermSource{term: wantTerm})

	ctx := context.Background()
	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	_, err := pub.PublishCommand(ctx, "steward-test", types.CommandSyncConfig, nil)
	require.NoError(t, err)

	select {
	case cmd := <-received:
		assert.Equal(t, wantTerm, cmd.Command.Term, "published command must carry the TermSource's term")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command")
	}
}

// TestPublishCommand_ZeroTermWhenNoSource verifies that a nil TermSource leaves
// Command.Term at zero (pre-fencing behaviour, wire-compatible with old stewards).
func TestPublishCommand_ZeroTermWhenNoSource(t *testing.T) {
	pub, client := newTestPublisher(t, nil)

	ctx := context.Background()
	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	_, err := pub.PublishCommand(ctx, "steward-test", types.CommandSyncConfig, nil)
	require.NoError(t, err)

	select {
	case cmd := <-received:
		assert.Equal(t, uint64(0), cmd.Command.Term, "nil TermSource must leave term at zero")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command")
	}
}

// TestPublishCommandWithSigner_StampsTerm verifies that PublishCommandWithSigner
// also stamps the term from a configured TermSource.
func TestPublishCommandWithSigner_StampsTerm(t *testing.T) {
	const wantTerm uint64 = 7

	pub, client := newTestPublisher(t, &staticTermSource{term: wantTerm})

	ctx := context.Background()
	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	_, err := pub.PublishCommandWithSigner(ctx, "steward-test", types.CommandSyncConfig, nil, nil)
	require.NoError(t, err)

	select {
	case cmd := <-received:
		assert.Equal(t, wantTerm, cmd.Command.Term, "PublishCommandWithSigner must carry the TermSource's term")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for command")
	}
}

// sendHookCP is a control-plane provider whose SendCommand runs a hook, so a test
// can deliver a steward event from inside the send. Every other method is
// unreachable from the publisher paths under test.
type sendHookCP struct {
	cpinterfaces.ControlPlaneProvider
	onSend func(cmd *types.SignedCommand) error
}

func (c *sendHookCP) SendCommand(_ context.Context, cmd *types.SignedCommand) error {
	return c.onSend(cmd)
}

func newSendHookPublisher(t *testing.T, onSend func(*types.SignedCommand) error) *commands.Publisher {
	t.Helper()
	pub, err := commands.New(&commands.Config{
		ControlPlane: &sendHookCP{onSend: onSend},
		TermSource:   &staticTermSource{term: 9},
		Logger:       logging.NewLogger("error"),
	})
	require.NoError(t, err)
	return pub
}

func newTestSignerAndVerifier(t *testing.T) (signature.Signer, signature.Verifier) {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{Organization: "Publisher Test", Country: "US", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	sc, err := ca.GenerateSigningCertificate(&cert.SigningCertConfig{CommonName: "pub-test", ValidityDays: 1, KeySize: 2048})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{CertificatePEM: sc.CertificatePEM, PrivateKeyPEM: sc.PrivateKeyPEM})
	require.NoError(t, err)
	verifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: sc.CertificatePEM})
	require.NoError(t, err)
	return signer, verifier
}

// TestPublishCommandWithSignerAndCallback_CompletionDuringSend delivers the
// completion event synchronously from inside SendCommand: the pending entry must
// already be registered, so the callback still fires.
func TestPublishCommandWithSignerAndCallback_CompletionDuringSend(t *testing.T) {
	var pub *commands.Publisher
	pub = newSendHookPublisher(t, func(cmd *types.SignedCommand) error {
		return pub.HandleEventUpdate(context.Background(), &types.Event{
			Type: types.EventCommandCompleted, StewardID: cmd.Command.StewardID, CommandID: cmd.Command.ID,
		})
	})

	signer, _ := newTestSignerAndVerifier(t)
	completed := make(chan *types.Event, 1)
	id, err := pub.PublishCommandWithSignerAndCallback(context.Background(), "steward-1",
		types.CommandPushSigningCert, map[string]interface{}{"k": "v"}, signer, time.Minute,
		func(ev *types.Event) { completed <- ev }, func() { t.Error("timeout must not fire") })
	require.NoError(t, err)

	select {
	case ev := <-completed:
		assert.Equal(t, id, ev.CommandID)
	case <-time.After(5 * time.Second):
		t.Fatal("completion delivered during SendCommand was lost")
	}
	assert.Empty(t, pub.GetPendingCommands())
}

// TestPublishCommandWithSignerAndCallback_SignsWithSuppliedSigner proves the
// signature verifies against the supplied signer's certificate (the publisher has
// no default signer here) and the term is stamped.
func TestPublishCommandWithSignerAndCallback_SignsWithSuppliedSigner(t *testing.T) {
	signer, verifier := newTestSignerAndVerifier(t)
	_, otherVerifier := newTestSignerAndVerifier(t)

	got := make(chan *types.SignedCommand, 1)
	pub := newSendHookPublisher(t, func(cmd *types.SignedCommand) error { got <- cmd; return nil })

	_, err := pub.PublishCommandWithSignerAndCallback(context.Background(), "steward-1",
		types.CommandPushSigningCert, map[string]interface{}{"serial": "42"}, signer, time.Minute, nil, nil)
	require.NoError(t, err)

	sc := <-got
	require.NotNil(t, sc.Signature)
	assert.Equal(t, uint64(9), sc.Command.Term)
	bytes, err := types.CommandSigningBytes(&sc.Command, types.InterfaceParamsToStringMap(sc.Command.Params))
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(bytes, sc.Signature))
	assert.Error(t, otherVerifier.Verify(bytes, sc.Signature), "a different key must not verify")
}

func TestPublishCommandWithSignerAndCallback_SendFailureCancelsEntry(t *testing.T) {
	pub := newSendHookPublisher(t, func(*types.SignedCommand) error { return assert.AnError })
	signer, _ := newTestSignerAndVerifier(t)

	timedOut := make(chan struct{}, 1)
	_, err := pub.PublishCommandWithSignerAndCallback(context.Background(), "steward-1",
		types.CommandPushSigningCert, nil, signer, 50*time.Millisecond,
		func(*types.Event) { t.Error("complete must not fire") }, func() { timedOut <- struct{}{} })
	require.Error(t, err)
	assert.Empty(t, pub.GetPendingCommands())

	select {
	case <-timedOut:
		t.Fatal("timeout callback fired for a command that was never sent")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPublishCommandWithSignerAndCallback_TimesOutWithoutCompletion(t *testing.T) {
	pub := newSendHookPublisher(t, func(*types.SignedCommand) error { return nil })
	signer, _ := newTestSignerAndVerifier(t)

	timedOut := make(chan struct{}, 1)
	_, err := pub.PublishCommandWithSignerAndCallback(context.Background(), "steward-1",
		types.CommandPushSigningCert, nil, signer, 50*time.Millisecond,
		func(*types.Event) { t.Error("complete must not fire") }, func() { timedOut <- struct{}{} })
	require.NoError(t, err)

	select {
	case <-timedOut:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout callback did not fire")
	}
	assert.Empty(t, pub.GetPendingCommands())
}

// TestPublishCommandWithID_SendsCallerID verifies the caller's ID reaches the
// steward unchanged, with the term stamped, and that an empty ID sends nothing.
func TestPublishCommandWithID_SendsCallerID(t *testing.T) {
	const wantTerm uint64 = 7

	setup := func(t *testing.T) (*commands.Publisher, chan *types.SignedCommand) {
		pub, client := newTestPublisher(t, &staticTermSource{term: wantTerm})
		received := make(chan *types.SignedCommand, 2)
		require.NoError(t, client.SubscribeCommands(context.Background(), "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
			received <- cmd
			return nil
		})))
		return pub, received
	}

	t.Run("sends caller ID and term", func(t *testing.T) {
		pub, received := setup(t)
		require.NoError(t, pub.PublishCommandWithID(context.Background(), "rec-1", "steward-test", types.CommandSyncConfig, nil))
		select {
		case cmd := <-received:
			assert.Equal(t, "rec-1", cmd.Command.ID)
			assert.Equal(t, wantTerm, cmd.Command.Term)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for command")
		}
	})

	t.Run("empty ID is rejected and nothing is sent", func(t *testing.T) {
		pub, received := setup(t)
		require.Error(t, pub.PublishCommandWithID(context.Background(), "", "steward-test", types.CommandSyncConfig, nil))
		require.Error(t, pub.TriggerConfigSyncWithID(context.Background(), "", "steward-test"))
		select {
		case <-received:
			t.Fatal("no command may be sent for an empty ID")
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("TriggerConfigSyncWithID sends sync_config under the ID", func(t *testing.T) {
		pub, received := setup(t)
		require.NoError(t, pub.TriggerConfigSyncWithID(context.Background(), "rec-2", "steward-test"))
		select {
		case cmd := <-received:
			assert.Equal(t, "rec-2", cmd.Command.ID)
			assert.Equal(t, types.CommandSyncConfig, cmd.Command.Type)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for command")
		}
	})
}

// raisableTermSource is a settable TermSource.
type raisableTermSource struct{ term atomic.Uint64 }

func (r *raisableTermSource) GetTerm() uint64 { return r.term.Load() }

func TestPublisher_RetryFenced_FreshTermAndBudget(t *testing.T) {
	ctx := context.Background()
	terms := &raisableTermSource{}
	terms.term.Store(3)

	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	client := memory.New(memory.ModeClient)
	require.NoError(t, client.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": "steward-test"}))
	require.NoError(t, client.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Stop(stopCtx)
		_ = server.Stop(stopCtx)
	})

	pub, err := commands.New(&commands.Config{
		ControlPlane:    server,
		TermSource:      terms,
		FenceRetryDelay: 10 * time.Millisecond,
		Logger:          logging.NewLogger("error"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = pub.Stop(ctx) })

	received := make(chan *types.SignedCommand, 8)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	type sent struct {
		attempt int
		err     error
	}
	sentCh := make(chan sent, 8)
	onSent := func(attempt int, err error) { sentCh <- sent{attempt, err} }

	// The term is raised before the retry fires; the re-send must carry it.
	terms.term.Store(6)
	require.True(t, pub.RetryFenced("cmd-1", "steward-test", types.CommandSyncConfig, nil, onSent))
	select {
	case cmd := <-received:
		assert.Equal(t, "cmd-1", cmd.Command.ID)
		assert.Equal(t, uint64(6), cmd.Command.Term)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the retry")
	}
	select {
	case s := <-sentCh:
		assert.Equal(t, 1, s.attempt)
		assert.NoError(t, s.err)
	case <-time.After(5 * time.Second):
		t.Fatal("onSent not called")
	}

	// Budget: attempts 2 and 3 are accepted, the 4th call is refused.
	terms.term.Store(7)
	require.True(t, pub.RetryFenced("cmd-1", "steward-test", types.CommandSyncConfig, nil, onSent))
	require.True(t, pub.RetryFenced("cmd-1", "steward-test", types.CommandSyncConfig, nil, onSent))
	for i := 0; i < 2; i++ {
		select {
		case cmd := <-received:
			assert.Equal(t, uint64(7), cmd.Command.Term)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for retry")
		}
	}
	assert.False(t, pub.RetryFenced("cmd-1", "steward-test", types.CommandSyncConfig, nil, onSent))
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, received, "an over-budget call must schedule no send")

	// The count was cleared on exhaustion, and other IDs have their own budget.
	assert.True(t, pub.RetryFenced("cmd-2", "steward-test", types.CommandSyncConfig, nil, nil))
}

func TestPublisher_Stop_CancelsPendingFenceRetries(t *testing.T) {
	ctx := context.Background()
	pub, client := newTestPublisher(t, &staticTermSource{term: 1})
	_ = client
	received := make(chan *types.SignedCommand, 1)
	require.NoError(t, client.SubscribeCommands(ctx, "steward-test", cpinterfaces.CommandHandler(func(_ context.Context, cmd *types.SignedCommand) error {
		received <- cmd
		return nil
	})))

	// Default 2s delay: Stop lands well before the timer fires.
	require.True(t, pub.RetryFenced("cmd-stop", "steward-test", types.CommandSyncConfig, nil, nil))
	require.NoError(t, pub.Stop(ctx))
	assert.False(t, pub.RetryFenced("cmd-after", "steward-test", types.CommandSyncConfig, nil, nil))

	select {
	case <-received:
		t.Fatal("a retry fired after Stop")
	case <-time.After(2500 * time.Millisecond):
	}
}

// TestPublisher_SigningPayloadVersionFollowsStewardCapability proves AC 4 for the
// publisher: a steward that advertised the term-covering payload receives a command
// whose signature verifies over it (and fails once the term is altered), while a
// steward that did not advertise it receives the current payload.
func TestPublisher_SigningPayloadVersionFollowsStewardCapability(t *testing.T) {
	signer, verifier := newTestSignerAndVerifier(t)
	caps := types.NewSigningCapabilities()
	caps.Record("steward-new", types.SupportedSigningPayloadVersions())
	caps.Record("steward-old", nil)

	sent := make(chan *types.SignedCommand, 2)
	pub, err := commands.New(&commands.Config{
		ControlPlane:        &sendHookCP{onSend: func(sc *types.SignedCommand) error { sent <- sc; return nil }},
		Signer:              signer,
		TermSource:          &staticTermSource{term: 9},
		SigningCapabilities: caps,
		Logger:              logging.NewLogger("error"),
	})
	require.NoError(t, err)

	_, err = pub.PublishCommand(context.Background(), "steward-new", types.CommandSyncConfig, map[string]interface{}{"k": "v"})
	require.NoError(t, err)
	newCmd := <-sent
	_, err = pub.PublishCommand(context.Background(), "steward-old", types.CommandSyncConfig, map[string]interface{}{"k": "v"})
	require.NoError(t, err)
	oldCmd := <-sent

	raw := func(sc *types.SignedCommand) map[string]string {
		return types.InterfaceParamsToStringMap(sc.Command.Params)
	}

	assert.Equal(t, types.SigningPayloadV2, newCmd.Command.SigningPayloadVersion)
	v2Bytes, err := types.CommandSigningBytesVersion(&newCmd.Command, raw(newCmd), types.SigningPayloadV2)
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(v2Bytes, newCmd.Signature))
	tampered := newCmd.Command
	tampered.Term = 1 << 60
	tamperedBytes, err := types.CommandSigningBytesVersion(&tampered, raw(newCmd), types.SigningPayloadV2)
	require.NoError(t, err)
	assert.Error(t, verifier.Verify(tamperedBytes, newCmd.Signature), "altering the term must break the v2 signature")

	assert.Zero(t, oldCmd.Command.SigningPayloadVersion)
	v1Bytes, err := types.CommandSigningBytes(&oldCmd.Command, raw(oldCmd))
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(v1Bytes, oldCmd.Signature))
}
