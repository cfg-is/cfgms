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
	stewardcommands "github.com/cfgis/cfgms/features/steward/commands"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// capturedSends is a publisher over a send hook that records every command, a
// real resolver, and the fixture the resolver reads.
type signingVersionHarness struct {
	*resolverFixture
	pub      *commands.Publisher
	sent     chan *types.SignedCommand
	signer   signature.Signer
	verifier signature.Verifier
}

func newSigningVersionHarness(t *testing.T, opts ...commands.CapabilityResolverOption) *signingVersionHarness {
	t.Helper()
	h := &signingVersionHarness{resolverFixture: newResolverFixture(t, opts...), sent: make(chan *types.SignedCommand, 8)}
	h.signer, h.verifier = newTestSignerAndVerifier(t)
	pub, err := commands.New(&commands.Config{
		ControlPlane:    &sendHookCP{onSend: func(sc *types.SignedCommand) error { h.sent <- sc; return nil }},
		Signer:          h.signer,
		TermSource:      &staticTermSource{term: 9},
		SigningVersions: h.resolver,
		Logger:          logging.NewLogger("error"),
	})
	require.NoError(t, err)
	h.pub = pub
	return h
}

func (h *signingVersionHarness) next(t *testing.T) *types.SignedCommand {
	t.Helper()
	select {
	case sc := <-h.sent:
		return sc
	case <-time.After(5 * time.Second):
		t.Fatal("no command was sent")
		return nil
	}
}

// verifiesAsV0105 verifies sc the way a v0.10.5 steward does: the v1 canonical
// bytes (pinned to the v0.10.5 golden vector by the types package) and no version
// field.
func verifiesAsV0105(t *testing.T, v signature.Verifier, sc *types.SignedCommand) bool {
	t.Helper()
	require.NotNil(t, sc.Signature)
	b, err := types.CommandSigningBytes(&sc.Command, types.InterfaceParamsToStringMap(sc.Command.Params))
	require.NoError(t, err)
	return v.Verify(b, sc.Signature) == nil
}

func newStewardHandler(t *testing.T, id string, verifier signature.Verifier, dispatched *atomic.Int32) *stewardcommands.Handler {
	t.Helper()
	steward, err := stewardcommands.New(&stewardcommands.Config{
		StewardID: id,
		OnStatus:  func(context.Context, *types.Event) {},
		Logger:    logging.NewLogger("error"),
		Verifier:  verifier,
	})
	require.NoError(t, err)
	steward.RegisterHandler(types.CommandSyncConfig, func(context.Context, *types.Command) error {
		dispatched.Add(1)
		return nil
	})
	return steward
}

func TestPublisher_PushSigningCertToFloorStewardIsSignedV1(t *testing.T) {
	h := newSigningVersionHarness(t)
	h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityFloor, []int32{1}, []uint32{1})

	// The rotating-cert path: a caller-chosen signer.
	_, err := h.pub.PublishCommandWithSigner(context.Background(), h.id, types.CommandPushSigningCert,
		map[string]interface{}{"cert": "pem"}, h.signer)
	require.NoError(t, err)
	sc := h.next(t)

	assert.Zero(t, sc.Command.SigningPayloadVersion, "a v1 command leaves the version unset on the wire")
	assert.Equal(t, uint64(9), sc.Command.Term, "the stamped term stays")
	assert.True(t, verifiesAsV0105(t, h.verifier, sc), "a v0.10.5 steward verifies the shared-key migration command")

	// And the callback path signs the same way.
	_, err = h.pub.PublishCommandWithSignerAndCallback(context.Background(), h.id, types.CommandPushSigningCert,
		map[string]interface{}{"cert": "pem"}, h.signer, time.Minute, nil, nil)
	require.NoError(t, err)
	sc = h.next(t)
	assert.Zero(t, sc.Command.SigningPayloadVersion)
	assert.True(t, verifiesAsV0105(t, h.verifier, sc))
}

func TestPublisher_DeclaredCurrentStewardIsSignedV2(t *testing.T) {
	h := newSigningVersionHarness(t)
	h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityDeclared, []int32{1, 9}, current())

	_, err := h.pub.PublishCommandWithSigner(context.Background(), h.id, types.CommandPushSigningCert, nil, h.signer)
	require.NoError(t, err)
	assert.Equal(t, types.SigningPayloadV2, h.next(t).Command.SigningPayloadVersion)
}

// Upgrade reconnect: the stored record is the floor from the steward's old build,
// the new connection declares current, and a real steward accepts the first
// on-connect command.
func TestPublisher_UpgradeReconnectFirstCommandIsV2AndAcceptedByARealHandler(t *testing.T) {
	h := newSigningVersionHarness(t, commands.WithCapabilityResolveWait(5*time.Second))
	h.seedOld(business.StewardCapabilityFloor, []uint32{1})
	conn := h.connect("conn-new", 0) // pending until the declaration arrives
	go func() {
		time.Sleep(30 * time.Millisecond)
		conn.SettleCapabilities(registry.CapabilityDeclared, []int32{1, 2}, current())
	}()

	require.NoError(t, h.pub.TriggerConfigSyncWithID(context.Background(), "cmd-first", h.id))
	sc := h.next(t)
	assert.Equal(t, types.SigningPayloadV2, sc.Command.SigningPayloadVersion)

	var dispatched atomic.Int32
	steward := newStewardHandler(t, h.id, h.verifier, &dispatched)
	require.NoError(t, steward.HandleCommand(context.Background(), sc), "a current steward accepts the stamped v2 command")
	steward.Wait()
	assert.Equal(t, int32(1), dispatched.Load())
}

// Rollback reconnect: the stored record says current, the new connection declares
// nothing, so the command goes out v1 once the bounded wait ends.
func TestPublisher_RollbackReconnectIsSignedV1AfterTheWait(t *testing.T) {
	h := newSigningVersionHarness(t)
	h.seedOld(business.StewardCapabilityDeclared, current())
	h.connect("conn-new", 0)

	require.NoError(t, h.pub.TriggerConfigSyncWithID(context.Background(), "cmd-rollback", h.id))
	sc := h.next(t)
	assert.Zero(t, sc.Command.SigningPayloadVersion)
	assert.True(t, verifiesAsV0105(t, h.verifier, sc))
}

// A re-send under the same command ID (the outbox drain, a fence retry) is signed
// again for the connection it goes out on.
func TestPublisher_ResendIsSignedPerConnection(t *testing.T) {
	h := newSigningVersionHarness(t)
	floor := h.connect("conn-old", 0)
	floor.SettleCapabilities(registry.CapabilityFloor, []int32{1}, []uint32{1})

	require.NoError(t, h.pub.PublishCommandWithID(context.Background(), "cmd-outbox", h.id, types.CommandSyncConfig, nil))
	assert.Zero(t, h.next(t).Command.SigningPayloadVersion)

	upgraded := h.connect("conn-new", 0)
	upgraded.SettleCapabilities(registry.CapabilityDeclared, []int32{1}, current())
	require.NoError(t, h.pub.PublishCommandWithID(context.Background(), "cmd-outbox", h.id, types.CommandSyncConfig, nil))
	resent := h.next(t)
	assert.Equal(t, "cmd-outbox", resent.Command.ID)
	assert.Equal(t, types.SigningPayloadV2, resent.Command.SigningPayloadVersion)
}

// Selection reads controller-held state only: a forged version on the command
// and capability-looking params change nothing.
func TestPublisher_SelectionIgnoresForgedVersionAndCapabilityParams(t *testing.T) {
	h := newSigningVersionHarness(t)
	h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityFloor, []int32{1}, []uint32{1})

	forged := map[string]interface{}{
		"signing_payload_version":  float64(2),
		"signing_payload_versions": []interface{}{float64(1), float64(2)},
		"command_types":            []interface{}{float64(14)},
		"capabilities":             "declared",
	}
	require.NoError(t, h.pub.PublishCommandWithID(context.Background(), "cmd-forged", h.id, types.CommandSyncConfig, forged))
	sc := h.next(t)
	assert.Zero(t, sc.Command.SigningPayloadVersion)
	assert.True(t, verifiesAsV0105(t, h.verifier, sc))

	// The other way: a declared-current steward stays v2 whatever the params say.
	h2 := newSigningVersionHarness(t)
	h2.connect("conn-1", 0).SettleCapabilities(registry.CapabilityDeclared, []int32{1}, current())
	require.NoError(t, h2.pub.PublishCommandWithID(context.Background(), "cmd-forged-2", h2.id, types.CommandSyncConfig,
		map[string]interface{}{"signing_payload_versions": []interface{}{float64(1)}}))
	assert.Equal(t, types.SigningPayloadV2, h2.next(t).Command.SigningPayloadVersion)
}

// Even when the controller's record says the steward supports only v1, a current
// steward refuses the stamped v1 command and runs nothing: the verifier, not the
// controller's record, is the authority.
func TestPublisher_CurrentHandlerRefusesStampedV1EvenWhenRecordSaysV1Only(t *testing.T) {
	h := newSigningVersionHarness(t)
	h.connect("conn-1", 0).SettleCapabilities(registry.CapabilityDeclared, []int32{1}, []uint32{1})

	require.NoError(t, h.pub.PublishCommandWithID(context.Background(), "cmd-v1-only", h.id, types.CommandSyncConfig, nil))
	sc := h.next(t)
	require.Zero(t, sc.Command.SigningPayloadVersion)
	require.Equal(t, uint64(9), sc.Command.Term)

	var dispatched atomic.Int32
	steward := newStewardHandler(t, h.id, h.verifier, &dispatched)
	err := steward.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, stewardcommands.ErrUnauthenticatedCommand)
	steward.Wait()
	assert.Zero(t, dispatched.Load(), "nothing is dispatched")
}

func TestPublisher_NoResolverSignsV2(t *testing.T) {
	signer, _ := newTestSignerAndVerifier(t)
	sent := make(chan *types.SignedCommand, 1)
	pub, err := commands.New(&commands.Config{
		ControlPlane: &sendHookCP{onSend: func(sc *types.SignedCommand) error { sent <- sc; return nil }},
		Signer:       signer,
		Logger:       logging.NewLogger("error"),
	})
	require.NoError(t, err)
	_, err = pub.PublishCommand(context.Background(), "s", types.CommandSyncConfig, nil)
	require.NoError(t, err)
	assert.Equal(t, types.SigningPayloadV2, (<-sent).Command.SigningPayloadVersion)
}
