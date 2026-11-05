// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// lockdownSet is the lockdown predicate for these tests: a mutable set of locked
// stewards plus stewards whose lookup fails. It implements the same one-method
// interface the controller's store-backed predicate does.
type lockdownSet struct {
	mu      sync.Mutex
	locked  map[string]bool
	failing map[string]bool
}

func newLockdownSet() *lockdownSet {
	return &lockdownSet{locked: map[string]bool{}, failing: map[string]bool{}}
}

func (l *lockdownSet) IsLockedDown(_ context.Context, id string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failing[id] {
		return true, errors.New("store unavailable")
	}
	return l.locked[id], nil
}

func (l *lockdownSet) lock(id string) {
	l.mu.Lock()
	l.locked[id] = true
	l.mu.Unlock()
}

// gateObserver records the gate's audit events.
type gateObserver struct {
	mu      sync.Mutex
	refused []string // "steward|type|reason"
	allowed []string // "operator|steward|type"
}

func (o *gateObserver) CommandRefused(_ context.Context, id string, t types.CommandType, reason string) {
	o.mu.Lock()
	o.refused = append(o.refused, id+"|"+string(t)+"|"+reason)
	o.mu.Unlock()
}

func (o *gateObserver) OperatorCommandAllowed(_ context.Context, op, id string, t types.CommandType) {
	o.mu.Lock()
	o.allowed = append(o.allowed, op+"|"+id+"|"+string(t))
	o.mu.Unlock()
}

func (o *gateObserver) snapshot() (refused, allowed []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.refused...), append([]string(nil), o.allowed...)
}

type gateEnv struct {
	server   *Provider
	pred     *lockdownSet
	obs      *gateObserver
	received map[string]chan *types.SignedCommand
	clients  map[string]*Provider
	registry registry.Registry
}

// newGateEnv starts a gated server and connects one steward per ID over real QUIC+mTLS.
func newGateEnv(t *testing.T, ids ...string) *gateEnv {
	t.Helper()
	tc := newTestCA(t)
	reg := registry.NewRegistry()
	pred := newLockdownSet()
	obs := &gateObserver{}

	server := New(ModeServer, WithLockdown(pred, obs))
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": tc.serverTLSConfig(t), "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)

	env := &gateEnv{server: server, pred: pred, obs: obs, registry: reg,
		received: map[string]chan *types.SignedCommand{}, clients: map[string]*Provider{}}
	for _, id := range ids {
		client := New(ModeClient)
		require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
			"mode": "client", "addr": server.ListenAddr(), "tls_config": tc.clientTLSConfig(t, id), "steward_id": id,
		}))
		require.NoError(t, client.Start(context.Background()))
		t.Cleanup(func() { _ = client.Stop(context.Background()) })
		ch := make(chan *types.SignedCommand, 64)
		env.received[id] = ch
		env.clients[id] = client
		require.NoError(t, client.SubscribeCommands(context.Background(), id, func(_ context.Context, sc *types.SignedCommand) error {
			ch <- sc
			return nil
		}))
	}
	require.Eventually(t, func() bool { return reg.Count() == len(ids) }, 5*time.Second, 10*time.Millisecond)
	return env
}

func (e *gateEnv) expectDelivered(t *testing.T, id, cmdID string) {
	t.Helper()
	select {
	case got := <-e.received[id]:
		assert.Equal(t, cmdID, got.Command.ID)
	case <-time.After(5 * time.Second):
		t.Fatalf("steward %s did not receive command %s", id, cmdID)
	}
}

func (e *gateEnv) expectNothing(t *testing.T, id string) {
	t.Helper()
	select {
	case got := <-e.received[id]:
		t.Fatalf("steward %s received a command it must not: %s", id, got.Command.ID)
	case <-time.After(150 * time.Millisecond):
	}
}

func gateCmd(id, steward string, typ types.CommandType) *types.SignedCommand {
	return &types.SignedCommand{Command: types.Command{ID: id, Type: typ, StewardID: steward, Timestamp: time.Now()}}
}

// declaredCommandTypes reads every CommandType constant from messages.go, so a
// new type cannot be added without this test seeing it.
func declaredCommandTypes(t *testing.T) []types.CommandType {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "../../types/messages.go", nil, 0)
	require.NoError(t, err)
	var out []types.CommandType
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "CommandType" {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				require.True(t, ok)
				val, err := strconv.Unquote(lit.Value)
				require.NoError(t, err)
				out = append(out, types.CommandType(val))
			}
		}
	}
	require.NotEmpty(t, out)
	return out
}

// Every command type is classified, an automated command is refused for a locked
// steward and delivered for a normal one, and an unclassified type fails.
func TestLockdownGate_EveryCommandType_AutomatedDeniedForLocked(t *testing.T) {
	env := newGateEnv(t, "s-normal", "s-locked")
	env.pred.lock("s-locked")

	for _, typ := range declaredCommandTypes(t) {
		_, classified := interfaces.CommandLockdownPolicy[typ]
		require.True(t, classified, "command type %q has no lockdown classification", typ)

		t.Run(string(typ), func(t *testing.T) {
			require.NoError(t, env.server.SendCommand(context.Background(), gateCmd("n-"+string(typ), "s-normal", typ)))
			env.expectDelivered(t, "s-normal", "n-"+string(typ))

			err := env.server.SendCommand(context.Background(), gateCmd("l-"+string(typ), "s-locked", typ))
			require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)
			env.expectNothing(t, "s-locked")
		})
	}
}

func TestLockdownGate_OperatorOrigin_Allowlist(t *testing.T) {
	env := newGateEnv(t, "s-locked")
	env.pred.lock("s-locked")
	opCtx := interfaces.WithOperatorOrigin(context.Background(), "alice")

	allowed := []types.CommandType{
		types.CommandStewardAction, types.CommandExecuteScript, types.CommandSyncDNA,
		types.CommandReconnect, types.CommandObserveModules, types.CommandOpenTerminal,
		types.CommandRelayResponse,
	}
	for _, typ := range allowed {
		id := "op-" + string(typ)
		require.NoError(t, env.server.SendCommand(opCtx, gateCmd(id, "s-locked", typ)), typ)
		env.expectDelivered(t, "s-locked", id)
	}

	denied := []types.CommandType{
		types.CommandSyncConfig, types.CommandPushSigningCert, types.CommandPushStewardBinary,
		types.CommandType("brand_new_command"),
	}
	for _, typ := range denied {
		err := env.server.SendCommand(opCtx, gateCmd("deny-"+string(typ), "s-locked", typ))
		require.ErrorIs(t, err, interfaces.ErrStewardLockedDown, typ)
	}
	env.expectNothing(t, "s-locked")

	refused, auditAllowed := env.obs.snapshot()
	require.Len(t, auditAllowed, len(allowed))
	assert.Contains(t, auditAllowed, "alice|s-locked|steward_action")
	assert.Contains(t, auditAllowed, "alice|s-locked|execute_script")
	assert.Len(t, refused, len(denied))
	assert.Contains(t, refused, "s-locked|push_steward_binary|command_type_denied")
}

func TestLockdownGate_AutomaticObserveModulesDenied(t *testing.T) {
	env := newGateEnv(t, "s-locked")
	env.pred.lock("s-locked")
	err := env.server.SendCommand(context.Background(), gateCmd("auto-observe", "s-locked", types.CommandObserveModules))
	require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)
	refused, _ := env.obs.snapshot()
	assert.Equal(t, []string{"s-locked|observe_modules|no_operator_origin"}, refused)
}

func TestLockdownGate_LookupErrorFailsClosed(t *testing.T) {
	env := newGateEnv(t, "s-flaky")
	env.pred.mu.Lock()
	env.pred.failing["s-flaky"] = true
	env.pred.mu.Unlock()

	opCtx := interfaces.WithOperatorOrigin(context.Background(), "alice")
	for _, ctx := range []context.Context{context.Background(), opCtx} {
		err := env.server.SendCommand(ctx, gateCmd("c", "s-flaky", types.CommandSyncDNA))
		require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)
	}
	env.expectNothing(t, "s-flaky")
	refused, _ := env.obs.snapshot()
	assert.Equal(t, []string{"s-flaky|sync_dna|lookup_failed", "s-flaky|sync_dna|lookup_failed"}, refused)
}

// A locked steward attached to another node is refused before the registry
// lookup, so the caller never sees ErrStewardNotConnected and does not forward.
func TestLockdownGate_LockedStewardOnAnotherNode_NotReportedAsNotConnected(t *testing.T) {
	env := newGateEnv(t, "s-here")
	env.pred.lock("s-elsewhere")

	err := env.server.SendCommand(context.Background(), gateCmd("c", "s-elsewhere", types.CommandSyncDNA))
	require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)
	assert.NotErrorIs(t, err, interfaces.ErrStewardNotConnected)

	err = env.server.SendCommand(context.Background(), gateCmd("c2", "s-unlocked-elsewhere", types.CommandSyncDNA))
	require.ErrorIs(t, err, interfaces.ErrStewardNotConnected)
}

// A command built before the steward became tampered is refused when it is sent.
func TestLockdownGate_QueuedBeforeTamper_RefusedAtSendTime(t *testing.T) {
	env := newGateEnv(t, "s-1")
	queued := gateCmd("queued", "s-1", types.CommandSyncConfig)

	env.pred.lock("s-1") // the transition happens after the command was queued

	require.ErrorIs(t, env.server.SendCommand(context.Background(), queued), interfaces.ErrStewardLockedDown)
	env.expectNothing(t, "s-1")
}

func TestLockdownGate_FanOut_TamperedReportedDeniedOthersDelivered(t *testing.T) {
	env := newGateEnv(t, "s-a", "s-b", "s-locked")
	env.pred.lock("s-locked")

	result, err := env.server.FanOutCommand(context.Background(),
		gateCmd("fan", "", types.CommandSyncDNA), []string{"s-a", "s-locked", "s-b", "s-gone"})
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"s-a", "s-b"}, result.Succeeded)
	require.ErrorIs(t, result.Failed["s-locked"], interfaces.ErrStewardLockedDown)
	require.ErrorIs(t, result.Failed["s-gone"], interfaces.ErrStewardNotConnected)
	env.expectDelivered(t, "s-a", "fan")
	env.expectDelivered(t, "s-b", "fan")
	env.expectNothing(t, "s-locked")
}

// A tampered steward's heartbeat and event still reach the controller.
func TestLockdownGate_TamperedStewardHeartbeatAndEventStillAccepted(t *testing.T) {
	env := newGateEnv(t, "s-locked")
	env.pred.lock("s-locked")

	hbs := make(chan *types.Heartbeat, 1)
	evs := make(chan *types.Event, 1)
	require.NoError(t, env.server.SubscribeHeartbeats(context.Background(), func(_ context.Context, hb *types.Heartbeat) error {
		hbs <- hb
		return nil
	}))
	require.NoError(t, env.server.SubscribeEvents(context.Background(), nil, func(_ context.Context, ev *types.Event) error {
		evs <- ev
		return nil
	}))

	now := time.Now()
	require.NoError(t, env.clients["s-locked"].SendHeartbeat(context.Background(),
		&types.Heartbeat{StewardID: "s-locked", Status: types.StatusHealthy, Timestamp: now}))
	require.NoError(t, env.clients["s-locked"].PublishEvent(context.Background(),
		&types.Event{ID: "e1", Type: types.EventConfigApplied, StewardID: "s-locked", Timestamp: now, Severity: "info"}))

	select {
	case hb := <-hbs:
		assert.Equal(t, "s-locked", hb.StewardID)
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat from tampered steward was not accepted")
	}
	select {
	case ev := <-evs:
		assert.Equal(t, "e1", ev.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("event from tampered steward was not accepted")
	}
}

func TestWithOperatorOrigin_EmptyPrincipalGivesNoMarker(t *testing.T) {
	_, ok := interfaces.OperatorOriginFrom(interfaces.WithOperatorOrigin(context.Background(), ""))
	assert.False(t, ok)
	p, ok := interfaces.OperatorOriginFrom(interfaces.WithOperatorOrigin(context.Background(), "bob"))
	assert.True(t, ok)
	assert.Equal(t, "bob", p)
}

// A tampered steward's open control stream receives no sync_config when its
// configuration is saved: the save path sends CommandSyncConfig over the stream,
// and the gate refuses it even when an operator caused the save (Issue #5666).
func TestLockdownGate_ConfigSavePush_NoSyncConfigOnOpenStream(t *testing.T) {
	env := newGateEnv(t, "s-normal", "s-locked")
	env.pred.lock("s-locked")

	for name, ctx := range map[string]context.Context{
		"automated": context.Background(),
		"operator":  interfaces.WithOperatorOrigin(context.Background(), "operator-1"),
	} {
		t.Run(name, func(t *testing.T) {
			err := env.server.SendCommand(ctx, gateCmd("save-"+name, "s-locked", types.CommandSyncConfig))
			require.ErrorIs(t, err, interfaces.ErrStewardLockedDown)
			env.expectNothing(t, "s-locked")
		})
	}

	require.NoError(t, env.server.SendCommand(context.Background(), gateCmd("save-normal", "s-normal", types.CommandSyncConfig)))
	env.expectDelivered(t, "s-normal", "save-normal")
}
