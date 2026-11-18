// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	sdna "github.com/cfgis/cfgms/pkg/dna"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// Wiring tests for the steward capability declaration and its late-declaration
// recovery (Issue #6337, epic #6307). The unit tests in features/controller/service
// drive the replay, the drain hook and the rejection recorder directly, so they
// pass whether or not server.New connects them. These tests build the controller
// with New, start it, and connect real client-mode control plane providers over
// QUIC with mTLS, so a wiring line removed from server.go fails a named assertion.

const (
	capWiringTenant = "cap-wiring-tenant"
	capWiringWait   = 45 * time.Second
	capWiringTick   = 50 * time.Millisecond
)

// capWiringInbox collects the commands a client-mode provider receives.
type capWiringInbox struct {
	mu       sync.Mutex
	commands []receivedCommand
}

type receivedCommand struct {
	id      string
	cmdType controlplaneTypes.CommandType
	version uint32
	at      time.Time
}

func (b *capWiringInbox) handle(_ context.Context, sc *controlplaneTypes.SignedCommand) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.commands = append(b.commands, receivedCommand{
		id:      sc.Command.ID,
		cmdType: sc.Command.Type,
		version: sc.Command.SigningPayloadVersion,
		at:      time.Now(),
	})
	return nil
}

func (b *capWiringInbox) all() []receivedCommand {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]receivedCommand(nil), b.commands...)
}

// byID returns the command with the given ID, if it has arrived.
func (b *capWiringInbox) byID(id string) (receivedCommand, bool) {
	for _, c := range b.all() {
		if c.id == id {
			return c, true
		}
	}
	return receivedCommand{}, false
}

// byType returns the commands of one type, in arrival order.
func (b *capWiringInbox) byType(t controlplaneTypes.CommandType) []receivedCommand {
	var out []receivedCommand
	for _, c := range b.all() {
		if c.cmdType == t {
			out = append(out, c)
		}
	}
	return out
}

// capWiringSteward is a registered steward and its connected client provider.
type capWiringSteward struct {
	id       string
	provider *grpcCP.Provider
	inbox    *capWiringInbox
}

// capWiringStart builds the controller with New (real transport, certificate
// management and storage) and starts it.
func capWiringStart(t *testing.T) *Server {
	t.Helper()
	srv := serverstartCharBuild(t, logging.NewNoopLogger(), true)
	require.NoError(t, srv.Start())
	require.NotNil(t, srv.quicListener, "Start must open the QUIC listener")
	require.NotNil(t, srv.commandPublisher)
	require.NotNil(t, srv.jobDispatcher)
	require.NotNil(t, srv.executionQueue)
	return srv
}

// capWiringRegister registers a steward through the controller service and makes
// sure the steward store, which the approval gate and the drain hook read, holds
// an admitted record for it with its tenant.
func capWiringRegister(t *testing.T, srv *Server) string {
	t.Helper()
	frag := func(kind string, fields map[string]interface{}) *commonpb.Fragment {
		f, err := sdna.NewFragment(kind, "test", sdna.MapState(fields))
		require.NoError(t, err)
		return f
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, capWiringTenant)
	resp, err := srv.controllerService.AcceptRegistration(ctx, &controllerpb.RegisterRequest{
		InitialDna: &commonpb.DNA{
			Id:              "cap-wiring-" + uuid.NewString(),
			SyncFingerprint: "cap-wiring-fp",
			Fragments: []*commonpb.Fragment{
				frag("hostname", map[string]interface{}{"hostname": "cap-wiring-host"}),
				frag("host:os", map[string]interface{}{"os": "linux"}),
			},
		},
	})
	require.NoError(t, err)
	id := resp.StewardId
	require.NotEmpty(t, id)

	store := srv.storageManager.GetStewardStore()
	rec, err := store.GetSteward(ctx, id)
	if errors.Is(err, business.ErrStewardNotFound) {
		now := time.Now()
		require.NoError(t, store.RegisterSteward(ctx, &business.StewardRecord{
			ID:           id,
			TenantID:     capWiringTenant,
			Hostname:     "cap-wiring-host",
			Platform:     "linux",
			Arch:         "amd64",
			Status:       business.StewardStatusRegistered,
			RegisteredAt: now,
			LastSeen:     now,
		}))
		rec, err = store.GetSteward(ctx, id)
	}
	require.NoError(t, err)
	require.Equal(t, capWiringTenant, rec.TenantID)
	return id
}

// capWiringConnect connects a client-mode provider for steward id over QUIC with a
// certificate the controller's certificate manager issues at test time.
func capWiringConnect(t *testing.T, srv *Server, id string, cp *grpcCP.Provider) *capWiringSteward {
	t.Helper()
	caPEM, err := srv.certManager.GetCACertificate()
	require.NoError(t, err)
	cc, err := srv.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   id,
		Organization: "CFGMS capability wiring test",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	tlsCfg, err := cert.CreateClientTLSConfig(cc.CertificatePEM, cc.PrivateKeyPEM, caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	tlsCfg.NextProtos = []string{quictransport.ALPNProtocol}

	ctx := context.Background()
	require.NoError(t, cp.Initialize(ctx, map[string]interface{}{
		"mode":       "client",
		"addr":       srv.quicListener.Addr().String(),
		"tls_config": tlsCfg,
		"steward_id": id,
		"tenant_id":  capWiringTenant,
	}))
	inbox := &capWiringInbox{}
	require.NoError(t, cp.Start(ctx))
	t.Cleanup(func() { _ = cp.Stop(context.Background()) })
	require.NoError(t, cp.SubscribeCommands(ctx, id, inbox.handle))

	require.Eventually(t, func() bool {
		_, ok := srv.connRegistry.Get(id)
		return ok
	}, 15*time.Second, capWiringTick, "steward %s must open a control channel", id)
	return &capWiringSteward{id: id, provider: cp, inbox: inbox}
}

// capWiringCapabilities reads the steward's durable capability record.
func capWiringCapabilities(srv *Server, id string) *business.StewardCapabilityRecord {
	rec, err := srv.storageManager.GetStewardStore().GetSteward(context.Background(), id)
	if err != nil || rec == nil {
		return nil
	}
	return rec.Capabilities
}

// TestCapabilityWiring_DeclaringStewardIsSignedV2 proves a steward that declares
// its capabilities is signed for in payload v2 and that the control plane writes
// the declaration to the durable record. Removing grpcCP.WithCapabilityRecorder
// from server.go fails the durable-record assertion; removing the publisher's
// SigningVersions does not (a declared steward is v2 either way), which the
// silent-steward test below covers.
func TestCapabilityWiring_DeclaringStewardIsSignedV2(t *testing.T) {
	srv := capWiringStart(t)
	id := capWiringRegister(t, srv)
	st := capWiringConnect(t, srv, id, grpcCP.New(grpcCP.ModeClient, grpcCP.WithStewardCapabilities(grpcCP.LocalCapabilities(id))))

	cmdID, err := srv.commandPublisher.PublishCommand(context.Background(), id, controlplaneTypes.CommandSyncDNA, map[string]interface{}{})
	require.NoError(t, err)

	var got receivedCommand
	require.Eventually(t, func() bool {
		c, ok := st.inbox.byID(cmdID)
		got = c
		return ok
	}, capWiringWait, capWiringTick, "the declaring steward must receive the published command")
	assert.Equal(t, controlplaneTypes.SigningPayloadV2, got.version,
		"a steward that declared v2 must be sent the v2 signing payload")

	require.Eventually(t, func() bool {
		c := capWiringCapabilities(srv, id)
		return c != nil && c.State == business.StewardCapabilityDeclared
	}, capWiringWait, capWiringTick,
		"the control plane must write the declaration to the durable record (grpcCP.WithCapabilityRecorder)")
	caps := capWiringCapabilities(srv, id)
	assert.Contains(t, caps.SigningPayloadVersions, controlplaneTypes.SigningPayloadV2,
		"the durable record must carry the declared v2")
}

// TestCapabilityWiring_SilentStewardFloorAndLateDeclaration proves, for one steward
// that does not declare at connect, that:
//   - a command the dispatcher sends and the drain row the connect hook publishes
//     are signed in the floor form (version 0), and the durable record settles at
//     the floor after the grace period;
//   - a later declaration marks the floor-form drain row rejected for re-issue and
//     re-runs the replay set, which sends a v2 command exactly once.
//
// Removing from server.go: dispatcher SigningVersions fails the dispatch version
// assertion; publisher SigningVersions fails the drain-row version assertion;
// grpcCP.WithCapabilityRecorder fails the durable floor-record assertion;
// SetSigningResolver and grpcCP.WithOnLateCapabilities fail the re-issue and
// replay assertions. SetFloorSentTracker cannot be proven here: the replay writes
// the same DeliveryDetailSigningFormRefusedReissue outcome first.
func TestCapabilityWiring_SilentStewardFloorAndLateDeclaration(t *testing.T) {
	srv := capWiringStart(t)
	id := capWiringRegister(t, srv)
	ctx := context.Background()

	// A pending drain row, created before the steward connects.
	rowID := uuid.NewString()
	require.NoError(t, srv.storageManager.GetCommandStore().CreateCommandRecord(ctx, &business.CommandRecord{
		ID:             rowID,
		Type:           string(controlplaneTypes.CommandSyncDNA),
		StewardID:      id,
		TenantID:       capWiringTenant,
		Payload:        map[string]interface{}{},
		IssuedBy:       "capability-wiring-test",
		IssuedAt:       time.Now(),
		DeliveryStatus: business.DeliveryStatusPending,
	}))

	connectedAt := time.Now()
	st := capWiringConnect(t, srv, id, grpcCP.New(grpcCP.ModeClient))

	// One command through the job dispatcher before the steward declares.
	execID := uuid.NewString()
	require.NoError(t, srv.executionQueue.QueueExecution(id, &scriptmodule.QueuedExecution{
		ExecutionID: execID,
		Shell:       scriptmodule.ShellBash,
		Timeout:     time.Minute,
		Metadata:    map[string]interface{}{"inline_script_content": "true"},
	}))
	srv.jobDispatcher.OnHeartbeat(id)

	var dispatched receivedCommand
	require.Eventually(t, func() bool {
		cmds := st.inbox.byType(controlplaneTypes.CommandExecuteScript)
		if len(cmds) == 0 {
			return false
		}
		dispatched = cmds[0]
		return true
	}, capWiringWait, capWiringTick, "the dispatcher must send the queued execution")
	assert.Zero(t, dispatched.version,
		"a steward that has not declared must be sent the floor (v1) form by the dispatcher")

	// The drain row arrives in the floor form once the resolver stops waiting.
	var drained receivedCommand
	require.Eventually(t, func() bool {
		c, ok := st.inbox.byID(rowID)
		drained = c
		return ok
	}, capWiringWait, capWiringTick, "the drain hook must deliver the pending row")
	assert.Zero(t, drained.version, "the drain row must be signed in the floor (v1) form")
	assert.GreaterOrEqual(t, drained.at.Sub(connectedAt), commands.DefaultCapabilityResolveWait-time.Second,
		"the row must not be sent before the resolver's wait for a declaration has run")

	// With no declaration, the default grace settles the durable record at the floor.
	require.Eventually(t, func() bool {
		c := capWiringCapabilities(srv, id)
		return c != nil && c.State == business.StewardCapabilityFloor
	}, capWiringWait, capWiringTick,
		"the grace period must settle the durable record at the floor (grpcCP.WithCapabilityRecorder)")
	require.GreaterOrEqual(t, time.Since(connectedAt), grpcCP.DefaultCapabilityGrace-time.Second)

	// The row was recorded delivered, not rejected, before the late declaration.
	require.Eventually(t, func() bool {
		rec, err := srv.storageManager.GetCommandStore().GetCommandRecord(ctx, rowID)
		return err == nil && rec.DeliveryStatus == business.DeliveryStatusDelivered
	}, capWiringWait, capWiringTick, "the drain hook must record the row delivered")

	isReplayCommand := func(c receivedCommand) bool {
		return c.cmdType == controlplaneTypes.CommandAdvertiseTransportAddress ||
			c.cmdType == controlplaneTypes.CommandPushSigningCert
	}
	v2Replayed := func() int {
		n := 0
		for _, c := range st.inbox.all() {
			if isReplayCommand(c) && c.version == controlplaneTypes.SigningPayloadV2 {
				n++
			}
		}
		return n
	}
	for _, c := range st.inbox.all() {
		if isReplayCommand(c) {
			assert.Zero(t, c.version, "a connect hook command sent during the grace must be in the floor form")
		}
	}
	require.Zero(t, v2Replayed())

	// The same steward declares after the grace.
	require.NoError(t, st.provider.SendCapabilities(ctx, capWiringLocal(id)))

	require.Eventually(t, func() bool {
		rec, err := srv.storageManager.GetCommandStore().GetCommandRecord(ctx, rowID)
		return err == nil &&
			rec.DeliveryStatus == business.DeliveryStatusRejected &&
			rec.DeliveryDetail == business.DeliveryDetailSigningFormRefusedReissue
	}, capWiringWait, capWiringTick,
		"a late declaration must mark the floor-form row rejected for re-issue (SetSigningResolver, grpcCP.WithOnLateCapabilities)")

	// The transport address hook runs last in the replay set, so once its v2
	// advertisement has arrived the replay has sent everything it will send.
	advertisedV2 := func() int {
		n := 0
		for _, c := range st.inbox.byType(controlplaneTypes.CommandAdvertiseTransportAddress) {
			if c.version == controlplaneTypes.SigningPayloadV2 {
				n++
			}
		}
		return n
	}
	require.Eventually(t, func() bool { return advertisedV2() > 0 }, capWiringWait, capWiringTick,
		"a late declaration must re-run the replay set, signed in v2 (grpcCP.WithOnLateCapabilities)")
	replayed := v2Replayed()

	// A second declaration on the same connection must not replay again.
	require.NoError(t, st.provider.SendCapabilities(ctx, capWiringLocal(id)))
	time.Sleep(2 * time.Second)
	assert.Equal(t, replayed, v2Replayed(), "the replay must run exactly once per connection")
	assert.Equal(t, 1, advertisedV2(), "the replay must advertise the transport address in v2 exactly once")

	// The declaration is now durable as v2.
	require.Eventually(t, func() bool {
		c := capWiringCapabilities(srv, id)
		return c != nil && c.State == business.StewardCapabilityDeclared
	}, capWiringWait, capWiringTick)
}

func capWiringLocal(id string) *controlplaneTypes.StewardCapabilities {
	caps := grpcCP.LocalCapabilities(id)
	return &caps
}

// TestLateReplayRelay_NoOpUntilBound pins the relay's contract: the provider is
// built before the replay exists, so a callback that fires early does nothing and
// one fired after Set reaches the replay.
func TestLateReplayRelay_NoOpUntilBound(t *testing.T) {
	var relay lateReplayRelay
	assert.NotPanics(t, func() { relay.OnLateCapabilities(context.Background(), "steward-a") },
		"an unbound relay must ignore the callback")
	assert.Nil(t, relay.target.Load())

	relay.Set(service.NewLateDeclarationReplay(logging.NewNoopLogger(), nil, nil, nil))
	assert.NotNil(t, relay.target.Load())
	assert.NotPanics(t, func() { relay.OnLateCapabilities(context.Background(), "steward-a") },
		"a bound relay must hand the callback to the replay")
}
