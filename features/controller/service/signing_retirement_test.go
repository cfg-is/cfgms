// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package service_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// retireEnv is a controller wired to an in-process control plane. Commands are
// signed through the same DynamicSigner the server builds, so a test can check
// which key signed what.
type retireEnv struct {
	t          *testing.T
	mgr        *cert.Manager
	rotation   *service.SigningRotationService
	controller *service.ControllerService
	bus        *memory.Bus

	mu       sync.Mutex
	received map[string][]*types.SignedCommand
}

func newRetireEnv(t *testing.T, mgr *cert.Manager) *retireEnv {
	t.Helper()
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	bus := memory.NewBus()
	server := memory.New(memory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() { _ = server.Stop(context.Background()) })

	publisher, err := commands.New(&commands.Config{
		ControlPlane: server,
		Logger:       logger,
		Signer:       signature.NewDynamicSigner(service.NewSigningResolver(mgr)),
	})
	require.NoError(t, err)

	env := &retireEnv{
		t: t, mgr: mgr, bus: bus,
		controller: service.NewControllerService(logger),
		received:   map[string][]*types.SignedCommand{},
	}
	env.rotation = service.NewSigningRotationService(mgr, logger)
	env.rotation.SetPublisher(publisher)
	env.rotation.SetControllerService(env.controller)
	return env
}

// addSteward registers a steward in the fleet and subscribes it to commands.
func (e *retireEnv) addSteward(id string) {
	e.t.Helper()
	require.NoError(e.t, e.controller.RegisterSteward(id, "root", "", "active"))
	e.subscribe(id)
}

// subscribe connects a steward's command stream without registering it in the fleet.
func (e *retireEnv) subscribe(id string) {
	e.t.Helper()
	ctx := context.Background()
	client := memory.New(memory.ModeClient)
	require.NoError(e.t, client.Initialize(ctx, map[string]interface{}{"bus": e.bus, "steward_id": id}))
	require.NoError(e.t, client.Start(ctx))
	e.t.Cleanup(func() { _ = client.Stop(context.Background()) })
	require.NoError(e.t, client.SubscribeCommands(ctx, id, func(_ context.Context, sc *types.SignedCommand) error {
		e.mu.Lock()
		e.received[id] = append(e.received[id], sc)
		e.mu.Unlock()
		return nil
	}))
}

// pushes returns the push_signing_cert commands steward id has received so far.
func (e *retireEnv) pushes(id string) []*types.SignedCommand {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []*types.SignedCommand
	for _, c := range e.received[id] {
		if c.Command.Type == types.CommandPushSigningCert {
			out = append(out, c)
		}
	}
	return out
}

func (e *retireEnv) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.received = map[string][]*types.SignedCommand{}
}

func rawParamsOf(sc *types.SignedCommand) map[string]string {
	if sc.RawParams != nil {
		return sc.RawParams
	}
	return types.InterfaceParamsToStringMap(sc.Command.Params)
}

// retireSerialsOf decodes the retire_serials param, which must be a JSON array.
func retireSerialsOf(t *testing.T, sc *types.SignedCommand) []string {
	t.Helper()
	raw, ok := rawParamsOf(sc)["retire_serials"]
	if !ok {
		return nil
	}
	var out []string
	require.NoError(t, json.Unmarshal([]byte(raw), &out), "retire_serials must be a JSON array of strings, got %q", raw)
	return out
}

// verifiesWith reports whether sc's signature verifies against serial's certificate.
func (e *retireEnv) verifiesWith(sc *types.SignedCommand, serial string) bool {
	e.t.Helper()
	pemBytes, _, err := e.mgr.ExportCertificate(serial, false, false)
	require.NoError(e.t, err)
	v, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: pemBytes})
	require.NoError(e.t, err)
	if sc.Signature == nil {
		return false
	}
	b, err := types.CommandSigningBytes(&sc.Command, rawParamsOf(sc))
	require.NoError(e.t, err)
	return v.Verify(b, sc.Signature) == nil
}

func (e *retireEnv) waitPushes(id string, n int) []*types.SignedCommand {
	e.t.Helper()
	require.Eventually(e.t, func() bool { return len(e.pushes(id)) >= n }, 5*time.Second, 10*time.Millisecond,
		"steward %s must receive %d push_signing_cert", id, n)
	return e.pushes(id)
}

// rotateTwice rotates so the original certificate is the rotating serial with
// the given overlap, and returns (rotating, current) serials.
func (e *retireEnv) rotateTwice(overlapDays int) (string, string) {
	e.t.Helper()
	original, err := e.mgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(e.t, err)
	res, err := e.rotation.Rotate(rootCtx(), "operator-serial", overlapDays, false)
	require.NoError(e.t, err)
	require.Equal(e.t, original.SerialNumber, res.OldSerial)
	return res.OldSerial, res.NewSerial
}

func TestSweep_RetiresRotatingSerialAfterOverlapElapsed(t *testing.T) {
	t.Parallel()
	mgr := newTestCertManager(t, t.TempDir())
	env := newRetireEnv(t, mgr)
	env.addSteward("steward-a")
	env.addSteward("steward-b")
	retire := service.NewSigningRetirementService(env.rotation, nil, logging.NewNoopLogger())

	rotating, current := env.rotateTwice(0) // zero overlap: the window is already closed
	env.waitPushes("steward-a", 1)
	env.waitPushes("steward-b", 1)
	env.reset()

	notified, err := retire.Sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, notified)

	for _, id := range []string{"steward-a", "steward-b"} {
		pushes := env.waitPushes(id, 1)
		assert.Equal(t, []string{rotating}, retireSerialsOf(t, pushes[0]))
		assert.Equal(t, current, rawParamsOf(pushes[0])["serial"], "the push carries the current certificate")
		assert.NotEmpty(t, rawParamsOf(pushes[0])["cert_pem"])
	}

	cursor, err := mgr.GetSigningCursorState()
	require.NoError(t, err)
	require.NotNil(t, cursor.RetiredAt, "the cursor is marked retired after the fan-out")

	// A second sweep has nothing left to do.
	env.reset()
	notified, err = retire.Sweep(context.Background())
	require.NoError(t, err)
	assert.Zero(t, notified)
	assert.Empty(t, env.pushes("steward-a"))
}

func TestSweep_SendsNothingBeforeOverlapElapses(t *testing.T) {
	t.Parallel()
	mgr := newTestCertManager(t, t.TempDir())
	env := newRetireEnv(t, mgr)
	env.addSteward("steward-a")
	retire := service.NewSigningRetirementService(env.rotation, nil, logging.NewNoopLogger())

	env.rotateTwice(30)
	env.waitPushes("steward-a", 1)
	env.reset()

	notified, err := retire.Sweep(context.Background())
	require.NoError(t, err)
	assert.Zero(t, notified)

	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, env.pushes("steward-a"), "nothing is sent while the overlap window is open")
	cursor, err := mgr.GetSigningCursorState()
	require.NoError(t, err)
	assert.Nil(t, cursor.RetiredAt)
}

func TestSweep_OnlyTheLeaderSweeps(t *testing.T) {
	t.Parallel()
	mgr := newTestCertManager(t, t.TempDir())
	env := newRetireEnv(t, mgr)
	env.addSteward("steward-a")
	env.rotateTwice(0)
	env.waitPushes("steward-a", 1)
	env.reset()

	var leader bool
	var mu sync.Mutex
	retire := service.NewSigningRetirementService(env.rotation, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return leader
	}, logging.NewNoopLogger())

	notified, err := retire.Sweep(context.Background())
	require.NoError(t, err)
	assert.Zero(t, notified, "a node without leadership sends nothing")
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, env.pushes("steward-a"))
	cursor, err := mgr.GetSigningCursorState()
	require.NoError(t, err)
	assert.Nil(t, cursor.RetiredAt, "a node without leadership does not mark the cursor")

	mu.Lock()
	leader = true
	mu.Unlock()
	notified, err = retire.Sweep(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, notified)
}

func TestSweep_SkippedInLegacyLocalMode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secrets := testutil.NewMemSecretStore()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)
	dir := t.TempDir()
	build := func(withKeyStore bool) *cert.Manager {
		cfg := &cert.ManagerConfig{
			StoragePath:        dir,
			CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
			SigningCursorStore: cursor,
		}
		if withKeyStore {
			ks, ksErr := cert.NewSecretStoreSigningKeyStore(secrets, clusterTestTenant, "")
			require.NoError(t, ksErr)
			cfg.SigningKeyStore = ks
		}
		m, mErr := cert.NewManagerFromSecretStore(ctx, secrets, clusterTestTenant, "cluster-ca", cfg)
		require.NoError(t, mErr)
		return m
	}
	// A node-local signing certificate, no shared key: the legacy identity.
	require.NoError(t, build(false).EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}))
	mgr := build(true)
	mode, err := mgr.SigningIdentityMode(ctx)
	require.NoError(t, err)
	require.Equal(t, cert.SigningIdentityLegacyLocal, mode)

	// A rotation whose window has long closed.
	_, err = cursor.TransitionCursor(ctx, "legacy-a", 0, false)
	require.NoError(t, err)
	_, err = cursor.TransitionCursor(ctx, "legacy-b", 0, false)
	require.NoError(t, err)

	env := newRetireEnv(t, mgr)
	env.addSteward("steward-a")
	retire := service.NewSigningRetirementService(env.rotation, nil, logging.NewNoopLogger())

	notified, err := retire.Sweep(ctx)
	require.NoError(t, err)
	assert.Zero(t, notified)
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, env.pushes("steward-a"))
	loaded, err := cursor.LoadCursor(ctx)
	require.NoError(t, err)
	assert.Nil(t, loaded.RetiredAt, "a retirement in LegacyLocal mode would strand stewards")
}

func TestReconnectAfterSweepGetsRetirementInSingleOnConnectPush(t *testing.T) {
	t.Parallel()
	mgr := newTestCertManager(t, t.TempDir())
	env := newRetireEnv(t, mgr)
	retire := service.NewSigningRetirementService(env.rotation, nil, logging.NewNoopLogger())

	// The steward is offline for the rotation and for the sweep: it is not in the fleet.
	rotating, current := env.rotateTwice(0)
	notified, err := retire.Sweep(context.Background())
	require.NoError(t, err)
	assert.Zero(t, notified)

	// It reconnects: the on-connect hook runs once.
	env.subscribe("steward-late")
	require.NoError(t, env.rotation.OnConnect(context.Background(), "steward-late"))

	first := env.waitPushes("steward-late", 1)
	require.Len(t, first, 1, "the on-connect hook delivers a single push")
	assert.Equal(t, []string{rotating}, retireSerialsOf(t, first[0]),
		"the first push already carries the retirement")
	time.Sleep(100 * time.Millisecond)
	pushes := env.pushes("steward-late")
	require.Len(t, pushes, 1, "retirement rides the one on-connect push, not a second command")
	assert.Equal(t, []string{rotating}, retireSerialsOf(t, pushes[0]))
	assert.Equal(t, current, rawParamsOf(pushes[0])["serial"])
	assert.True(t, env.verifiesWith(pushes[0], rotating),
		"signed by a key the steward still trusts: it missed every push since the rotation")
	env.mu.Lock()
	total := len(env.received["steward-late"])
	env.mu.Unlock()
	assert.Equal(t, 1, total, "exactly one command is delivered on connect")
}

func TestRevoke_RecordsRetiresAndFansOut(t *testing.T) {
	t.Parallel()
	mgr := newTestCertManager(t, t.TempDir())
	env := newRetireEnv(t, mgr)
	env.addSteward("steward-a")
	env.addSteward("steward-b")
	retire := service.NewSigningRetirementService(env.rotation, nil, logging.NewNoopLogger())

	rotating, current := env.rotateTwice(30) // window open: only the revoke retires it
	env.waitPushes("steward-a", 1)
	env.waitPushes("steward-b", 1)
	env.reset()

	res, err := retire.Revoke(rootCtx(), "operator-serial", rotating, "compromised")
	require.NoError(t, err)
	assert.Equal(t, 2, res.StewardsNotified)
	assert.True(t, res.RetiredFromCursor)

	for _, id := range []string{"steward-a", "steward-b"} {
		pushes := env.waitPushes(id, 1)
		assert.Equal(t, []string{rotating}, retireSerialsOf(t, pushes[0]))
		assert.Equal(t, current, rawParamsOf(pushes[0])["serial"])
		assert.True(t, env.verifiesWith(pushes[0], current), "fan-out is signed by the current key")
	}
	serials, err := mgr.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Equal(t, []string{rotating}, serials)

	_, err = retire.Revoke(rootCtx(), "operator-serial", current, "oops")
	require.ErrorIs(t, err, cert.ErrRevokeCurrentSigningCert)
	_, err = retire.Revoke(context.Background(), "operator-serial", rotating, "no scope")
	require.Error(t, err, "revoke requires root scope")
}

func TestRevokedSerialNeverSigns_ExceptTheDeliveryThatRetiresIt(t *testing.T) {
	t.Parallel()
	mgr := newTestCertManager(t, t.TempDir())
	env := newRetireEnv(t, mgr)
	retire := service.NewSigningRetirementService(env.rotation, nil, logging.NewNoopLogger())

	rotating, current := env.rotateTwice(30)
	_, err := retire.Revoke(rootCtx(), "operator-serial", rotating, "compromised")
	require.NoError(t, err)

	// Every ordinary signing path resolves the current key, never the revoked one.
	signer := signature.NewDynamicSigner(service.NewSigningResolver(mgr))
	sig, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)
	rotatingPEM, _, err := mgr.ExportCertificate(rotating, false, false)
	require.NoError(t, err)
	rotatingVerifier, err := signature.NewVerifier(&signature.VerifierConfig{CertificatePEM: rotatingPEM})
	require.NoError(t, err)
	assert.Error(t, rotatingVerifier.Verify([]byte("payload"), sig), "ordinary signing never uses the revoked key")

	// The one delivery that retires the revoked serial, to a steward that trusts
	// nothing else, is signed by it.
	env.subscribe("steward-late")
	require.NoError(t, env.rotation.OnConnect(context.Background(), "steward-late"))
	pushes := env.waitPushes("steward-late", 1)
	assert.Equal(t, []string{rotating}, retireSerialsOf(t, pushes[0]))
	assert.True(t, env.verifiesWith(pushes[0], rotating), "the retiring delivery is signed by the serial it retires")
	assert.Equal(t, current, rawParamsOf(pushes[0])["serial"])
}

func TestRevokedCurrentSerialRefusesToSign(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rev, err := cert.NewFileRevocationStore(dir)
	require.NoError(t, err)
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:     dir,
		CAConfig:        &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
		RevocationStore: rev,
	})
	require.NoError(t, err)
	require.NoError(t, mgr.EnsureSigningCertificate(nil))
	env := newRetireEnv(t, mgr)

	current, err := mgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	_, err = signature.NewDynamicSigner(service.NewSigningResolver(mgr)).Sign([]byte("payload"))
	require.NoError(t, err)

	// Revoked behind the API's back (the API refuses to revoke the current serial).
	require.NoError(t, rev.Revoke(context.Background(), certinterfaces.RevocationEntry{
		Serial: current.SerialNumber, RevokedAt: time.Now(), Reason: cert.RevocationReasonSigningCert,
	}))

	_, err = signature.NewDynamicSigner(service.NewSigningResolver(mgr)).Sign([]byte("payload"))
	require.Error(t, err, "a revoked current serial must not sign")

	env.subscribe("steward-a")
	require.Error(t, env.rotation.EnsureStewardCurrent(context.Background(), "steward-a"),
		"the on-connect push refuses to sign with a revoked current certificate")
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, env.pushes("steward-a"))
}

func TestRotate_DoesNotSignWithRevokedPredecessor(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rev, err := cert.NewFileRevocationStore(dir)
	require.NoError(t, err)
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath:     dir,
		CAConfig:        &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
		RevocationStore: rev,
	})
	require.NoError(t, err)
	require.NoError(t, mgr.EnsureSigningCertificate(nil))
	env := newRetireEnv(t, mgr)
	env.addSteward("steward-a")

	old, err := mgr.GetCurrentCertForPurpose(cert.PurposeSigning)
	require.NoError(t, err)
	require.NoError(t, rev.Revoke(context.Background(), certinterfaces.RevocationEntry{
		Serial: old.SerialNumber, RevokedAt: time.Now(), Reason: cert.RevocationReasonSigningCert,
	}))

	res, err := env.rotation.Rotate(rootCtx(), "operator-serial", 7, false)
	require.NoError(t, err)

	pushes := env.waitPushes("steward-a", 1)
	assert.False(t, env.verifiesWith(pushes[0], old.SerialNumber), "the revoked predecessor must not sign the rotation fan-out")
	assert.True(t, env.verifiesWith(pushes[0], res.NewSerial))
	assert.Equal(t, []string{old.SerialNumber}, retireSerialsOf(t, pushes[0]), "the revoked serial is retired in the same push")
}
