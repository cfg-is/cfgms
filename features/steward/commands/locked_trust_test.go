// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package commands

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/steward/operatorroster"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

const lockedStewardID = "steward-test"

// lockedFx is a controller PKI for locked-trust tests: a root, an optional
// intermediate, a CodeSigning certificate (the controller's command signer), a
// payload-signing operator certificate and a server certificate for the link.
type lockedFx struct {
	rootPEM  []byte
	root     *x509.Certificate
	interPEM []byte
	issuer   *cert.CA
	signing  *cert.Certificate
	operator *cert.Certificate
	server   *x509.Certificate
	chainPEM []byte
	signer   *signature.ConfigSigner
}

func newLockedFx(t *testing.T, withIntermediate bool) *lockedFx {
	t.Helper()
	rootCA, err := cert.NewCA(&cert.CAConfig{
		Organization: "Locked Test Root", Country: "US", ValidityDays: 365, KeySize: 2048,
		PathLength: 1, PathLengthSet: true,
	})
	require.NoError(t, err)
	require.NoError(t, rootCA.Initialize(nil))
	rootPEM, err := rootCA.GetCACertificate()
	require.NoError(t, err)
	root, err := cert.ParseCertificateFromPEM(rootPEM)
	require.NoError(t, err)

	fx := &lockedFx{rootPEM: rootPEM, root: root, issuer: rootCA}
	if withIntermediate {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		subCert, err := rootCA.SignSubordinateCA(&key.PublicKey, &cert.SubordinateCAConfig{
			CommonName: "Locked Test Intermediate", Organization: "Locked Test", ValidityDays: 365, PathLength: 0,
		})
		require.NoError(t, err)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		sub, err := cert.NewCA(&cert.CAConfig{Organization: "Locked Test"})
		require.NoError(t, err)
		require.NoError(t, sub.ImportSubordinateCA(subCert.CertificatePEM, keyPEM, rootPEM))
		fx.issuer = sub
		fx.interPEM = subCert.CertificatePEM
	}

	fx.signing, err = fx.issuer.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName: "locked-test-signer", Organization: "Locked Test", ValidityDays: 365, KeySize: 2048,
	})
	require.NoError(t, err)
	fx.operator, err = fx.issuer.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "operator.test", ValidityDays: 365, KeySize: 2048, TemplateModifier: boundPayloadSigning,
	})
	require.NoError(t, err)
	srv, err := fx.issuer.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, ValidityDays: 365, KeySize: 2048,
	})
	require.NoError(t, err)
	fx.server, err = cert.ParseCertificateFromPEM(srv.CertificatePEM)
	require.NoError(t, err)

	fx.chainPEM = append(append(append([]byte{}, fx.signing.CertificatePEM...), fx.interPEM...), rootPEM...)
	fx.signer, err = signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: fx.signing.CertificatePEM, PrivateKeyPEM: fx.signing.PrivateKeyPEM,
	})
	require.NoError(t, err)
	return fx
}

// bakedFor returns the baked-root check of a binary whose baked list holds the
// fingerprints of roots: a self-signed CA with a listed fingerprint.
func bakedFor(roots ...*x509.Certificate) func(*x509.Certificate) bool {
	return func(c *x509.Certificate) bool {
		if c == nil || !c.IsCA || c.CheckSignatureFrom(c) != nil {
			return false
		}
		sum := sha256.Sum256(c.Raw)
		for _, r := range roots {
			if r.Raw != nil && sum == sha256.Sum256(r.Raw) {
				return true
			}
		}
		return false
	}
}

// link returns the server certificate chain of a stream to this controller.
func (fx *lockedFx) link() func() []*x509.Certificate {
	chain := []*x509.Certificate{fx.server}
	if fx.interPEM != nil {
		chain = append(chain, mustCertNoT(fx.interPEM))
	}
	return func() []*x509.Certificate { return chain }
}

func mustCertNoT(certPEM []byte) *x509.Certificate {
	c, err := cert.ParseCertificateFromPEM(certPEM)
	if err != nil {
		panic(err)
	}
	return c
}

// sign signs sc with the controller signing certificate and attaches the chain.
func (fx *lockedFx) sign(t *testing.T, sc *cpTypes.SignedCommand) *cpTypes.SignedCommand {
	t.Helper()
	sc.Command.SigningPayloadVersion = cpTypes.SigningPayloadV2
	raw := cpTypes.InterfaceParamsToStringMap(sc.Command.Params)
	data, err := cpTypes.CommandSigningBytesVersion(&sc.Command, raw, cpTypes.SigningPayloadV2)
	require.NoError(t, err)
	sc.Signature, err = fx.signer.Sign(data)
	require.NoError(t, err)
	sc.SignerChainPEM = fx.chainPEM
	return sc
}

func lockedCmd(id string, typ cpTypes.CommandType, params map[string]interface{}) *cpTypes.SignedCommand {
	return &cpTypes.SignedCommand{Command: cpTypes.Command{
		ID: id, Type: typ, StewardID: lockedStewardID, Timestamp: time.Now(), Params: params,
	}}
}

// manifest returns a signed revocation manifest issued at issuedAt.
func (fx *lockedFx) manifest(t *testing.T, issuedAt time.Time, revoked ...string) []byte {
	t.Helper()
	// The roster authorizes the fixture's operator, as the controller's manifest does for an
	// account holding operator-payload:sign.
	return signManifestWith(t, fx.signing, issuedAt, revoked, rootScopeSignerEntry(fx.operator))
}

func signManifestWith(t *testing.T, signingCert *cert.Certificate, issuedAt time.Time, revoked []string, signers ...operatorroster.AuthorizedX509Signer) []byte {
	t.Helper()
	if revoked == nil {
		revoked = []string{}
	}
	m := revocationManifestPayload{Kind: revocationManifestKind, Version: int64(len(revoked)), IssuedAt: issuedAt, RevokedSerials: revoked, AuthorizedX509Signers: signers}
	data, err := json.Marshal(m)
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM, PrivateKeyPEM: signingCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)
	out, err := json.Marshal(signedRevocationManifest{Manifest: m, Signature: sig, SignerCertificatePEM: string(signingCert.CertificatePEM)})
	require.NoError(t, err)
	return out
}

// reasons records the reasons a locked handler sets.
type reasons struct {
	mu   sync.Mutex
	list []string
}

func (r *reasons) set(code string) {
	r.mu.Lock()
	r.list = append(r.list, code)
	r.mu.Unlock()
}

func (r *reasons) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.list) == 0 {
		return ""
	}
	return r.list[len(r.list)-1]
}

// lockedHarness is a locked handler with real script execution and recording
// service and terminal back ends.
type lockedHarness struct {
	fx     *lockedFx
	trust  *LockedTrust
	h      *Handler
	rs     *reasons
	ctrl   *recordingServiceController
	dialer *recordingDialer
	events func() []*cpTypes.Event
}

type harnessOpts struct {
	matcher         func(*x509.Certificate) bool
	bakedReason     func() string
	skipManifest    bool
	manifestIssued  time.Time
	revoked         []string
	disableTerminal bool
	refresh         func(ctx context.Context) error
}

func newLockedHarness(t *testing.T, fx *lockedFx, o harnessOpts) *lockedHarness {
	t.Helper()
	if o.matcher == nil {
		o.matcher = bakedFor(fx.root)
	}
	rs := &reasons{}
	trust, err := NewLockedTrust(LockedTrustConfig{
		MatchesBakedRoot: o.matcher, BakedRootReason: o.bakedReason,
		RevocationRefreshInterval: time.Minute, OnReason: rs.set, RefreshRevocation: o.refresh,
	})
	require.NoError(t, err)
	if !o.skipManifest {
		roots, err := cert.CertPoolFromPEM(fx.rootPEM)
		require.NoError(t, err)
		var inter *x509.CertPool
		if fx.interPEM != nil {
			inter, err = cert.CertPoolFromPEM(fx.interPEM)
			require.NoError(t, err)
		}
		trust.Revocation().SetTrust(roots, inter)
		issued := o.manifestIssued
		if issued.IsZero() {
			issued = time.Now()
		}
		require.NoError(t, trust.Revocation().VerifyManifest(fx.manifest(t, issued.UTC().Truncate(time.Second), o.revoked...), stewardtypes.ModuleTrustModeStrict))
	}
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: lockedStewardID, OnStatus: cb, Logger: newTestLogger(t), Locked: trust})
	require.NoError(t, err)
	ctrl := &recordingServiceController{self: map[string]bool{}}
	dialer := newRecordingDialer()
	h.RegisterExecuteScriptHandler()
	h.registerStewardAction(ctrl, newPlatformProcessController())
	h.RegisterOpenTerminalHandler(dialer)
	if o.disableTerminal {
		h.DisableRemoteTerminal()
	}
	return &lockedHarness{fx: fx, trust: trust, h: h, rs: rs, ctrl: ctrl, dialer: dialer, events: getEvents}
}

// scriptCmd, actionCmd and terminalCmd build fully valid signed commands.
func (lh *lockedHarness) scriptCmd(t *testing.T, id string) *cpTypes.SignedCommand {
	t.Helper()
	op := lh.fx.operator
	params := sigTestOperatorEnvelopeParams(t, op.PrivateKeyPEM, string(op.CertificatePEM), []byte(echoScriptBody("locked-hello")), platformShell(), lockedStewardID)
	params["execution_id"] = "exec-" + id
	return lh.fx.sign(t, lockedCmd(id, cpTypes.CommandExecuteScript, params))
}

func (lh *lockedHarness) actionCmd(t *testing.T, id string) *cpTypes.SignedCommand {
	t.Helper()
	content := testActionContent(t, operatorpayload.Action{Verb: "service.start", TargetKind: "service", TargetName: "nginx"})
	params := signedActionParams(t, lh.fx.operator, content, []string{lockedStewardID}, sigTestNonce(t), time.Now().Add(time.Minute))
	params["execution_id"] = "exec-" + id
	params["verb"] = "service.start"
	params["target"] = map[string]interface{}{"kind": "service", "name": "nginx"}
	params["parameters"] = map[string]string{}
	return lh.fx.sign(t, lockedCmd(id, cpTypes.CommandStewardAction, params))
}

func (lh *lockedHarness) terminalCmd(t *testing.T, id string) *cpTypes.SignedCommand {
	t.Helper()
	params := validTerminalParams(t, lh.fx.operator, allowedShell(), "sess-"+id)
	return lh.fx.sign(t, lockedCmd(id, cpTypes.CommandOpenTerminal, params))
}

func (lh *lockedHarness) handle(sc *cpTypes.SignedCommand) error {
	return lh.h.HandleLockedCommand(context.Background(), sc, lh.fx.link())
}

// requireRefused asserts sc is refused and nothing runs.
func (lh *lockedHarness) requireRefused(t *testing.T, sc *cpTypes.SignedCommand) {
	t.Helper()
	// Chain, link, signature and parameter refusals are synchronous. A steward
	// action or terminal envelope is checked by its handler, so the refusal can
	// surface as a failed command instead; either way nothing runs.
	if err := lh.refuseAndAssertInert(t, sc); err != nil {
		assert.ErrorIs(t, err, ErrUnauthenticatedCommand)
	}
}

// requireRefusedWithReason asserts sc is refused synchronously with a
// LockedRefusal carrying want, and nothing runs.
func (lh *lockedHarness) requireRefusedWithReason(t *testing.T, sc *cpTypes.SignedCommand, want string) {
	t.Helper()
	err := lh.refuseAndAssertInert(t, sc)
	var r *LockedRefusal
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	require.True(t, errors.As(err, &r), "expected a LockedRefusal, got %v", err)
	assert.Equal(t, want, r.Reason)
}

// refuseAndAssertInert handles sc, asserts nothing ran and returns the handler error.
func (lh *lockedHarness) refuseAndAssertInert(t *testing.T, sc *cpTypes.SignedCommand) error {
	t.Helper()
	err := lh.handle(sc)
	lh.h.Wait()
	assert.Empty(t, lh.ctrl.callList(), "nothing may run")
	assert.Empty(t, lh.dialer.dialCalls(), "no terminal may open")
	assert.Nil(t, firstEventOfType(lh.events(), cpTypes.EventScriptCompleted), "no script may run")
	return err
}

func (lh *lockedHarness) allKinds(t *testing.T, prefix string) []*cpTypes.SignedCommand {
	return []*cpTypes.SignedCommand{lh.scriptCmd(t, prefix+"-s"), lh.actionCmd(t, prefix+"-a"), lh.terminalCmd(t, prefix+"-t")}
}

func TestLocked_RunsScriptActionAndTerminal(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})

	require.NoError(t, lh.handle(lh.scriptCmd(t, "ok-s")))
	require.NoError(t, lh.handle(lh.actionCmd(t, "ok-a")))
	require.NoError(t, lh.handle(lh.terminalCmd(t, "ok-t")))
	lh.h.Wait()

	require.NotNil(t, firstEventOfType(lh.events(), cpTypes.EventScriptCompleted), "script result event")
	assert.Equal(t, []string{"start:nginx"}, lh.ctrl.callList())
	require.Eventually(t, func() bool { return len(lh.dialer.dialCalls()) == 1 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, "", lh.rs.last(), "an accepted action clears the reason")
}

func TestLocked_PlantedTrustRefusedForAllKinds(t *testing.T) {
	baked := newLockedFx(t, false)
	planted := newLockedFx(t, false)
	lh := newLockedHarness(t, baked, harnessOpts{})
	// Everything below is signed under the planted root: outer signature, envelope
	// operator certificate and server certificate.
	plantedLH := &lockedHarness{fx: planted, trust: lh.trust, h: lh.h, rs: lh.rs, ctrl: lh.ctrl, dialer: lh.dialer, events: lh.events}
	for _, sc := range plantedLH.allKinds(t, "planted") {
		lh.requireRefusedWithReason(t, sc, cpTypes.ReasonCodeLockedRootMismatch)
	}
	assert.Equal(t, cpTypes.ReasonCodeLockedRootMismatch, lh.rs.last())
	assert.EqualValues(t, 3, lh.trust.RefusalCount(cpTypes.ReasonCodeLockedRootMismatch))
}

func TestLocked_OperatorCertOrManifestFromAnotherRootRefused(t *testing.T) {
	fx := newLockedFx(t, false)
	other := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})

	// Valid controller signature and chain, but the operator certificate chains
	// to a root that is not the baked one.
	foreign := &lockedHarness{fx: &lockedFx{operator: other.operator}, ctrl: lh.ctrl}
	content := []byte(echoScriptBody("x"))
	params := sigTestOperatorEnvelopeParams(t, foreign.fx.operator.PrivateKeyPEM, string(foreign.fx.operator.CertificatePEM), content, platformShell(), lockedStewardID)
	lh.requireRefused(t, fx.sign(t, lockedCmd("foreign-op", cpTypes.CommandExecuteScript, params)))

	actionContent := testActionContent(t, operatorpayload.Action{Verb: "service.start", TargetKind: "service", TargetName: "nginx"})
	ap := signedActionParams(t, other.operator, actionContent, []string{lockedStewardID}, sigTestNonce(t), time.Now().Add(time.Minute))
	ap["verb"], ap["target"], ap["parameters"] = "service.start", map[string]interface{}{"kind": "service", "name": "nginx"}, map[string]string{}
	lh.requireRefused(t, fx.sign(t, lockedCmd("foreign-act", cpTypes.CommandStewardAction, ap)))

	// A WebAuthn manifest signed under another root.
	priv, pub := webauthntest.NewKey(t)
	credID := []byte("cred-1")
	manifest := sigTestSignManifest(t, other.signing, []authorizedWebAuthnCredential{{
		Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pub, RootScope: true, Grants: []string{operatorPayloadSignGrant},
	}})
	wp := sigTestWebAuthnAssertionParams(t, priv, credID, manifest, content, platformShell(), []string{lockedStewardID}, sigTestNonce(t), time.Now().Add(time.Minute))
	lh.requireRefused(t, fx.sign(t, lockedCmd("foreign-wa", cpTypes.CommandExecuteScript, wp)))
}

func TestLocked_WebAuthnManifestUnderBakedRootAccepted(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})
	priv, pub := webauthntest.NewKey(t)
	credID := []byte("cred-1")
	manifest := sigTestSignManifest(t, fx.signing, []authorizedWebAuthnCredential{{
		Kind: authorizedWebAuthnCredentialKind, CredentialID: credID, PublicKey: pub, RootScope: true, Grants: []string{operatorPayloadSignGrant},
	}})
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifest, []byte(echoScriptBody("wa")), platformShell(), []string{lockedStewardID}, sigTestNonce(t), time.Now().Add(time.Minute))
	require.NoError(t, lh.handle(fx.sign(t, lockedCmd("wa-ok", cpTypes.CommandExecuteScript, params))))
	lh.h.Wait()
	require.NotNil(t, firstEventOfType(lh.events(), cpTypes.EventScriptCompleted))
}

func TestLocked_ChainRootRules(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})
	planted := newLockedFx(t, false)

	// A planted, self-signed root with a non-baked fingerprint, otherwise valid.
	sc := planted.sign(t, lh.scriptCmd(t, "pl-1"))
	lh.requireRefused(t, sc)

	// The baked root is present but not last.
	sc = lh.scriptCmd(t, "pl-2")
	sc.SignerChainPEM = append(append(append([]byte{}, fx.signing.CertificatePEM...), fx.rootPEM...), planted.rootPEM...)
	lh.requireRefusedWithReason(t, sc, cpTypes.ReasonCodeLockedRootMismatch)

	// Missing chain, leaf-only chain.
	sc = lh.scriptCmd(t, "pl-3")
	sc.SignerChainPEM = nil
	lh.requireRefused(t, sc)
	sc = lh.scriptCmd(t, "pl-4")
	sc.SignerChainPEM = fx.signing.CertificatePEM
	lh.requireRefused(t, sc)
}

func TestLocked_RotatedIntermediateVerifies(t *testing.T) {
	fx := newLockedFx(t, true)
	lh := newLockedHarness(t, fx, harnessOpts{})
	require.NoError(t, lh.handle(lh.scriptCmd(t, "rot-s")))
	require.NoError(t, lh.handle(lh.actionCmd(t, "rot-a")))
	require.NoError(t, lh.handle(lh.terminalCmd(t, "rot-t")))
	lh.h.Wait()
	require.NotNil(t, firstEventOfType(lh.events(), cpTypes.EventScriptCompleted))
	assert.Equal(t, []string{"start:nginx"}, lh.ctrl.callList())
}

func TestLocked_NoEnvelopeNonAllowedTypesAndLibraryScripts(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})

	// Allowed types, valid controller signature, no operator envelope.
	for i, typ := range []cpTypes.CommandType{cpTypes.CommandExecuteScript, cpTypes.CommandStewardAction, cpTypes.CommandOpenTerminal} {
		params := map[string]interface{}{"script_content": "ZWNobyBoaQ==", "shell": platformShell(), "session_id": "s", "verb": "service.start"}
		lh.requireRefused(t, fx.sign(t, lockedCmd("noenv-"+string(rune('a'+i)), typ, params)))
	}
	assert.EqualValues(t, 3, lh.trust.RefusalCount("no_envelope"))

	// One of each non-allowed type, validly controller-signed.
	for _, typ := range []cpTypes.CommandType{
		cpTypes.CommandSyncConfig, cpTypes.CommandSyncDNA, cpTypes.CommandReconnect, cpTypes.CommandPushSigningCert,
		cpTypes.CommandPushStewardBinary, cpTypes.CommandObserveModules, cpTypes.CommandRelayResponse,
	} {
		lh.requireRefused(t, fx.sign(t, lockedCmd("na-"+string(typ), typ, map[string]interface{}{"execution_id": "x"})))
		assert.EqualValues(t, 1, lh.trust.RefusalCount("type_not_allowed:"+string(typ)))
	}

	// A library script and a required_api_scope, even on a valid inline envelope.
	sc := lh.scriptCmd(t, "lib-1")
	sc.Command.Params["script_id"] = "lib-script"
	lh.requireRefused(t, fx.sign(t, sc))
	sc = lh.scriptCmd(t, "lib-2")
	sc.Command.Params["required_api_scope"] = []string{"read"}
	lh.requireRefused(t, fx.sign(t, sc))
	assert.EqualValues(t, 2, lh.trust.RefusalCount("library_script"))
}

func TestLocked_ScriptIDChangedInTransitRefused(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})
	sc := lh.scriptCmd(t, "tamper-1")
	// The proxy edits script_id after the controller signed: the outer signature
	// breaks; and even if re-signed the library selector is refused.
	sc.Command.Params["script_id"] = "lib"
	lh.requireRefused(t, sc)
}

func TestLocked_RevocationRules(t *testing.T) {
	fx := newLockedFx(t, false)
	opSerial := mustCert(t, fx.operator.CertificatePEM).SerialNumber.String()

	t.Run("revoked operator certificate", func(t *testing.T) {
		lh := newLockedHarness(t, fx, harnessOpts{revoked: []string{opSerial}})
		for _, sc := range lh.allKinds(t, "rev") {
			lh.requireRefused(t, sc)
		}
	})
	t.Run("no manifest yet", func(t *testing.T) {
		lh := newLockedHarness(t, fx, harnessOpts{skipManifest: true})
		lh.requireRefusedWithReason(t, lh.scriptCmd(t, "nom"), cpTypes.ReasonCodeLockedRevocationStale)
		assert.Equal(t, cpTypes.ReasonCodeLockedRevocationStale, lh.rs.last())
	})
	t.Run("manifest older than twice the interval", func(t *testing.T) {
		lh := newLockedHarness(t, fx, harnessOpts{manifestIssued: time.Now().Add(-3 * time.Minute)})
		for _, sc := range lh.allKinds(t, "old") {
			lh.requireRefused(t, sc)
		}
		assert.Equal(t, cpTypes.ReasonCodeLockedRevocationStale, lh.rs.last())
	})
	t.Run("manifest just inside twice the interval", func(t *testing.T) {
		lh := newLockedHarness(t, fx, harnessOpts{manifestIssued: time.Now().Add(-110 * time.Second)})
		require.NoError(t, lh.handle(lh.actionCmd(t, "edge")))
		lh.h.Wait()
	})
	t.Run("refresh before refusing", func(t *testing.T) {
		var lh *lockedHarness
		lh = newLockedHarness(t, fx, harnessOpts{skipManifest: true, refresh: func(context.Context) error {
			return lh.trust.Revocation().VerifyManifest(fx.manifest(t, time.Now().UTC().Truncate(time.Second)), stewardtypes.ModuleTrustModeStrict)
		}})
		require.NoError(t, lh.handle(lh.actionCmd(t, "refreshed")))
		lh.h.Wait()
		assert.Equal(t, []string{"start:nginx"}, lh.ctrl.callList())
	})
}

func TestLocked_ForcedStrictIgnoresModuleTrustMode(t *testing.T) {
	fx := newLockedFx(t, false)
	other := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{skipManifest: true})
	roots, err := cert.CertPoolFromPEM(fx.rootPEM)
	require.NoError(t, err)
	lh.trust.Revocation().SetTrust(roots, nil)
	forged := signManifestWith(t, other.signing, time.Now().UTC().Truncate(time.Second), nil)
	for _, mode := range []stewardtypes.ModuleTrustMode{
		stewardtypes.ModuleTrustModeController, stewardtypes.ModuleTrustModeBypass, stewardtypes.ModuleTrustModeStrict,
	} {
		assert.Error(t, lh.trust.Revocation().VerifyManifest(forged, mode), "mode %q must not weaken the check", mode)
	}
	_, ok := lh.trust.Revocation().NewestIssuedAt()
	assert.False(t, ok)
	lh.requireRefused(t, lh.actionCmd(t, "forged"))
}

func TestLocked_ReplayRules(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})

	first := lh.actionCmd(t, "rp-1")
	require.NoError(t, lh.handle(first))
	lh.h.Wait()

	// Same outer command ID.
	err := lh.handle(first)
	assert.ErrorIs(t, err, ErrCommandDuplicate)

	// Same envelope (nonce) under a new outer ID and signature.
	again := lockedCmd("rp-2", cpTypes.CommandStewardAction, first.Command.Params)
	require.NoError(t, lh.handle(fx.sign(t, again)))
	lh.h.Wait()
	assert.Len(t, lh.ctrl.callList(), 1, "a re-sent envelope must not run twice")

	// Expired envelope, and an envelope whose signed targets omit this steward.
	content := testActionContent(t, operatorpayload.Action{Verb: "service.start", TargetKind: "service", TargetName: "nginx"})
	build := func(id string, targets []string, exp time.Time) *cpTypes.SignedCommand {
		p := signedActionParams(t, fx.operator, content, targets, sigTestNonce(t), exp)
		p["verb"], p["target"], p["parameters"] = "service.start", map[string]interface{}{"kind": "service", "name": "nginx"}, map[string]string{}
		return fx.sign(t, lockedCmd(id, cpTypes.CommandStewardAction, p))
	}
	n := len(lh.ctrl.callList())
	lh.requireRefusedKeepCalls(t, build("rp-exp", []string{lockedStewardID}, time.Now().Add(-6*time.Minute)), n)
	lh.requireRefusedKeepCalls(t, build("rp-tgt", []string{"other-steward"}, time.Now().Add(time.Minute)), n)

	// A restart empties the in-memory caches; an envelope older than the maximum
	// lifetime is still refused, and so is one valid for longer than the maximum.
	restarted := newLockedHarness(t, fx, harnessOpts{})
	restarted.requireRefused(t, build("rp-old", []string{lockedStewardID}, time.Now().Add(-operatorpayload.ActionEnvelopeMaxTTL-time.Minute)))
	restarted.requireRefused(t, build("rp-long", []string{lockedStewardID}, time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL+time.Hour)))
}

func (lh *lockedHarness) requireRefusedKeepCalls(t *testing.T, sc *cpTypes.SignedCommand, calls int) {
	t.Helper()
	_ = lh.handle(sc)
	lh.h.Wait()
	assert.Len(t, lh.ctrl.callList(), calls, "the refused action must not run")
}

func TestLocked_HandlerWithNeitherVerifierNorLockedRefusesEverything(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})
	plain, err := New(&Config{StewardID: lockedStewardID, OnStatus: noopStatus, Logger: newTestLogger(t), ControllerCARoots: inlineTestCARoots(t), RevocationVerifier: inlineTestRevocationVerifier(t)})
	require.NoError(t, err)
	plain.RegisterExecuteScriptHandler()
	plain.RegisterOpenTerminalHandler(newRecordingDialer())
	for _, sc := range lh.allKinds(t, "plain") {
		err := plain.HandleLockedCommand(context.Background(), sc, fx.link())
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUnauthenticatedCommand)
	}
	plain.Wait()

	// And a locked handler refuses the normal entry point.
	for _, sc := range lh.allKinds(t, "locked-normal") {
		assert.ErrorIs(t, lh.h.HandleCommand(context.Background(), sc), ErrUnauthenticatedCommand)
	}
	assert.Empty(t, lh.ctrl.callList())
}

func TestLocked_BakedRootStatesRefuseEverythingWithDistinctReasons(t *testing.T) {
	fx := newLockedFx(t, false)
	cases := map[string]harnessOpts{
		cpTypes.ReasonCodeLockedNoBakedRoot:        {bakedReason: func() string { return cpTypes.ReasonCodeLockedNoBakedRoot }, matcher: func(*x509.Certificate) bool { return false }},
		cpTypes.ReasonCodeLockedBakedRootMalformed: {bakedReason: func() string { return cpTypes.ReasonCodeLockedBakedRootMalformed }, matcher: func(*x509.Certificate) bool { return false }},
		cpTypes.ReasonCodeLockedRootMismatch:       {matcher: bakedFor(newLockedFx(t, false).root)},
	}
	for want, o := range cases {
		t.Run(want, func(t *testing.T) {
			lh := newLockedHarness(t, fx, o)
			lh.trust.ReportBakedState()
			for _, sc := range lh.allKinds(t, "baked") {
				lh.requireRefused(t, sc)
			}
			assert.Equal(t, want, lh.rs.last())
		})
	}
}

func TestLocked_LinkNotAnchoredDropsCommand(t *testing.T) {
	fx := newLockedFx(t, false)
	proxy := newLockedFx(t, false) // a CA that is not baked
	lh := newLockedHarness(t, fx, harnessOpts{})
	proxyLink := func() []*x509.Certificate { return []*x509.Certificate{proxy.server} }
	for _, sc := range lh.allKinds(t, "relay") {
		err := lh.h.HandleLockedCommand(context.Background(), sc, proxyLink)
		require.Error(t, err)
		var r *LockedRefusal
		require.True(t, errors.As(err, &r))
		assert.Equal(t, cpTypes.ReasonCodeLockedLinkNotAnchored, r.Reason)
	}
	lh.h.Wait()
	assert.Equal(t, cpTypes.ReasonCodeLockedLinkNotAnchored, lh.rs.last())
	assert.Empty(t, lh.ctrl.callList())
	assert.Empty(t, lh.dialer.dialCalls())

	// No peer certificates at all is not anchored either.
	err := lh.h.HandleLockedCommand(context.Background(), lh.actionCmd(t, "nopeer"), func() []*x509.Certificate { return nil })
	assert.Error(t, err)
}

func TestLocked_ConfigCanOnlyRestrict(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{disableTerminal: true})
	err := lh.handle(lh.terminalCmd(t, "noterm"))
	require.NoError(t, err) // dispatched; the handler refuses
	lh.h.Wait()
	assert.Empty(t, lh.dialer.dialCalls())
	assert.NotNil(t, firstEventOfType(lh.events(), cpTypes.EventCommandFailed))

	// RequireSignedAdhoc: false in Config still requires a signed script.
	trust, terr := NewLockedTrust(LockedTrustConfig{MatchesBakedRoot: bakedFor(fx.root), RevocationRefreshInterval: time.Minute})
	require.NoError(t, terr)
	h, terr := New(&Config{StewardID: lockedStewardID, OnStatus: noopStatus, Logger: newTestLogger(t), Locked: trust, RequireSignedAdhoc: false})
	require.NoError(t, terr)
	assert.True(t, h.requireSignedAdhoc)
	h.RegisterExecuteScriptHandler()
	unsigned := fx.sign(t, lockedCmd("unsigned", cpTypes.CommandExecuteScript, map[string]interface{}{
		"script_content": "ZWNobyBoaQ==", "shell": platformShell(),
	}))
	assert.Error(t, h.HandleLockedCommand(context.Background(), unsigned, fx.link()))
	h.Wait()

	// A locked handler takes no verifier, store or CA of its own.
	_, terr = New(&Config{StewardID: lockedStewardID, OnStatus: noopStatus, Logger: newTestLogger(t), Locked: trust, ControllerCARoots: inlineTestCARoots(t), RevocationVerifier: inlineTestRevocationVerifier(t)})
	assert.Error(t, terr)
	mv, terr := signature.NewMultiVerifier([]*x509.Certificate{fx.root})
	require.NoError(t, terr)
	_, terr = New(&Config{StewardID: lockedStewardID, OnStatus: noopStatus, Logger: newTestLogger(t), Locked: trust, Verifier: mv})
	assert.Error(t, terr)
}

func TestLocked_StaleOrUnsignedOuterCommandRefused(t *testing.T) {
	fx := newLockedFx(t, false)
	lh := newLockedHarness(t, fx, harnessOpts{})

	sc := lh.actionCmd(t, "unsig")
	sc.Signature = nil
	lh.requireRefused(t, sc)

	sc = lh.actionCmd(t, "tampered")
	sc.Command.Params["execution_id"] = "changed-in-transit"
	lh.requireRefused(t, sc)

	sc = lh.actionCmd(t, "wrongsteward")
	sc.Command.StewardID = "someone-else"
	err := lh.handle(fx.sign(t, sc))
	assert.ErrorIs(t, err, ErrWrongSteward)

	sc = lh.actionCmd(t, "stale")
	sc.Command.Timestamp = time.Now().Add(-time.Hour)
	assert.ErrorIs(t, lh.handle(fx.sign(t, sc)), ErrCommandStale)

	// A stamped command signed over the v1 payload is refused.
	sc = lh.actionCmd(t, "v1term")
	sc.Command.Term = 7
	sc.Command.SigningPayloadVersion = 0
	raw := cpTypes.InterfaceParamsToStringMap(sc.Command.Params)
	data, berr := cpTypes.CommandSigningBytesVersion(&sc.Command, raw, cpTypes.SigningPayloadV1)
	require.NoError(t, berr)
	sc.Signature, berr = fx.signer.Sign(data)
	require.NoError(t, berr)
	lh.requireRefused(t, sc)
}

func TestVerifyLockedSigner(t *testing.T) {
	fx := newLockedFx(t, true)
	planted := newLockedFx(t, false)
	SetBakedRootMatcher(bakedFor(fx.root))
	t.Cleanup(func() { SetBakedRootMatcher(nil) })

	payload := []byte("repair-request-bytes")
	sig, err := fx.signer.Sign(payload)
	require.NoError(t, err)
	rawSig := decodeSig(t, sig.Signature)

	require.NoError(t, VerifyLockedSigner(fx.chainPEM, rawSig, payload))
	assert.Error(t, VerifyLockedSigner(fx.chainPEM, rawSig, []byte("other bytes")))
	assert.Error(t, VerifyLockedSigner(planted.chainPEM, rawSig, payload), "planted chain")

	psig, err := planted.signer.Sign(payload)
	require.NoError(t, err)
	assert.Error(t, VerifyLockedSigner(planted.chainPEM, decodeSig(t, psig.Signature), payload))

	SetBakedRootMatcher(nil)
	assert.Error(t, VerifyLockedSigner(fx.chainPEM, rawSig, payload), "no matcher registered fails closed")
}

func mustCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	c, err := cert.ParseCertificateFromPEM(certPEM)
	require.NoError(t, err)
	return c
}

func decodeSig(t *testing.T, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	return raw
}
