// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/steward/operatorroster"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// Locked-trust command handling.
//
// A steward latched into report-only mode still runs three kinds of
// operator-signed action: an inline script, a structured steward action and a
// remote terminal. It never verifies them with trust material from its data
// folder. The only anchor is a root certificate whose SHA-256 fingerprint is
// baked into the binary. The root arrives as the last certificate of the signer
// chain the controller attaches to each command; it is accepted only after the
// baked-fingerprint check, never by position alone. Certificates and keys cached
// in the data folder (the persisted CA, the signing certificates) are never
// consulted.
//
// The LockedTrust is a separate construction from the normal verifier: a handler
// built with Config.Locked has no signature.Verifier, no store and no fallback to
// the on-disk verifier. A missing chain, root or manifest means refuse.
//
// Unsigned parameters. The controller's outer signature is verified through the
// chain, and the operator envelope is verified on top of it. The parameters
// outside the operator envelope are:
//   - timeout_seconds: clamped by commandTimeout; it bounds a run, it grants nothing.
//   - execution_id: a correlation label echoed on result events.
//   - session_id, cols, rows: terminal bookkeeping; the terminal dialer is
//     controller-side, so these choose no destination, shell or credential.
//   - script_id and required_api_scope: library-script selectors. Library scripts
//     are refused while locked, so a non-empty script_id or required_api_scope
//     is refused, not dropped and run.
//
// Residual replay window, stated plainly: the replay cache and the envelope nonce
// cache are in memory and reset on restart. After a restart a captured envelope
// can be replayed until it expires; the envelope signature chain, its target
// binding (this steward must be a signed target), its nonce and its expiry
// (at most ActionEnvelopeMaxTTL, 5 minutes) bound that window.

// Component-agnostic refusal text. Detail never carries certificate bytes.
var (
	// ErrLockedRefused wraps every refusal made by the locked-trust rules.
	ErrLockedRefused = errors.New("locked steward refused the command")

	// errNoBakedRootMatcher is returned by VerifyLockedSigner before a baked-root
	// matcher is registered.
	errNoBakedRootMatcher = errors.New("no baked root matcher registered")
)

// LockedRefusal is the error HandleLockedCommand returns for a refusal. Reason is
// the heartbeat reason code to report ("" when the refusal sets none). It wraps
// ErrUnauthenticatedCommand, so the receive path reports it as unauthenticated.
type LockedRefusal struct {
	Reason string
	Detail string
}

func (e *LockedRefusal) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%v: %s (%s)", ErrLockedRefused, e.Detail, e.Reason)
	}
	return fmt.Sprintf("%v: %s", ErrLockedRefused, e.Detail)
}

// Is makes a LockedRefusal match both sentinels.
func (e *LockedRefusal) Is(target error) bool {
	return target == ErrUnauthenticatedCommand || target == ErrLockedRefused
}

func refuse(reason, detail string) error { return &LockedRefusal{Reason: reason, Detail: detail} }

// Bounds on a presented signer chain.
const (
	maxLockedChainCerts = 8
	maxLockedChainBytes = 64 << 10
)

// lockedAllowedTypes is the whole set of command types a locked steward accepts.
var lockedAllowedTypes = map[cpTypes.CommandType]bool{
	cpTypes.CommandExecuteScript: true,
	cpTypes.CommandStewardAction: true,
	cpTypes.CommandOpenTerminal:  true,
}

// lockedExecuteScriptKeys are the only params a locked inline execute_script may
// carry: the script, the unsigned bookkeeping above and the operator envelope.
var lockedExecuteScriptKeys = map[string]bool{
	"script_content": true, "shell": true, "execution_id": true, "execution_context": true,
	// environment is sent by the controller for prepared runs; the steward never
	// reads it, so it carries no authority here.
	"environment": true, "timeout_seconds": true, "targets": true, "nonce": true, "expires_at": true,
	"signature_algorithm": true, "signature_value": true, "signature_public_key": true,
	"webauthn_authenticator_data": true, "webauthn_client_data_json": true,
	"webauthn_signature": true, "webauthn_credential_id": true, "webauthn_manifest": true,
}

// lockedOpenTerminalKeys are the only params a locked open_terminal may carry.
var lockedOpenTerminalKeys = map[string]bool{
	"session_id": true, "shell": true, "cols": true, "rows": true,
	"targets": true, "nonce": true, "expires_at": true,
	"signature_algorithm": true, "signature_value": true, "signature_public_key": true,
	"webauthn_authenticator_data": true, "webauthn_client_data_json": true,
	"webauthn_signature": true, "webauthn_credential_id": true, "webauthn_manifest": true,
}

// LockedTrustConfig builds a LockedTrust.
type LockedTrustConfig struct {
	// MatchesBakedRoot reports whether a certificate is a self-signed CA whose
	// fingerprint is in the binary's baked list. It must fail closed.
	MatchesBakedRoot func(*x509.Certificate) bool

	// BakedRootReason returns "" when the baked list is usable, else the reason
	// code (ReasonCodeLockedNoBakedRoot or ReasonCodeLockedBakedRootMalformed).
	// While it is non-empty every command is refused.
	BakedRootReason func() string

	// RevocationRefreshInterval is the manifest refresh cadence. The newest
	// verified manifest must be no older than twice this value.
	RevocationRefreshInterval time.Duration

	// OnReason receives the reason code a refusal sets, or "" to clear it after an
	// action was accepted. It may be nil.
	OnReason func(code string)

	// RefreshRevocation, when set, fetches and verifies a manifest now. It is
	// tried once before an action is refused as stale. Its result is judged only
	// by the revocation verifier's own freshness.
	RefreshRevocation func(ctx context.Context) error
}

// LockedTrust is the trust a locked steward verifies operator actions with. It
// holds no data-folder material.
type LockedTrust struct {
	cfg        LockedTrustConfig
	revocation *operatorroster.RevocationVerifier

	mu       sync.Mutex
	refusals map[string]int64
}

// NewLockedTrust validates cfg and builds a LockedTrust. The revocation verifier
// it owns is forced strict, so no module trust mode weakens it.
func NewLockedTrust(cfg LockedTrustConfig) (*LockedTrust, error) {
	if cfg.MatchesBakedRoot == nil {
		return nil, errors.New("locked trust requires a baked-root matcher")
	}
	if cfg.RevocationRefreshInterval <= 0 {
		return nil, errors.New("locked trust requires a revocation refresh interval")
	}
	return &LockedTrust{
		cfg:        cfg,
		revocation: operatorroster.NewRevocationVerifier(nil, operatorroster.WithForcedStrict()),
		refusals:   make(map[string]int64),
	}, nil
}

// applyLocked turns cfg into a locked-handler configuration. A locked handler
// takes no verifier, store, controller CA or revocation verifier of its own:
// config can only restrict, so inline commands always need a signature and the
// signing policy is empty.
func (cfg *Config) applyLocked() error {
	if cfg.Locked == nil {
		return nil
	}
	if cfg.Verifier != nil || cfg.Store != nil || cfg.ControllerCARoots != nil || cfg.RevocationVerifier != nil {
		return fmt.Errorf("locked handler takes no verifier, store, controller CA or revocation verifier")
	}
	cfg.RequireSignedAdhoc = true
	cfg.RevocationVerifier = cfg.Locked.revocation
	cfg.SigningConfig = script.ModuleSigningConfig{}
	return nil
}

// Revocation returns the forced-strict revocation verifier. The caller feeds it
// manifests (FetchAndVerify); the roots it verifies against are set from each
// accepted command chain.
func (t *LockedTrust) Revocation() *operatorroster.RevocationVerifier { return t.revocation }

// RevocationRefreshInterval returns the manifest refresh cadence.
func (t *LockedTrust) RevocationRefreshInterval() time.Duration {
	return t.cfg.RevocationRefreshInterval
}

// BakedRootReason returns the reason the baked list is unusable, or "".
func (t *LockedTrust) BakedRootReason() string {
	if t.cfg.BakedRootReason == nil {
		return ""
	}
	return t.cfg.BakedRootReason()
}

// ReportBakedState reports the baked-list reason through OnReason now, so the
// next heartbeat carries it before any command arrives.
func (t *LockedTrust) ReportBakedState() {
	if r := t.BakedRootReason(); r != "" && t.cfg.OnReason != nil {
		t.cfg.OnReason(r)
	}
}

func (t *LockedTrust) count(key string) {
	t.mu.Lock()
	t.refusals[key]++
	t.mu.Unlock()
}

// RefusalCount returns how many commands were refused under key. Keys are the
// reason codes, "type_not_allowed:<command type>", "no_envelope", "library_script",
// "stale_or_invalid".
func (t *LockedTrust) RefusalCount(key string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.refusals[key]
}

// lockedChain is a signer chain whose root matched a baked fingerprint.
type lockedChain struct {
	leaf          *x509.Certificate
	root          *x509.Certificate
	roots         *x509.CertPool // the root only
	intermediates *x509.CertPool // nil when the chain has none
}

// splitChainPEM parses the CERTIFICATE blocks of a PEM chain. The first block is
// the leaf; the remaining blocks (intermediates, then the root) are returned in
// order as above.
func splitChainPEM(chainPEM []byte) (leaf *x509.Certificate, above []*x509.Certificate, err error) {
	if len(chainPEM) == 0 {
		return nil, nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "command carries no signer chain")
	}
	if len(chainPEM) > maxLockedChainBytes {
		return nil, nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer chain is too large")
	}
	count := 0
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return leaf, above, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer chain holds an unparseable certificate")
		}
		if count++; count > maxLockedChainCerts {
			return nil, nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer chain is too long")
		}
		if leaf == nil {
			leaf = c
			continue
		}
		above = append(above, c)
	}
}

// certsPool builds a verification pool from certificates through pkg/cert.
func certsPool(certs ...*x509.Certificate) (*x509.CertPool, error) {
	var raw []byte
	for _, c := range certs {
		raw = append(raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return cert.CertPoolFromPEM(raw)
}

// parseLockedChain splits a PEM chain (leaf first, root last) and accepts it only
// when the last certificate is a self-signed CA whose fingerprint is baked.
// A chain whose baked root is not in last position is refused.
func parseLockedChain(chainPEM []byte, matches func(*x509.Certificate) bool) (*lockedChain, error) {
	leaf, above, err := splitChainPEM(chainPEM)
	if err != nil {
		return nil, err
	}
	if leaf == nil || len(above) == 0 {
		return nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer chain must hold a leaf and a root")
	}
	root := above[len(above)-1]
	if !matches(root) {
		return nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer chain root is not a baked root")
	}
	lc := &lockedChain{leaf: leaf, root: root}
	if lc.roots, err = certsPool(root); err != nil {
		return nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer chain root is unusable")
	}
	if len(above) > 1 {
		if lc.intermediates, err = certsPool(above[:len(above)-1]...); err != nil {
			return nil, refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer chain intermediates are unusable")
		}
	}
	return lc, nil
}

// verifyLeaf checks the chain's leaf chains to the baked root with the CodeSigning
// usage, the same checks verifyPushedSigningCertChain applies to a pushed
// signing certificate.
func (lc *lockedChain) verifyLeaf(now time.Time) error {
	if _, err := lc.leaf.Verify(x509.VerifyOptions{
		Roots:         lc.roots,
		Intermediates: lc.intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return refuse(cpTypes.ReasonCodeLockedRootMismatch, "signer certificate does not chain to the baked root")
	}
	return nil
}

// linkAnchored reports whether the server certificate chain of the stream the
// command arrived on chains, with its intermediates and ServerAuth usage, to the
// root this command's chain selected.
func (lc *lockedChain) linkAnchored(peer []*x509.Certificate, now time.Time) bool {
	if len(peer) == 0 {
		return false
	}
	var inter *x509.CertPool
	if len(peer) > 1 {
		inter, _ = certsPool(peer[1:]...)
	}
	_, err := peer[0].Verify(x509.VerifyOptions{
		Roots:         lc.roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

var bakedRootMatcher atomic.Pointer[func(*x509.Certificate) bool]

// SetBakedRootMatcher registers the baked-root check VerifyLockedSigner uses. The
// steward binary registers its own check at start-up; the commands package never
// reads the baked list itself.
func SetBakedRootMatcher(fn func(*x509.Certificate) bool) {
	if fn == nil {
		bakedRootMatcher.Store(nil)
		return
	}
	bakedRootMatcher.Store(&fn)
}

// VerifyLockedSigner checks that signature is a valid signature of signedBytes by
// the leaf of chainPEM, and that the chain ends in a baked root and the leaf
// chains to it with the CodeSigning usage. It reads nothing from the data folder.
// The repair path calls it for the repair signal on a baked host.
func VerifyLockedSigner(chainPEM, signature, signedBytes []byte) error {
	fn := bakedRootMatcher.Load()
	if fn == nil {
		return errNoBakedRootMatcher
	}
	lc, err := parseLockedChain(chainPEM, *fn)
	if err != nil {
		return err
	}
	if err := lc.verifyLeaf(time.Now()); err != nil {
		return err
	}
	return lc.verifyRawSignature(signature, signedBytes)
}

// verifyRawSignature verifies a raw signature (ECDSA ASN.1 or RSA PKCS#1 v1.5 over
// SHA-256) of data by the chain leaf's key.
func (lc *lockedChain) verifyRawSignature(sig, data []byte) error {
	var alg signature.Algorithm
	switch lc.leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		alg = signature.AlgorithmECDSASHA256
	case *rsa.PublicKey:
		alg = signature.AlgorithmRSASHA256
	default:
		return refuse("", "signer key type is unsupported")
	}
	return lc.verifySignature(&signature.ConfigSignature{Algorithm: alg, Signature: base64.StdEncoding.EncodeToString(sig)}, data)
}

func (lc *lockedChain) verifySignature(sig *signature.ConfigSignature, data []byte) error {
	v, err := signature.NewVerifierFromCertificate(lc.leaf)
	if err != nil {
		return refuse("", "signer certificate key is unusable")
	}
	if err := v.Verify(data, sig); err != nil {
		return refuse("", "command signature does not verify")
	}
	return nil
}

// lockedCommandTrust is the trust one command is verified with: the root its own
// chain selected. Envelope verification looks it up by command pointer.
type lockedCommandTrust struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

// operatorTrust returns the roots, intermediates and revocation verifier the
// operator envelope of cmd is verified with. A normal handler uses its configured
// roots. A locked handler uses only the trust bound to this command by
// HandleLockedCommand; with none bound it returns an error, never a default.
func (h *Handler) operatorTrust(cmd *cpTypes.Command) (roots, intermediates *x509.CertPool, rev *operatorroster.RevocationVerifier, err error) {
	if h.locked == nil {
		return h.controllerCARoots, nil, h.revocationVerifier, nil
	}
	v, ok := h.lockedCmds.Load(cmd)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%w: no locked trust bound to this command", ErrUnauthenticatedCommand)
	}
	ct := v.(*lockedCommandTrust)
	return ct.roots, ct.intermediates, h.locked.revocation, nil
}

// emptyPool reports whether p holds no certificates. A zero CertPool equals an
// empty pool from the standard library constructor.
func emptyPool(p *x509.CertPool) bool {
	return p == nil || p.Equal(new(x509.CertPool))
}

// lockedCall carries one command through the admission steps.
type lockedCall struct {
	ctx    context.Context
	signed *cpTypes.SignedCommand
	cmd    *cpTypes.Command
	peer   func() []*x509.Certificate
	lc     *lockedChain
}

// lockedStep checks one rule. On refusal it returns the key the refusal is
// counted under and the error.
type lockedStep func(*lockedCall) (string, error)

// HandleLockedCommand is the entry for a command received on a report-only link.
// peerChain returns the server certificate chain of the stream the command
// arrived on. Order is fixed:
//
//  1. the baked list must be usable;
//  2. the chain's root is selected by fingerprint;
//  3. the stream's server certificate must chain to that root, else the command
//     is dropped (link_not_anchored);
//  4. the command type must be on the allowlist;
//  5. the outer controller signature must verify through the chain;
//  6. steward ID, timestamp, replay and params size, then the unsigned-parameter
//     guards and the operator envelope requirement;
//  7. the revocation manifest must be fresh;
//  8. the operator envelope is verified under that root.
//
// A handler not built with Config.Locked refuses every command here.
func (h *Handler) HandleLockedCommand(ctx context.Context, signed *cpTypes.SignedCommand, peerChain func() []*x509.Certificate) error {
	if h.locked == nil {
		return refuse("", "handler is not a locked-trust handler")
	}
	if signed == nil {
		return h.lockedFail("no_command", refuse("", "no command"))
	}
	call := &lockedCall{ctx: ctx, signed: signed, cmd: &signed.Command, peer: peerChain}
	for _, step := range []lockedStep{
		h.stepBakedState, h.stepChain, h.stepLink, h.stepType, h.stepOuterSignature,
		h.stepIdentity, h.stepParams, h.stepEnvelopeTTL, h.stepRevocation,
	} {
		if key, err := step(call); err != nil {
			return h.lockedFail(key, err)
		}
	}
	return h.dispatchLocked(call)
}

// lockedFail counts and logs a refusal and reports its reason code.
func (h *Handler) lockedFail(key string, err error) error {
	t := h.locked
	t.count(key)
	var r *LockedRefusal
	if errors.As(err, &r) && r.Reason != "" && t.cfg.OnReason != nil {
		t.cfg.OnReason(r.Reason)
	}
	h.logger.Warn("Locked steward refused a command",
		"reason", logging.SanitizeLogValue(key),
		"detail", logging.SanitizeLogValue(err.Error()))
	return err
}

func (h *Handler) stepBakedState(*lockedCall) (string, error) {
	if reason := h.locked.BakedRootReason(); reason != "" {
		return reason, refuse(reason, "no usable baked controller root")
	}
	return "", nil
}

func (h *Handler) stepChain(c *lockedCall) (string, error) {
	chainPEM := c.signed.SignerChainPEM
	if len(chainPEM) == 0 {
		chainPEM = c.cmd.SignerChainPEM
	}
	lc, err := parseLockedChain(chainPEM, h.locked.cfg.MatchesBakedRoot)
	if err != nil {
		return cpTypes.ReasonCodeLockedRootMismatch, err
	}
	c.lc = lc
	return "", nil
}

func (h *Handler) stepLink(c *lockedCall) (string, error) {
	var peer []*x509.Certificate
	if c.peer != nil {
		peer = c.peer()
	}
	if !c.lc.linkAnchored(peer, time.Now()) {
		return cpTypes.ReasonCodeLockedLinkNotAnchored,
			refuse(cpTypes.ReasonCodeLockedLinkNotAnchored, "the link is not anchored to the command's baked root")
	}
	return "", nil
}

func (h *Handler) stepType(c *lockedCall) (string, error) {
	if !lockedAllowedTypes[c.cmd.Type] {
		return "type_not_allowed:" + string(c.cmd.Type), refuse("", "command type is not accepted while locked")
	}
	return "", nil
}

// stepOuterSignature verifies the controller's signature over the command
// through the chain's leaf.
func (h *Handler) stepOuterSignature(c *lockedCall) (string, error) {
	if err := c.lc.verifyLeaf(time.Now()); err != nil {
		return cpTypes.ReasonCodeLockedRootMismatch, err
	}
	cmd := c.cmd
	if c.signed.Signature == nil {
		return "unsigned", refuse("", "command carries no signature")
	}
	if cpTypes.CommandPayloadVersion(cmd) == cpTypes.SigningPayloadV1 && cmd.Term > 0 {
		return "unsigned", refuse("", "stamped command signed without term coverage")
	}
	rawParams := c.signed.RawParams
	if rawParams == nil {
		rawParams = cpTypes.InterfaceParamsToStringMap(cmd.Params)
	}
	data, err := cpTypes.CommandSigningBytesVersion(cmd, rawParams, cpTypes.CommandPayloadVersion(cmd))
	if err != nil {
		return "unsigned", refuse("", "command cannot be canonicalised")
	}
	if err := c.lc.verifySignature(c.signed.Signature, data); err != nil {
		return "unsigned", err
	}
	return "", nil
}

// stepIdentity applies the steward ID, timestamp window, params size and replay
// rules of HandleCommand.
func (h *Handler) stepIdentity(c *lockedCall) (string, error) {
	switch {
	case c.cmd.StewardID != h.stewardID:
		return "wrong_steward", ErrWrongSteward
	case time.Since(c.cmd.Timestamp) > h.replayWindow:
		return "stale_command", ErrCommandStale
	}
	if err := h.checkParamsSize(c.cmd); err != nil {
		return "params_too_large", err
	}
	if !h.replayCache.Add(c.cmd.ID) {
		return "duplicate_command", ErrCommandDuplicate
	}
	return "", nil
}

func (h *Handler) stepParams(c *lockedCall) (string, error) {
	if err := lockedParamGuards(c.cmd); err != nil {
		if errors.Is(err, errLibraryScript) {
			return "library_script", err
		}
		return "no_envelope", err
	}
	return "", nil
}

// stepEnvelopeTTL gives an inline script the action ceiling; steward actions and
// terminals apply their own in their handlers.
func (h *Handler) stepEnvelopeTTL(c *lockedCall) (string, error) {
	if c.cmd.Type != cpTypes.CommandExecuteScript {
		return "", nil
	}
	exp, err := time.Parse(time.RFC3339, stringParam(c.cmd, "expires_at"))
	if err == nil && exp.After(time.Now().Add(operatorpayload.ActionEnvelopeMaxTTL)) {
		return "envelope_ttl", fmt.Errorf("%w: envelope validity exceeds the maximum", ErrUnauthenticatedCommand)
	}
	return "", nil
}

// stepRevocation points the manifest verifier at this command's baked root and
// requires a fresh manifest verified against it.
func (h *Handler) stepRevocation(c *lockedCall) (string, error) {
	h.locked.revocation.SetTrust(c.lc.roots, c.lc.intermediates)
	if err := h.locked.requireFreshManifest(c.ctx); err != nil {
		return cpTypes.ReasonCodeLockedRevocationStale, err
	}
	return "", nil
}

// dispatchLocked binds the command's trust and runs it. Inline-script envelope
// verification runs before dispatch (as in HandleCommand); steward_action and
// open_terminal verify inside their handlers, with the trust bound here.
func (h *Handler) dispatchLocked(c *lockedCall) error {
	h.lockedCmds.Store(c.cmd, &lockedCommandTrust{roots: c.lc.roots, intermediates: c.lc.intermediates})
	if c.cmd.Type == cpTypes.CommandExecuteScript {
		if err := h.preflightScriptSignature(c.cmd); err != nil {
			h.lockedCmds.Delete(c.cmd)
			return h.lockedFail("stale_or_invalid", err)
		}
	}
	if h.locked.cfg.OnReason != nil {
		h.locked.cfg.OnReason("")
	}
	return h.dispatch(c.ctx, c.cmd)
}

var errLibraryScript = errors.New("library scripts are refused while locked")

// lockedParamGuards enforces the allowlisted param keys and requires an operator
// envelope. A script_id or non-empty required_api_scope is refused, not dropped.
func lockedParamGuards(cmd *cpTypes.Command) error {
	if err := refuseLibrarySelectors(cmd); err != nil {
		return err
	}
	if err := refuseUnknownParams(cmd); err != nil {
		return err
	}
	if !hasX509Proof(cmd) && !hasWebAuthnProof(cmd) {
		return fmt.Errorf("%w: a locked steward needs an operator envelope", ErrUnauthenticatedCommand)
	}
	return nil
}

func refuseLibrarySelectors(cmd *cpTypes.Command) error {
	if v, ok := cmd.Params["script_id"]; ok && fmt.Sprint(v) != "" {
		return fmt.Errorf("%w: %w", ErrUnauthenticatedCommand, errLibraryScript)
	}
	v, ok := cmd.Params["required_api_scope"]
	if ok && (len(extractStringSlice(v)) > 0 || (fmt.Sprint(v) != "" && fmt.Sprint(v) != "[]")) {
		return fmt.Errorf("%w: %w", ErrUnauthenticatedCommand, errLibraryScript)
	}
	return nil
}

// refuseUnknownParams refuses any param outside the kind's allowlist; the empty
// library selectors were checked above.
func refuseUnknownParams(cmd *cpTypes.Command) error {
	allowed := lockedOpenTerminalKeys
	switch cmd.Type {
	case cpTypes.CommandExecuteScript:
		allowed = lockedExecuteScriptKeys
	case cpTypes.CommandStewardAction:
		allowed = stewardActionParamKeys
	}
	for k := range cmd.Params {
		if k != "script_id" && k != "required_api_scope" && !allowed[k] {
			return fmt.Errorf("%w: unexpected param %q", ErrUnauthenticatedCommand, logging.SanitizeLogValue(k))
		}
	}
	return nil
}

func hasX509Proof(cmd *cpTypes.Command) bool {
	return stringParam(cmd, "signature_algorithm") != "" && stringParam(cmd, "signature_value") != "" &&
		stringParam(cmd, "signature_public_key") != ""
}

func hasWebAuthnProof(cmd *cpTypes.Command) bool {
	return stringParam(cmd, "webauthn_authenticator_data") != "" && stringParam(cmd, "webauthn_client_data_json") != "" &&
		stringParam(cmd, "webauthn_signature") != "" && stringParam(cmd, "webauthn_credential_id") != ""
}

func stringParam(cmd *cpTypes.Command, key string) string {
	s, _ := cmd.Params[key].(string)
	return s
}

// requireFreshManifest refuses unless a manifest verified against the baked root
// was issued within twice the refresh interval. It tries one refresh first.
func (t *LockedTrust) requireFreshManifest(ctx context.Context) error {
	if t.manifestFresh() {
		return nil
	}
	if t.cfg.RefreshRevocation != nil {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_ = t.cfg.RefreshRevocation(rctx)
		cancel()
		if t.manifestFresh() {
			return nil
		}
	}
	return refuse(cpTypes.ReasonCodeLockedRevocationStale, "no fresh revocation manifest verified against the baked root")
}

func (t *LockedTrust) manifestFresh() bool {
	issued, ok := t.revocation.NewestIssuedAt()
	return ok && time.Since(issued) <= 2*t.cfg.RevocationRefreshInterval
}
