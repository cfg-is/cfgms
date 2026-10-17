// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"crypto/x509"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// ---------------------------------------------------------------------------
// recordingDialer — real in-process TerminalDialer for tests (no mocks).
// ---------------------------------------------------------------------------

// recordingDialer implements TerminalDialer and records every Dial call for
// assertion. It blocks until the test signals it via allow or until the context
// is cancelled, simulating a long-lived bridge session without a real PTY.
type recordingDialer struct {
	mu      sync.Mutex
	calls   []dialCall
	callCh  chan dialCall // non-nil allows callers to receive dial events
	allowCh chan struct{} // closed by allowReturn to unblock Dial
	dialErr error         // error Dial returns after unblocking
}

type dialCall struct {
	SessionID string
	Shell     string
	Cols      int
	Rows      int
}

// newRecordingDialer returns a recordingDialer whose Dial returns immediately
// with nil.
func newRecordingDialer() *recordingDialer {
	ch := make(chan struct{})
	close(ch) // Dial returns immediately unless blocked
	return &recordingDialer{allowCh: ch}
}

// newBlockingDialer returns a recordingDialer whose Dial blocks until
// allowReturn or ctx cancellation. Use for testing concurrent behaviour.
func newBlockingDialer() *recordingDialer {
	return &recordingDialer{
		callCh:  make(chan dialCall, 1),
		allowCh: make(chan struct{}),
	}
}

// allowReturn unblocks a Dial call that is currently blocking.
func (d *recordingDialer) allowReturn(err error) {
	d.mu.Lock()
	d.dialErr = err
	d.mu.Unlock()
	close(d.allowCh)
}

func (d *recordingDialer) Dial(_ context.Context, sessionID, shellStr string, cols, rows int) error {
	call := dialCall{SessionID: sessionID, Shell: shellStr, Cols: cols, Rows: rows}
	d.mu.Lock()
	d.calls = append(d.calls, call)
	d.mu.Unlock()
	if d.callCh != nil {
		d.callCh <- call
	}
	<-d.allowCh
	d.mu.Lock()
	err := d.dialErr
	d.mu.Unlock()
	return err
}

func (d *recordingDialer) dialCalls() []dialCall {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]dialCall, len(d.calls))
	copy(out, d.calls)
	return out
}

// Compile-time check: recordingDialer implements TerminalDialer.
var _ TerminalDialer = (*recordingDialer)(nil)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newOpenTerminalHandler builds a handler (StewardID "steward-test") that trusts the
// returned operator signing certificate for terminal-open envelopes.
func newOpenTerminalHandler(t *testing.T) (*Handler, *cert.Certificate) {
	t.Helper()
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	return newHandlerWithSigning(t, nil, true, caPool), signer
}

// terminalParams returns open_terminal params carrying an X.509-signed envelope over
// content with envelope shell envShell, targeted at targets.
func terminalParams(t *testing.T, signer *cert.Certificate, content []byte, envShell string, targets []string, expiresAt time.Time) map[string]interface{} {
	t.Helper()
	params := signedActionParams(t, signer, content, targets, sigTestNonce(t), expiresAt)
	// signedActionParams signs with ActionShell; re-sign with the requested shell.
	env := operatorpayload.Envelope{Content: content, Shell: envShell, Targets: targets,
		Nonce: params["nonce"].(string), ExpiresAt: expiresAt}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)
	params["signature_value"] = sigTestSignWithCert(t, signer.PrivateKeyPEM, canonical)
	return params
}

// validTerminalParams signs a terminal-open envelope for steward-test and shell sh.
func validTerminalParams(t *testing.T, signer *cert.Certificate, sh, sessionID string) map[string]interface{} {
	t.Helper()
	content, err := operatorpayload.TerminalContent("steward-test", sh)
	require.NoError(t, err)
	params := terminalParams(t, signer, content, operatorpayload.TerminalShell, []string{"steward-test"}, time.Now().Add(time.Minute))
	params["session_id"] = sessionID
	params["shell"] = sh
	params["cols"] = float64(120)
	params["rows"] = float64(40)
	return params
}

// allowedShell returns a shell name that is valid on the current platform.
func allowedShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestOpenTerminal_NoProof_Rejected: a command with no operator proof never dials.
func TestOpenTerminal_NoProof_Rejected(t *testing.T) {
	dialer := newRecordingDialer()
	h, _ := newOpenTerminalHandler(t)

	cmd := &cpTypes.Command{ID: "ot-noproof", StewardID: "steward-test", Params: map[string]interface{}{
		"session_id": "sess-001", "shell": allowedShell(), "cols": float64(80), "rows": float64(24),
	}}
	err := h.handleOpenTerminal(context.Background(), cmd, dialer)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Empty(t, dialer.dialCalls())
}

// TestOpenTerminal_InvalidShell_Rejected: a correctly signed but non-allowlisted shell
// is still refused by the allowlist, without dialing.
func TestOpenTerminal_InvalidShell_Rejected(t *testing.T) {
	dialer := newRecordingDialer()
	h, signer := newOpenTerminalHandler(t)

	params := validTerminalParams(t, signer, "/bin/evil-shell", "sess-001")
	err := h.handleOpenTerminal(context.Background(), &cpTypes.Command{ID: "ot-bad-shell", StewardID: "steward-test", Params: params}, dialer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported shell")
	assert.Empty(t, dialer.dialCalls(), "Dial must not be called for a non-allowlisted shell")
}

// TestOpenTerminal_ValidEnvelope_DialerCalledOnce: a valid X.509 terminal envelope dials
// once with the expected values; replaying the same values is rejected (nonce reuse).
func TestOpenTerminal_ValidEnvelope_DialerCalledOnce(t *testing.T) {
	dialer := newBlockingDialer()
	h, signer := newOpenTerminalHandler(t)
	h.RegisterOpenTerminalHandler(dialer)

	params := validTerminalParams(t, signer, allowedShell(), "sess-abc")
	require.NoError(t, h.HandleCommand(context.Background(), testSignedCommandWithParams("ot-valid-001", cpTypes.CommandOpenTerminal, params)))
	h.Wait()

	select {
	case call := <-dialer.callCh:
		assert.Equal(t, dialCall{SessionID: "sess-abc", Shell: allowedShell(), Cols: 120, Rows: 40}, call)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TerminalDialer.Dial to be called")
	}

	// Replay of the same signed values is a reused nonce.
	err := h.handleOpenTerminal(context.Background(), &cpTypes.Command{ID: "ot-replay", StewardID: "steward-test", Params: params}, dialer)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand)
	assert.Contains(t, err.Error(), "nonce already used")

	dialer.allowReturn(nil)
	assert.Len(t, dialer.dialCalls(), 1)
}

// TestOpenTerminal_WebAuthnEnvelope_DialerCalled: a real WebAuthn assertion over the
// terminal content is accepted.
func TestOpenTerminal_WebAuthnEnvelope_DialerCalled(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-terminal-001")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{sigTestAuthorizedEntry(credID, pubKey)})
	h := newHandlerWithSigning(t, nil, true, caPool)
	dialer := newBlockingDialer()

	content, err := operatorpayload.TerminalContent("steward-test", allowedShell())
	require.NoError(t, err)
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, operatorpayload.TerminalShell,
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(time.Minute))
	delete(params, "script_content")
	params["shell"] = allowedShell()
	params["session_id"] = "sess-wa"
	params["cols"] = float64(100)
	params["rows"] = float64(30)

	require.NoError(t, h.handleOpenTerminal(context.Background(), &cpTypes.Command{ID: "ot-wa", StewardID: "steward-test", Params: params}, dialer))
	select {
	case call := <-dialer.callCh:
		assert.Equal(t, dialCall{SessionID: "sess-wa", Shell: allowedShell(), Cols: 100, Rows: 30}, call)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for TerminalDialer.Dial")
	}
	dialer.allowReturn(nil)
}

// TestOpenTerminal_BadEnvelopes_Rejected: every defective envelope is refused with
// ErrUnauthenticatedCommand and never dials.
func TestOpenTerminal_BadEnvelopes_Rejected(t *testing.T) {
	sh := allowedShell()
	otherShell := "powershell"
	if sh == otherShell {
		otherShell = "bash"
	}
	termContent := func(id, s string) []byte {
		c, err := operatorpayload.TerminalContent(id, s)
		require.NoError(t, err)
		return c
	}
	steward := []string{"steward-test"}
	cases := map[string]func(t *testing.T, signer *cert.Certificate) map[string]interface{}{
		"expired": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			return terminalParams(t, s, termContent("steward-test", sh), operatorpayload.TerminalShell, steward, time.Now().Add(-time.Minute))
		},
		"ttl too long": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			return terminalParams(t, s, termContent("steward-test", sh), operatorpayload.TerminalShell, steward,
				time.Now().Add(operatorpayload.TerminalEnvelopeMaxTTL+time.Hour))
		},
		"targets omit steward": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			return terminalParams(t, s, termContent("steward-test", sh), operatorpayload.TerminalShell, []string{"other"}, time.Now().Add(time.Minute))
		},
		"signed for other shell": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			return terminalParams(t, s, termContent("steward-test", otherShell), operatorpayload.TerminalShell, steward, time.Now().Add(time.Minute))
		},
		"signed for other steward": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			return terminalParams(t, s, termContent("steward-other", sh), operatorpayload.TerminalShell, steward, time.Now().Add(time.Minute))
		},
		"action shell": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			return terminalParams(t, s, termContent("steward-test", sh), operatorpayload.ActionShell, steward, time.Now().Add(time.Minute))
		},
		"empty shell": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			p := validTerminalParams(t, s, sh, "sess")
			p["shell"] = ""
			return p
		},
		"omitted shell": func(t *testing.T, s *cert.Certificate) map[string]interface{} {
			p := validTerminalParams(t, s, sh, "sess")
			delete(p, "shell")
			return p
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			dialer := newRecordingDialer()
			h, signer := newOpenTerminalHandler(t)
			params := build(t, signer)
			params["session_id"] = "sess"
			if _, ok := params["shell"]; !ok && name != "omitted shell" {
				params["shell"] = sh
			}
			err := h.handleOpenTerminal(context.Background(), &cpTypes.Command{ID: "ot-bad", StewardID: "steward-test", Params: params}, dialer)
			require.ErrorIs(t, err, ErrUnauthenticatedCommand)
			assert.Empty(t, dialer.dialCalls())
		})
	}
}

// TestOpenTerminal_CommandCompletesBeforeBridgeDone verifies that handleOpenTerminal
// returns nil immediately (allowing EventCommandCompleted) while the bridge goroutine
// is still running. This decouples the command handler timeout from the PTY session.
func TestOpenTerminal_CommandCompletesBeforeBridgeDone(t *testing.T) {
	dialer := newBlockingDialer()

	var commandCompletedAt atomic.Int64

	// Capture when EventCommandCompleted is emitted.
	cb := func(_ context.Context, evt *cpTypes.Event) {
		if evt.Type == cpTypes.EventCommandCompleted {
			commandCompletedAt.Store(time.Now().UnixNano())
		}
	}
	ca, caPool := sigTestCA(t)
	signer := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)
	h2, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
	})
	require.NoError(t, err)
	h2.RegisterOpenTerminalHandler(dialer)

	sc := testSignedCommandWithParams("ot-timing-001", cpTypes.CommandOpenTerminal,
		validTerminalParams(t, signer, allowedShell(), "sess-timing"))

	require.NoError(t, h2.HandleCommand(context.Background(), sc))
	h2.Wait() // returns once executeCommand goroutine completes (bridge still blocked)

	// At this point EventCommandCompleted should have been emitted.
	assert.NotZero(t, commandCompletedAt.Load(),
		"EventCommandCompleted must be emitted before Dial returns")

	// Unblock the bridge goroutine.
	dialer.allowReturn(nil)
}

// TestOpenTerminal_NoControllerCARoots_FailsClosed: with nil or empty controller CA
// roots, an envelope carrying a valid signature from a freshly generated key (no
// operator credential chain) is refused and nothing is dialed.
func TestOpenTerminal_NoControllerCARoots_FailsClosed(t *testing.T) {
	// Signer from an unrelated CA: the signature is valid, the chain is not trusted.
	otherCA, _ := sigTestCA(t)
	rogue := sigTestOperatorCert(t, otherCA, cert.SetPayloadSigningMarker)

	roots := map[string]*x509.CertPool{"nil": nil, "empty": x509.NewCertPool()}
	for name, pool := range roots {
		t.Run(name, func(t *testing.T) {
			dialer := newRecordingDialer()
			h := newHandlerWithSigning(t, nil, true, pool)
			h.RegisterOpenTerminalHandler(dialer)

			params := validTerminalParams(t, rogue, allowedShell(), "sess-rogue")
			err := h.handleOpenTerminal(context.Background(),
				&cpTypes.Command{ID: "ot-noroots-" + name, StewardID: "steward-test", Params: params}, dialer)
			require.ErrorIs(t, err, ErrUnauthenticatedCommand)
			assert.Contains(t, err.Error(), "controller CA")
			h.Wait()
			assert.Empty(t, dialer.dialCalls(), "Dial must not be called without controller CA roots")
		})
	}
}
