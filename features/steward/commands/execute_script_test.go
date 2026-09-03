// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// recordingEmitter — real in-process EventEmitter for tests (no mocks).
// ---------------------------------------------------------------------------

// recordingEmitter is a real channel-backed EventEmitter that satisfies the
// commands.EventEmitter interface. It records every Enqueue call for assertion.
type recordingEmitter struct {
	mu      sync.Mutex
	entries []*transportpb.LogEntry
}

func (r *recordingEmitter) Enqueue(entry *transportpb.LogEntry) {
	r.mu.Lock()
	r.entries = append(r.entries, entry)
	r.mu.Unlock()
}

func (r *recordingEmitter) Entries() []*transportpb.LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*transportpb.LogEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// Compile-time check: recordingEmitter implements commands.EventEmitter.
var _ EventEmitter = (*recordingEmitter)(nil)

// firstScriptOutputEntry returns the first LogEntry with event_kind=script_output,
// or nil if none was emitted.
func firstScriptOutputEntry(entries []*transportpb.LogEntry) *transportpb.LogEntry {
	for _, e := range entries {
		if e.GetFields()["event_kind"] == "script_output" {
			return e
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Issue #1978 — 1 MB hard cap on exec output.
// ---------------------------------------------------------------------------

// overCapStdoutScriptBody returns a script that writes approximately 2 MB to stdout
// — twice the execOutputHardCapBytes limit — using fast shell builtins.
func overCapStdoutScriptBody() string {
	if runtime.GOOS == "windows" {
		// PowerShell: write 2 MB of 'A' without buffering overhead.
		return `[Console]::Out.Write([string]::new('A', 2097152))`
	}
	// bash: yes generates an infinite stream; head -c cuts at exactly 2 MB.
	return `yes A | head -c 2097152`
}

// underCapStdoutScriptBody returns a script that writes 512 KB to stdout —
// well under the execOutputHardCapBytes limit — using fast shell builtins.
func underCapStdoutScriptBody() string {
	if runtime.GOOS == "windows" {
		return `[Console]::Out.Write([string]::new('A', 524288))`
	}
	return `yes A | head -c 524288`
}

// ---------------------------------------------------------------------------
// Unit tests for applyOutputCap.
// ---------------------------------------------------------------------------

func TestApplyOutputCap_BelowLimit_NoChange(t *testing.T) {
	out, err := applyOutputCap("hello", "world", execOutputHardCapBytes)
	assert.Equal(t, "hello", out)
	assert.Equal(t, "world", err)
}

func TestApplyOutputCap_AtExactLimit_NoChange(t *testing.T) {
	stdout := strings.Repeat("A", execOutputHardCapBytes)
	out, err := applyOutputCap(stdout, "", execOutputHardCapBytes)
	assert.Equal(t, stdout, out, "output exactly at limit must not be truncated")
	assert.Empty(t, err)
	assert.NotContains(t, out, execOutputTruncMarker)
}

// TestApplyOutputCap_StdoutExceedsLimit is a required test verifying that
// when a command produces 2 MB of stdout, the capped output contains the
// truncation marker and does not exceed the 1 MB ceiling (plus marker length).
func TestApplyOutputCap_StdoutExceedsLimit_TruncatedWithMarker(t *testing.T) {
	twoMB := strings.Repeat("A", 2*execOutputHardCapBytes)
	out, err := applyOutputCap(twoMB, "", execOutputHardCapBytes)
	assert.True(t, strings.HasSuffix(out, execOutputTruncMarker),
		"capped stdout must end with the truncation marker")
	assert.Empty(t, err, "stderr must be empty when stdout fills the cap")
	assert.LessOrEqual(t, len(out)+len(err), execOutputHardCapBytes+len(execOutputTruncMarker),
		"combined capped output must not exceed cap + marker")
	assert.NotEqual(t, twoMB, out, "output must be shorter than original 2 MB")
}

func TestApplyOutputCap_CombinedExceedsLimit_StderrTruncated(t *testing.T) {
	halfCap := strings.Repeat("A", execOutputHardCapBytes/2)
	// stdout alone fits; adding extra stderr pushes combined over the cap.
	out, err := applyOutputCap(halfCap, halfCap+strings.Repeat("B", 100), execOutputHardCapBytes)
	assert.Equal(t, halfCap, out, "stdout must be unchanged when it fits in the cap")
	assert.True(t, strings.HasSuffix(err, execOutputTruncMarker),
		"stderr must end with the truncation marker when it is the buffer that overflows")
	assert.LessOrEqual(t, len(out)+len(err), execOutputHardCapBytes+len(execOutputTruncMarker))
}

func TestApplyOutputCap_EmptyInputs_NoChange(t *testing.T) {
	out, err := applyOutputCap("", "", execOutputHardCapBytes)
	assert.Empty(t, out)
	assert.Empty(t, err)
}

// ---------------------------------------------------------------------------
// Integration tests via handleExecuteScript — required by AC.
// ---------------------------------------------------------------------------

// TestExecuteScriptHandler_OutputOverCap_TruncatedWithMarker is a required test (Issue #1978 AC):
// an exec command producing 2 MB of output must result in capped output ending with the
// truncation marker. Verified via the full stdout field in EventScriptCompleted.
func TestExecuteScriptHandler_OutputOverCap_TruncatedWithMarker(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	params := signedInlineEnvelopeParams(t, []byte(overCapStdoutScriptBody()), platformShell(), "steward-test")
	params["execution_id"] = "esc-cap-over-001"
	sc := testSignedCommandWithParams("esc-cap-over-001", cpTypes.CommandExecuteScript, params)

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "expected EventScriptCompleted event")

	// Full capped output is sent under the "stdout" key.
	stdout, ok := evt.Details["stdout"].(string)
	require.True(t, ok, "stdout field must be present and a string in EventScriptCompleted")

	assert.True(t, strings.HasSuffix(stdout, execOutputTruncMarker),
		"capped stdout must end with %q; got %d bytes ending in: %q",
		execOutputTruncMarker, len(stdout), lastN(stdout, 50))
	assert.LessOrEqual(t, len(stdout), execOutputHardCapBytes+len(execOutputTruncMarker),
		"capped stdout must not exceed 1 MB + marker length")
}

// TestExecuteScriptHandler_OutputUnderCap_CapturedFully is a required test (Issue #1978 AC):
// an exec command producing under 1 MB of output must be captured fully without a truncation marker.
func TestExecuteScriptHandler_OutputUnderCap_CapturedFully(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	params := signedInlineEnvelopeParams(t, []byte(underCapStdoutScriptBody()), platformShell(), "steward-test")
	params["execution_id"] = "esc-cap-under-001"
	sc := testSignedCommandWithParams("esc-cap-under-001", cpTypes.CommandExecuteScript, params)

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "expected EventScriptCompleted event")

	stdout, ok := evt.Details["stdout"].(string)
	require.True(t, ok, "stdout field must be present and a string in EventScriptCompleted")

	assert.NotContains(t, stdout, execOutputTruncMarker,
		"output under 1 MB must not contain the truncation marker")
	// 512 KB = 524288; allow for newlines added by the shell.
	assert.GreaterOrEqual(t, len(stdout), 500*1024,
		"output under cap must not be silently dropped (expected ~512 KB)")
}

// lastN returns the last n bytes of s as a string, for readable test failure messages.
func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// TestResolveRelayUID_SystemContext verifies that a system-context script
// resolves to the steward process UID, making the relay socket chown a no-op.
func TestResolveRelayUID_SystemContext(t *testing.T) {
	uid := resolveRelayUID(script.ExecutionContextSystem, logging.NewNoopLogger())
	assert.Equal(t, os.Getuid(), uid, "system context must resolve to the process UID")
}

// TestResolveRelayUID_LoggedInUser_FallsBackOnError verifies that when the
// logged-in user cannot be resolved (e.g. no interactive session), resolveRelayUID
// falls back to the steward process UID rather than returning a bogus value.
// The executor independently fails the run with the same underlying error.
func TestResolveRelayUID_LoggedInUser_FallsBackOnError(t *testing.T) {
	uid := resolveRelayUID(script.ExecutionContextLoggedInUser, logging.NewNoopLogger())
	if runtime.GOOS == "windows" {
		// On Windows, ResolveExecutionUID always returns -1 with no error:
		// process identity is SID-based and the relay pipe is DACL-controlled,
		// so -1 is the intentional "skip UID ownership" sentinel, not a failure.
		assert.Equal(t, -1, uid, "resolveRelayUID must return the Windows -1 sentinel")
		return
	}
	// On Unix, regardless of whether a user is logged in, the result must be a
	// valid UID: either the resolved logged-in user's UID, or the process-UID
	// fallback. It must never be a negative/zero sentinel from a partial
	// resolution.
	assert.GreaterOrEqual(t, uid, 0, "resolveRelayUID must always return a usable UID")
}

// ---------------------------------------------------------------------------
// Issue #1675 — handler-level relay-socket guard tests.
//
// AC1 [REQUIRED TEST]: a per-execution relay socket is created ONLY for a
// library script (non-empty script_id) with a non-empty required_api_scope.
// Inline run-command dispatches (empty script_id) must NOT create a socket
// regardless of required_api_scope.
//
// Detection: the relay sets CFGMS_API_SOCKET in the script's environment. A
// probe script echoes that variable; the value observed in stdout_preview is
// the proof of whether a relay was created for this execution.
// ---------------------------------------------------------------------------

const socketProbeOpen = "SOCKVAL["
const socketProbeClose = "]"

// socketEnvProbeScriptBody returns a script body that writes the value of the
// CFGMS_API_SOCKET environment variable to stdout, wrapped in SOCKVAL[...]
// markers. An empty value (SOCKVAL[]) means no relay socket was injected.
func socketEnvProbeScriptBody() string {
	if runtime.GOOS == "windows" {
		return `Write-Output ("` + socketProbeOpen + `" + $env:CFGMS_API_SOCKET + "` + socketProbeClose + `")`
	}
	return `echo "` + socketProbeOpen + `$CFGMS_API_SOCKET` + socketProbeClose + `"`
}

// socketValFromStdout extracts the CFGMS_API_SOCKET value the probe script
// observed from a stdout_preview string. It requires the SOCKVAL[...] marker
// to be present so a test never silently passes on missing output.
func socketValFromStdout(t *testing.T, stdout string) string {
	t.Helper()
	start := strings.Index(stdout, socketProbeOpen)
	require.GreaterOrEqual(t, start, 0, "probe marker %q missing from stdout: %q", socketProbeOpen, stdout)
	rest := stdout[start+len(socketProbeOpen):]
	end := strings.Index(rest, socketProbeClose)
	require.GreaterOrEqual(t, end, 0, "probe close marker missing from stdout: %q", stdout)
	return rest[:end]
}

// runScriptProbe executes the socket-env probe script through handleExecuteScript
// with the supplied params merged in, and returns the observed CFGMS_API_SOCKET
// value. extraParams supplies script_id / required_api_scope per test case.
func runScriptProbe(t *testing.T, h *Handler, getEvents func() []*cpTypes.Event,
	executionID string, extraParams map[string]interface{}) string {
	t.Helper()

	params := map[string]interface{}{
		"script_content": base64.StdEncoding.EncodeToString([]byte(socketEnvProbeScriptBody())),
		"shell":          platformShell(),
		"execution_id":   executionID,
	}
	for k, v := range extraParams {
		params[k] = v
	}

	cmd := &cpTypes.Command{
		ID:        "cmd-" + executionID,
		Type:      cpTypes.CommandExecuteScript,
		StewardID: "steward-test",
		Timestamp: time.Now(),
		Params:    params,
	}
	require.NoError(t, h.handleExecuteScript(context.Background(), cmd))

	events := getEvents()
	failEvt := firstEventOfType(events, cpTypes.EventCommandFailed)
	require.Nil(t, failEvt, "script execution must not fail: %+v", failEvt)
	evt := firstEventOfType(events, cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "expected EventScriptCompleted event")
	stdout, ok := evt.Details["stdout_preview"].(string)
	require.True(t, ok, "stdout_preview must be a string")
	return socketValFromStdout(t, stdout)
}

// TestExecuteScriptHandler_LibraryScriptWithScope_CreatesRelaySocket verifies
// that a library script (non-empty script_id) with a non-empty
// required_api_scope runs with CFGMS_API_SOCKET pointing at a per-execution
// relay socket — i.e. the relay IS created.
func TestExecuteScriptHandler_LibraryScriptWithScope_CreatesRelaySocket(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	socketVal := runScriptProbe(t, h, getEvents, "exec-relay-lib", map[string]interface{}{
		"script_id":          "lib-script-1",
		"required_api_scope": []string{"read:inventory"},
	})

	assert.NotEmpty(t, socketVal,
		"library script with non-empty required_api_scope must run with CFGMS_API_SOCKET set")
	assert.Contains(t, socketVal, "exec-relay-lib",
		"CFGMS_API_SOCKET must reference the per-execution relay for this execution_id")
}

// TestExecuteScriptHandler_LibraryScriptNoScope_NoRelaySocket verifies that a
// library script with an EMPTY required_api_scope does NOT get a relay socket.
func TestExecuteScriptHandler_LibraryScriptNoScope_NoRelaySocket(t *testing.T) {
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: newTestLogger(t)})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	socketVal := runScriptProbe(t, h, getEvents, "exec-relay-noscope", map[string]interface{}{
		"script_id": "lib-script-2",
		// required_api_scope intentionally omitted
	})

	assert.Empty(t, socketVal,
		"library script with empty required_api_scope must NOT create a relay socket")
}

// ---------------------------------------------------------------------------
// Issue #2143 — stream script output to controller (secret-redacted).
// ---------------------------------------------------------------------------

// secretScriptBody returns a script that writes known-sensitive patterns to
// stdout in the key=value form caught by audit.RedactString.
func secretScriptBody() string {
	if runtime.GOOS == "windows" {
		return `Write-Output "password=hunter2 token=abc123 api_key=secret-key-value"`
	}
	return `echo "password=hunter2 token=abc123 api_key=secret-key-value"`
}

// TestScriptOutput_SecretsRedacted is a required test (Issue #2143 AC):
// script output containing password=... / token=... / api-key patterns must
// emit [REDACTED] in the LogEntry fields; cleartext secrets must be absent from
// the emitted entry.
func TestScriptOutput_SecretsRedacted(t *testing.T) {
	emitter := &recordingEmitter{}
	cb, _ := collectEvents()
	h, err := New(&Config{
		StewardID:    "steward-test",
		OnStatus:     cb,
		Logger:       newTestLogger(t),
		EventEmitter: emitter,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	// Inline command (no script_id) so no library-script signature is required.
	scriptContent := base64.StdEncoding.EncodeToString([]byte(secretScriptBody()))
	cmd := &cpTypes.Command{
		ID:        "sec-redact-001",
		Type:      cpTypes.CommandExecuteScript,
		StewardID: "steward-test",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"script_content": scriptContent,
			"shell":          platformShell(),
			"execution_id":   "exec-sec-redact-001",
		},
	}
	require.NoError(t, h.handleExecuteScript(context.Background(), cmd))

	entry := firstScriptOutputEntry(emitter.Entries())
	require.NotNil(t, entry, "expected a script_output LogEntry to be emitted")

	stdout := entry.GetFields()["stdout"]

	// Cleartext secrets must be absent.
	assert.NotContains(t, stdout, "hunter2",
		"cleartext password value must not appear in emitted LogEntry stdout")
	assert.NotContains(t, stdout, "abc123",
		"cleartext token value must not appear in emitted LogEntry stdout")
	assert.NotContains(t, stdout, "secret-key-value",
		"cleartext api_key value must not appear in emitted LogEntry stdout")

	// Redaction placeholder must be present.
	assert.Contains(t, stdout, "[REDACTED]",
		"emitted stdout must contain [REDACTED] where secrets appeared")
}

// TestScriptOutput_BoundedAndAttributed is a required test (Issue #2143 AC):
// oversized output is truncated to the preview cap; the emitted LogEntry carries
// correct script_id, cfg_id, exit_code, and duration_ms attribution.
func TestScriptOutput_BoundedAndAttributed(t *testing.T) {
	emitter := &recordingEmitter{}
	cb, _ := collectEvents()
	h, err := New(&Config{
		StewardID:    "steward-test",
		OnStatus:     cb,
		Logger:       newTestLogger(t),
		EventEmitter: emitter,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	const wantScriptID = "lib-big-script"
	const wantExecID = "exec-bounded-001"
	const cmdID = "bounded-001"

	// Use the existing 2 MB script to produce output well above scriptPreviewMaxBytes.
	// Call handleExecuteScript directly so we can set script_id without a library-script
	// signature (signature verification is the preflightScriptSignature concern, not ours here).
	scriptContent := base64.StdEncoding.EncodeToString([]byte(overCapStdoutScriptBody()))
	cmd := &cpTypes.Command{
		ID:        cmdID,
		Type:      cpTypes.CommandExecuteScript,
		StewardID: "steward-test",
		Timestamp: time.Now(),
		Params: map[string]interface{}{
			"script_content": scriptContent,
			"shell":          platformShell(),
			"execution_id":   wantExecID,
			"script_id":      wantScriptID,
		},
	}

	before := time.Now()
	require.NoError(t, h.handleExecuteScript(context.Background(), cmd))
	elapsed := time.Since(before)

	entry := firstScriptOutputEntry(emitter.Entries())
	require.NotNil(t, entry, "expected a script_output LogEntry to be emitted")

	fields := entry.GetFields()

	// Attribution checks.
	assert.Equal(t, "script_output", fields["event_kind"])
	assert.Equal(t, wantScriptID, fields["script_id"],
		"script_id field must match the dispatched script_id param")
	assert.Equal(t, cmdID, fields["cfg_id"],
		"cfg_id field must equal the command ID (triggering cfg/script identifier)")
	assert.Equal(t, "0", fields["exit_code"],
		"exit_code field must be '0' for a successful script")

	durationMS := fields["duration_ms"]
	require.NotEmpty(t, durationMS, "duration_ms field must be present")
	// Sanity: duration_ms must be a non-negative decimal integer.
	var durVal int64
	for _, ch := range durationMS {
		require.True(t, ch >= '0' && ch <= '9',
			"duration_ms %q contains non-digit character %q", durationMS, ch)
		durVal = durVal*10 + int64(ch-'0')
	}
	assert.GreaterOrEqual(t, durVal, int64(0), "duration_ms must be non-negative")
	assert.LessOrEqual(t, time.Duration(durVal)*time.Millisecond, elapsed+time.Second,
		"duration_ms must not exceed wall-clock elapsed time plus slack")

	// Bounds check: stdout field in the LogEntry must be bounded to scriptPreviewMaxBytes.
	stdout := fields["stdout"]
	assert.LessOrEqual(t, len(stdout), scriptPreviewMaxBytes,
		"stdout in the emitted LogEntry must be bounded to scriptPreviewMaxBytes (%d bytes)", scriptPreviewMaxBytes)
}

// TestExecuteScriptHandler_InlineCommandWithScope_NoRelaySocket is the AC1
// "regardless" guard: an inline run-command dispatch (empty script_id) must
// NOT create a relay socket even when required_api_scope is non-empty. The
// handler enforces this invariant rather than trusting the dispatcher to omit
// the param.
func TestExecuteScriptHandler_InlineCommandWithScope_NoRelaySocket(t *testing.T) {
	capLog := &capturingLogger{}
	cb, getEvents := collectEvents()
	h, err := New(&Config{StewardID: "steward-test", OnStatus: cb, Logger: capLog})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	socketVal := runScriptProbe(t, h, getEvents, "exec-relay-inline", map[string]interface{}{
		// script_id intentionally omitted → inline command
		"required_api_scope": []string{"read:inventory"},
	})

	assert.Empty(t, socketVal,
		"inline command must NOT create a relay socket regardless of required_api_scope")

	// The handler must also surface the anomaly: an inline command carrying a
	// non-empty required_api_scope indicates a dispatcher bug or tampering.
	var sawWarn bool
	for _, line := range capLog.Lines() {
		if strings.Contains(line, "ignoring required_api_scope on inline command") {
			sawWarn = true
		}
	}
	assert.True(t, sawWarn,
		"handler must log a warning when an inline command carries required_api_scope")
}

// ---------------------------------------------------------------------------
// Issue #3696 — operator payload signing switches to the zero-custody
// CSR-issued credential; the admin-bundle marker no longer qualifies a
// certificate to sign an operator payload.
// ---------------------------------------------------------------------------

// TestExecuteScriptHandler_InlineScript_AdminBundleCert_RejectedForPayloadSigning
// is a REQUIRED test (Issue #3696 AC): a certificate shaped exactly like one
// IssueAdminBundle would mint — chained to the controller CA, unexpired,
// carrying cert.AdminMarkerOID via cert.SetAdminMarker — must no longer
// authorize signing an operator payload now that verifyOperatorCert checks
// cert.HasPayloadSigningMarker instead of cert.HasAdminMarker. The envelope is
// submitted through the real dispatch path (h.HandleCommand), not a direct
// call to verifyOperatorCert/HasPayloadSigningMarker with hand-built inputs,
// so the assertion covers the actual wiring a cfg-signed payload traverses.
func TestExecuteScriptHandler_InlineScript_AdminBundleCert_RejectedForPayloadSigning(t *testing.T) {
	ca, caPool := sigTestCA(t)
	// IssueAdminBundle-shaped: admin-marked, NOT payload-signing-marked.
	adminCert := sigTestOperatorCert(t, ca, cert.SetAdminMarker)

	h := newHandlerWithSigning(t, nil, true, caPool)

	content := []byte(echoScriptBody("hello"))
	params := sigTestOperatorEnvelopeParams(t, adminCert.PrivateKeyPEM, string(adminCert.CertificatePEM), content, platformShell(), "steward-test")
	params["execution_id"] = "sig-admin-bundle-001"
	sc := testSignedCommandWithParams("sig-admin-bundle-001", cpTypes.CommandExecuteScript, params)

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"an admin-bundle-shaped credential (AdminMarkerOID, no PayloadSigningMarkerOID) must not authorize payload signing")
}

// TestExecuteScriptHandler_InlineScript_PayloadSigningCert_Accepted is a
// REQUIRED test (Issue #3696 AC): a genuine S10-issued payload-signing
// credential — chained to the controller CA, unexpired, carrying
// cert.PayloadSigningMarkerOID via cert.SetPayloadSigningMarker — is accepted
// end-to-end through the real dispatch path (h.HandleCommand).
func TestExecuteScriptHandler_InlineScript_PayloadSigningCert_Accepted(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestOperatorCert(t, ca, cert.SetPayloadSigningMarker)

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("operator-hello"))
	params := sigTestOperatorEnvelopeParams(t, signingCert.PrivateKeyPEM, string(signingCert.CertificatePEM), content, platformShell(), "steward-test")
	params["execution_id"] = "sig-payload-signing-001"
	sc := testSignedCommandWithParams("sig-payload-signing-001", cpTypes.CommandExecuteScript, params)

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "inline command signed by a genuine payload-signing credential must be accepted")
}

// ---------------------------------------------------------------------------
// Issue #3697 — steward-side verification of a WebAuthn-signed operator payload
// (the browser-only-operator path alongside the X.509 path above).
// ---------------------------------------------------------------------------

// sigTestSigningCert issues a PurposeSigning-shaped certificate (CodeSigning EKU) from
// ca, matching pkg/cert.CA.GenerateSigningCertificate's production template — the
// manifest-signer credential type webauthnOperatorCredentialVerifier chain-verifies.
func sigTestSigningCert(t *testing.T, ca *cert.CA) *cert.Certificate {
	t.Helper()
	c, err := ca.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName:   "test-config-signer",
		Organization: "Test CFGMS",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(t, err)
	return c
}

// sigTestWebAuthnKeypair generates a real ECDSA P-256 keypair and returns it alongside
// its CBOR COSE-encoded public key bytes — the exact format
// AuthorizedWebAuthnCredential.PublicKey stores — mirroring generateSyntheticCredential
// in features/controller/api/handlers_operator_payload_sign_test.go (duplicated here:
// a different package). Real cryptographic material throughout — no mocks.
func sigTestWebAuthnKeypair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	padCoord := func(b []byte) []byte {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return out
	}
	coseKey := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   2, // EC2
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: padCoord(priv.X.Bytes()),
		YCoord: padCoord(priv.Y.Bytes()),
	}
	pubKeyBytes, err := webauthncbor.Marshal(coseKey)
	require.NoError(t, err)
	return priv, pubKeyBytes
}

// sigTestSignManifest builds a CA-signed manifest (JSON bytes, ready for the
// webauthn_manifest param) carrying credEntries, issued now and bound to the test
// relying party, signed by signingCert via the same signature.NewSigner construction
// the controller's signRevocationManifest uses
// (features/controller/api/handlers_revocation_manifest.go).
func sigTestSignManifest(t *testing.T, signingCert *cert.Certificate, credEntries []authorizedWebAuthnCredential) []byte {
	t.Helper()
	return sigTestSignManifestAt(t, signingCert, credEntries, time.Now().UTC().Truncate(time.Second),
		&webauthnRelyingParty{ID: sigTestRPID, Origins: []string{sigTestAssertionOrigin}})
}

// sigTestSignManifestAt is sigTestSignManifest with the issuance instant and
// relying-party binding chosen by the caller, for freshness and RP-binding tests.
func sigTestSignManifestAt(t *testing.T, signingCert *cert.Certificate, credEntries []authorizedWebAuthnCredential, issuedAt time.Time, rp *webauthnRelyingParty) []byte {
	t.Helper()
	manifest := revocationManifestPayload{
		Kind:                          revocationManifestKind,
		Version:                       1,
		IssuedAt:                      issuedAt,
		RevokedSerials:                []string{},
		AuthorizedWebAuthnCredentials: credEntries,
		WebAuthnRelyingParty:          rp,
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)

	signer, err := signature.NewSigner(&signature.SignerConfig{
		CertificatePEM: signingCert.CertificatePEM,
		PrivateKeyPEM:  signingCert.PrivateKeyPEM,
	})
	require.NoError(t, err)
	sig, err := signer.Sign(data)
	require.NoError(t, err)

	out, err := json.Marshal(signedRevocationManifest{
		Manifest:             manifest,
		Signature:            sig,
		SignerCertificatePEM: string(signingCert.CertificatePEM),
	})
	require.NoError(t, err)
	return out
}

// sigTestWebAuthnAssertionParams builds the full cmd.Params set for a WebAuthn-signed
// inline command from sigTestWebAuthnProof's real cryptographic construction
// (webauthn_credential_verifier_test.go) — the same bytes and algorithm production
// verification uses (Issue #3697). manifestJSON is embedded verbatim as the
// webauthn_manifest param. targets/nonce/expiresAt are exposed separately (rather than
// baked only into the envelope) so re-addressing/replay tests can swap in mismatched
// values while keeping the same real signature.
func sigTestWebAuthnAssertionParams(t *testing.T, priv *ecdsa.PrivateKey, credID, manifestJSON, content []byte, shell string, envelopeTargets []string, nonce string, expiresAt time.Time) map[string]interface{} {
	t.Helper()
	_, proof := sigTestWebAuthnProof(t, priv, credID, manifestJSON, content, shell, envelopeTargets, nonce, expiresAt)

	var p webauthnAssertionProof
	require.NoError(t, json.Unmarshal(proof, &p))

	return map[string]interface{}{
		"script_content":              base64.StdEncoding.EncodeToString(content),
		"shell":                       shell,
		"webauthn_authenticator_data": base64.StdEncoding.EncodeToString(p.AuthenticatorData),
		"webauthn_client_data_json":   base64.StdEncoding.EncodeToString(p.ClientDataJSON),
		"webauthn_signature":          base64.StdEncoding.EncodeToString(p.Signature),
		"webauthn_credential_id":      base64.StdEncoding.EncodeToString(p.CredentialID),
		"webauthn_manifest":           p.SignedManifestJSON,
		"targets":                     envelopeTargets,
		"nonce":                       nonce,
		"expires_at":                  expiresAt.UTC().Format(time.RFC3339),
	}
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_Accepted is a REQUIRED test (Issue
// #3697 AC): a payload signed via S6's WebAuthn flow, delivered to the steward, is
// accepted end-to-end through the real dispatch path (h.HandleCommand) — the epic's
// browser-only-operator success criterion, demonstrated positively.
func TestExecuteScriptHandler_WebAuthnSignedPayload_Accepted(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-accept-001")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("webauthn-hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-accept-001"
	sc := testSignedCommandWithParams("sig-webauthn-accept-001", cpTypes.CommandExecuteScript, params)

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()

	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "a payload signed via the WebAuthn flow, delivered to the steward, must be accepted end-to-end")
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_UnauthorizedCredential_Rejected verifies
// that a real, validly-signed assertion is rejected when its credential ID is not
// present in the CA-signed manifest — proving the public key really comes from the
// manifest (never a live, unsigned controller claim).
func TestExecuteScriptHandler_WebAuthnSignedPayload_UnauthorizedCredential_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, _ := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-unauthorized-001")
	// Empty manifest: this credential ID is not among the authorized entries.
	manifestJSON := sigTestSignManifest(t, signingCert, nil)

	h := newHandlerWithSigning(t, nil, true, caPool)

	content := []byte(echoScriptBody("hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-unauth-001"
	sc := testSignedCommandWithParams("sig-webauthn-unauth-001", cpTypes.CommandExecuteScript, params)

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a validly-signed assertion whose credential is absent from the CA-signed manifest must be rejected")
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_TargetMismatch_Rejected is the WebAuthn
// counterpart of TestExecuteScriptHandler_TargetMismatch_Rejected (REQUIRED test, Issue
// #3697 AC): an envelope signed for target list ["host-A"], delivered to a steward whose
// own ID is "host-B", is rejected — confirming the WebAuthn dispatch branch actually
// calls the shared target-binding check rather than short-circuiting.
func TestExecuteScriptHandler_WebAuthnSignedPayload_TargetMismatch_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-mismatch-001")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	cb, err := New(&Config{StewardID: "host-B", OnStatus: noopStatus, Logger: newTestLogger(t), RequireSignedAdhoc: true, ControllerCARoots: caPool})
	require.NoError(t, err)
	cb.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"host-A"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-mismatch-001"
	sc := testSignedCommandForSteward("sig-webauthn-mismatch-001", "host-B", cpTypes.CommandExecuteScript, params)

	err = cb.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"an envelope signed for a different target list must be rejected even though the outer command legitimately routes to this steward")
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_ExpiredEnvelope_Rejected is the
// WebAuthn counterpart of TestExecuteScriptHandler_ExpiredEnvelope_Rejected (REQUIRED
// test, Issue #3697 AC).
func TestExecuteScriptHandler_WebAuthnSignedPayload_ExpiredEnvelope_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-expired-001")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	h := newHandlerWithSigning(t, nil, true, caPool)

	content := []byte(echoScriptBody("hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(-time.Minute))
	params["execution_id"] = "sig-webauthn-expired-001"
	sc := testSignedCommandWithParams("sig-webauthn-expired-001", cpTypes.CommandExecuteScript, params)

	err := h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand, "an expired WebAuthn-signed envelope must be rejected")
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_NonceReplay_Rejected is the WebAuthn
// counterpart of TestExecuteScriptHandler_EnvelopeNonceReplay_RejectedIndependentlyOfOuterReplayCache
// (REQUIRED test, Issue #3697 AC).
func TestExecuteScriptHandler_WebAuthnSignedPayload_NonceReplay_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-replay-001")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("hello"))
	nonce := sigTestNonce(t)
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, nonce, time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-replay-001"
	sc := testSignedCommandWithParams("sig-webauthn-replay-001", cpTypes.CommandExecuteScript, params)

	require.NoError(t, h.HandleCommand(context.Background(), sc))
	h.Wait()
	evt := firstEventOfType(getEvents(), cpTypes.EventScriptCompleted)
	require.NotNil(t, evt, "first use of the nonce must be accepted")

	// Same nonce, fresh outer command ID/timestamp — must still be rejected because the
	// nonce is bound into what the operator actually signed (envelopeNonceCache), unlike
	// the outer SignedCommand's own independent replay window.
	replayParams := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, nonce, time.Now().Add(5*time.Minute))
	replayParams["execution_id"] = "sig-webauthn-replay-002"
	replaySc := testSignedCommandWithParams("sig-webauthn-replay-002", cpTypes.CommandExecuteScript, replayParams)

	err = h.HandleCommand(context.Background(), replaySc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand, "a reused operator envelope nonce must be rejected")
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_NoCARoots_Rejected covers
// verifyWebAuthnOperatorSignature's fail-closed branch: with no controller CA roots
// configured, a WebAuthn-signed inline command is rejected outright. This is where the
// WebAuthn path deliberately diverges from the X.509 path, which falls back to
// any_valid signature verification when no roots are configured — a WebAuthn public key
// has no source other than the CA-verified manifest, so "no roots" cannot mean "skip the
// credential check". Asserted directly so a regression back to fail-open cannot ship.
func TestExecuteScriptHandler_WebAuthnSignedPayload_NoCARoots_Rejected(t *testing.T) {
	ca, _ := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-no-ca-roots")
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{
		sigTestAuthorizedEntry(credID, pubKey),
	})

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID: "steward-test",
		OnStatus:  cb,
		Logger:    newTestLogger(t),
		// No ControllerCARoots: the manifest cannot be chain-verified here.
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-no-ca-001"
	sc := testSignedCommandWithParams("sig-webauthn-no-ca-001", cpTypes.CommandExecuteScript, params)

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a WebAuthn-signed command must be rejected when no controller CA roots are configured")
	assert.Contains(t, err.Error(), "requires a configured controller CA")
	assert.Nil(t, firstEventOfType(getEvents(), cpTypes.EventScriptCompleted),
		"nothing may execute when the manifest cannot be chain-verified")
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_ForeignTenantCredential_Rejected proves
// the dispatch path really passes this steward's own tenant to the verifier: a roster
// entry owned by an account in another tenant does not authorize execution here, even
// though the manifest is fleet-wide, correctly signed, and the assertion is valid.
func TestExecuteScriptHandler_WebAuthnSignedPayload_ForeignTenantCredential_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-foreign-tenant")

	entry := sigTestAuthorizedEntry(credID, pubKey)
	entry.RootScope = false
	entry.TenantID = "root/msp-b"
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{entry})

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
		TenantID:           "root/msp-a/client-1",
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-foreign-tenant-001"
	sc := testSignedCommandWithParams("sig-webauthn-foreign-tenant-001", cpTypes.CommandExecuteScript, params)

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a credential registered in another tenant must not authorize execution on this steward")
	assert.Nil(t, firstEventOfType(getEvents(), cpTypes.EventScriptCompleted))
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_UnauthorizedGrant_Rejected proves the
// dispatch path enforces the roster entry's authority: a credential that is in the
// CA-signed manifest but carries no operator-payload signing grant — the shape a passkey
// on a zero-privilege account would have — executes nothing.
func TestExecuteScriptHandler_WebAuthnSignedPayload_UnauthorizedGrant_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-no-grant")

	entry := sigTestAuthorizedEntry(credID, pubKey)
	entry.Grants = nil
	manifestJSON := sigTestSignManifest(t, signingCert, []authorizedWebAuthnCredential{entry})

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-no-grant-001"
	sc := testSignedCommandWithParams("sig-webauthn-no-grant-001", cpTypes.CommandExecuteScript, params)

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand,
		"a rostered credential without the signing grant must not authorize execution")
	assert.Nil(t, firstEventOfType(getEvents(), cpTypes.EventScriptCompleted))
}

// TestExecuteScriptHandler_WebAuthnSignedPayload_StaleManifest_Rejected proves the
// dispatch path enforces manifest freshness end-to-end, so a captured manifest listing a
// since-removed credential cannot be presented indefinitely.
func TestExecuteScriptHandler_WebAuthnSignedPayload_StaleManifest_Rejected(t *testing.T) {
	ca, caPool := sigTestCA(t)
	signingCert := sigTestSigningCert(t, ca)
	priv, pubKey := sigTestWebAuthnKeypair(t)
	credID := []byte("webauthn-cred-stale-manifest")

	stale := time.Now().Add(-webauthnManifestMaxAge - time.Minute).UTC().Truncate(time.Second)
	manifestJSON := sigTestSignManifestAt(t, signingCert,
		[]authorizedWebAuthnCredential{sigTestAuthorizedEntry(credID, pubKey)}, stale,
		&webauthnRelyingParty{ID: sigTestRPID, Origins: []string{sigTestAssertionOrigin}})

	cb, getEvents := collectEvents()
	h, err := New(&Config{
		StewardID:          "steward-test",
		OnStatus:           cb,
		Logger:             newTestLogger(t),
		RequireSignedAdhoc: true,
		ControllerCARoots:  caPool,
	})
	require.NoError(t, err)
	h.RegisterExecuteScriptHandler()

	content := []byte(echoScriptBody("hello"))
	params := sigTestWebAuthnAssertionParams(t, priv, credID, manifestJSON, content, platformShell(),
		[]string{"steward-test"}, sigTestNonce(t), time.Now().Add(5*time.Minute))
	params["execution_id"] = "sig-webauthn-stale-001"
	sc := testSignedCommandWithParams("sig-webauthn-stale-001", cpTypes.CommandExecuteScript, params)

	err = h.HandleCommand(context.Background(), sc)
	require.ErrorIs(t, err, ErrUnauthenticatedCommand, "a stale manifest must not authorize execution")
	assert.Nil(t, firstEventOfType(getEvents(), cpTypes.EventScriptCompleted))
}
