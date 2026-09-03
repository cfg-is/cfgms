// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/steward/operatorroster"
	scriptrelay "github.com/cfgis/cfgms/features/steward/script_relay"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

const (
	scriptPreviewMaxBytes   = 4096
	execOutputHardCapBytes  = 1 << 20 // 1 MB combined stdout+stderr cap
	execOutputTruncMarker   = "\n[output truncated at 1 MB]"
	defaultScriptTimeoutSec = 900 // 15 minutes
)

// RegisterExecuteScriptHandler registers the built-in execute_script command handler on h.
// The handler extracts script params, invokes the script module executor, and publishes
// EventScriptCompleted (carrying exit code, duration, and bounded previews) or
// EventCommandFailed when the executor itself cannot run.
func (h *Handler) RegisterExecuteScriptHandler() {
	h.RegisterHandler(cpTypes.CommandExecuteScript, func(ctx context.Context, cmd *cpTypes.Command) error {
		return h.handleExecuteScript(ctx, cmd)
	})
}

// handleExecuteScript is the CommandFunc implementation for CommandExecuteScript.
// It always returns nil — the command outcome is communicated via onStatus events
// so that executeCommand does not emit a redundant EventCommandFailed.
func (h *Handler) handleExecuteScript(ctx context.Context, cmd *cpTypes.Command) error {
	// Extract params via type assertion per spec; zero-value on missing key is intentional.
	scriptContentB64, _ := cmd.Params["script_content"].(string)
	shellStr, _ := cmd.Params["shell"].(string)
	executionID, _ := cmd.Params["execution_id"].(string)
	executionContextStr, _ := cmd.Params["execution_context"].(string)
	scriptID, _ := cmd.Params["script_id"].(string)

	// Decode base64 script content — content is NEVER stored in a variable that gets logged.
	contentBytes, err := base64.StdEncoding.DecodeString(scriptContentB64)
	if err != nil {
		h.logger.Error("execute_script: invalid script_content encoding",
			"command_id", cmd.ID,
			"execution_id", executionID,
			"error", err)
		h.sendStatus(ctx, &cpTypes.Event{
			ID:        newEventID(),
			Type:      cpTypes.EventCommandFailed,
			StewardID: h.stewardID,
			CommandID: cmd.ID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"execution_id": executionID,
				"error":        "invalid script_content encoding: " + err.Error(),
			},
		})
		return nil
	}

	// Extract required_api_scope — non-empty only for library scripts with
	// RequiredAPIScope set (Issue #1675). Inline run-command scripts never have a scope.
	requiredAPIScope := extractStringSlice(cmd.Params["required_api_scope"])

	// Extract timeout; default to 15 minutes per spec.
	timeoutSecs := float64(defaultScriptTimeoutSec)
	if ts, ok := cmd.Params["timeout_seconds"].(float64); ok && ts > 0 {
		timeoutSecs = ts
	}
	timeout := time.Duration(timeoutSecs) * time.Second

	// Map execution_context param to script.ExecutionContext.
	execCtx := script.ExecutionContextSystem
	if executionContextStr == string(script.ExecutionContextLoggedInUser) {
		execCtx = script.ExecutionContextLoggedInUser
	}

	cfg := &script.ScriptConfig{
		Content:          string(contentBytes), // content is placed only in ScriptConfig, never logged
		Shell:            script.ShellType(shellStr),
		Timeout:          timeout,
		ExecutionContext: execCtx,
		SigningPolicy:    script.SigningPolicyNone, // pre-flight verification is done in preflightScriptSignature
	}

	// Issue #1675: start per-execution relay when the script needs API access.
	// Guard: only LIBRARY scripts (non-empty script_id) ever get a relay socket.
	// Inline run-command dispatches NEVER create a socket regardless of
	// required_api_scope — the steward enforces this invariant here at the
	// handler layer rather than trusting the dispatcher to omit the param.
	isLibraryScript := scriptID != ""
	if !isLibraryScript && len(requiredAPIScope) > 0 {
		// Anomaly: an inline command carrying required_api_scope indicates a
		// dispatcher bug or tampering. Drop the scope and proceed without a relay.
		h.logger.Warn("execute_script: ignoring required_api_scope on inline command — relay sockets are library-script only",
			"command_id", cmd.ID,
			"execution_id", executionID)
	}
	var relay *scriptrelay.Relay
	if isLibraryScript && len(requiredAPIScope) > 0 {
		// Resolve the UID the script will run as so the relay socket can be
		// chowned to it — a logged_in_user script (launched via `sudo -u`)
		// otherwise cannot connect to the 0700/0600 socket owned by the
		// steward process.
		relayUID := resolveRelayUID(execCtx, h.logger)
		r, err := scriptrelay.NewRelay(executionID, h.stewardID, relayUID, h.sendStatus, h.logger)
		if err != nil {
			h.logger.Error("execute_script: failed to start relay",
				"command_id", cmd.ID,
				"execution_id", executionID,
				"error", err)
			h.sendStatus(ctx, &cpTypes.Event{
				ID:        newEventID(),
				Type:      cpTypes.EventCommandFailed,
				StewardID: h.stewardID,
				CommandID: cmd.ID,
				Timestamp: time.Now(),
				Details: map[string]interface{}{
					"execution_id": executionID,
					"error":        "relay start failed: " + err.Error(),
				},
			})
			return nil
		}
		if err := r.Start(ctx); err != nil {
			h.logger.Error("execute_script: failed to start relay listener",
				"execution_id", executionID,
				"error", err)
			r.Stop()
			return nil
		}
		h.registerRelay(executionID, r)
		cfg.Environment = mergeEnv(cfg.Environment, map[string]string{
			"CFGMS_API_SOCKET": r.SocketPath(),
		})
		// Inject the shell helper function so the script can call cfgms_api / Invoke-CfgApi.
		switch cfg.Shell {
		case script.ShellBash, script.ShellSh, script.ShellZsh:
			cfg.Content = scriptrelay.InjectBashPreamble(cfg.Content, r.SocketPath())
		case script.ShellPowerShell:
			cfg.Content = scriptrelay.InjectPowerShellPreamble(cfg.Content, r.SocketPath())
		}
		relay = r
	}

	// Log only non-sensitive correlation data: SHA-256 prefix + byte length, never content.
	contentHash := sha256.Sum256(contentBytes)
	h.logger.Info("execute_script: starting",
		"command_id", cmd.ID,
		"execution_id", executionID,
		"shell", shellStr,
		"content_sha256_prefix", fmt.Sprintf("%x", contentHash[:4]),
		"content_bytes", len(contentBytes),
		"timeout_seconds", int(timeoutSecs))

	// Derive a timeout context; ctx carries the connection-lifetime deadline so the
	// outer deadline still cancels first when it is shorter.
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	executor := script.NewExecutor(cfg)
	result, execErr := executor.Execute(timeoutCtx)

	// Stop relay after execution regardless of outcome so the socket is cleaned up.
	if relay != nil {
		relay.Stop()
		h.unregisterRelay(executionID)
	}

	if execErr != nil {
		h.logger.Error("execute_script: executor failed",
			"command_id", cmd.ID,
			"execution_id", executionID,
			"error", execErr)
		h.sendStatus(ctx, &cpTypes.Event{
			ID:        newEventID(),
			Type:      cpTypes.EventCommandFailed,
			StewardID: h.stewardID,
			CommandID: cmd.ID,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"execution_id": executionID,
				"error":        execErr.Error(),
			},
		})
		return nil
	}

	// Apply 1 MB hard cap on combined stdout+stderr before generating previews.
	result.Stdout, result.Stderr = applyOutputCap(result.Stdout, result.Stderr, execOutputHardCapBytes)

	// Truncate previews to cap; excess bytes are silently dropped.
	// stdout_preview and stderr_preview are NEVER logged — only byte counts are.
	stdoutPreview := truncatePreview(result.Stdout, scriptPreviewMaxBytes)
	stderrPreview := truncatePreview(result.Stderr, scriptPreviewMaxBytes)

	h.logger.Info("execute_script: completed",
		"command_id", cmd.ID,
		"execution_id", executionID,
		"exit_code", result.ExitCode,
		"duration_ms", result.Duration.Milliseconds(),
		"stdout_bytes", len(result.Stdout),
		"stderr_bytes", len(result.Stderr))

	h.sendStatus(ctx, &cpTypes.Event{
		ID:        newEventID(),
		Type:      cpTypes.EventScriptCompleted,
		StewardID: h.stewardID,
		CommandID: cmd.ID,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"execution_id":   executionID,
			"exit_code":      result.ExitCode,
			"duration_ms":    result.Duration.Milliseconds(),
			"stdout_preview": stdoutPreview,
			"stderr_preview": stderrPreview,
			"stdout":         result.Stdout, // full capped output (up to 1 MB); controller reads this key
			"stderr":         result.Stderr, // full capped output (up to 1 MB); controller reads this key
		},
	})

	// Emit script output via the S3 EventEmitter (additive to the ControlChannel path above).
	// stdout/stderr previews are secret-redacted then control-char-sanitized before emission.
	// Enqueue is non-blocking; the caller is never stalled on a slow or full emitter buffer.
	h.emitScriptOutput(cmd.ID, scriptID, executionID, result.ExitCode, result.Duration, stdoutPreview, stderrPreview)

	return nil
}

// emitScriptOutput enqueues a script_output LogEntry on the S3 EventEmitter when one is
// configured. stdout and stderr are the already-bounded preview strings (scriptPreviewMaxBytes).
// Redaction is applied before sanitization: RedactString catches key=value patterns in free-form
// text; SanitizeLogValue strips control characters. RedactMap catches any field whose key matches
// the RedactedKeys deny-list. A nil emitter is a silent no-op.
func (h *Handler) emitScriptOutput(cmdID, scriptID, executionID string, exitCode int, duration time.Duration, stdout, stderr string) {
	if h.eventEmitter == nil {
		return
	}

	redactedStdout := logging.SanitizeLogValue(audit.RedactString(stdout))
	redactedStderr := logging.SanitizeLogValue(audit.RedactString(stderr))

	rawFields := map[string]interface{}{
		"event_kind":   "script_output",
		"cfg_id":       cmdID,
		"execution_id": executionID,
		"exit_code":    fmt.Sprintf("%d", exitCode),
		"duration_ms":  fmt.Sprintf("%d", duration.Milliseconds()),
		"stdout":       redactedStdout,
		"stderr":       redactedStderr,
	}
	if scriptID != "" {
		rawFields["script_id"] = scriptID
	}

	redactedFields := audit.RedactMap(rawFields)
	pbFields := make(map[string]string, len(redactedFields))
	for k, v := range redactedFields {
		if sv, ok := v.(string); ok {
			pbFields[k] = sv
		}
	}

	h.eventEmitter.Enqueue(&transportpb.LogEntry{
		StewardId: h.stewardID,
		Level:     transportpb.Severity_SEVERITY_INFO,
		Message:   "script_output",
		Timestamp: timestamppb.Now(),
		Fields:    pbFields,
	})
}

// resolveRelayUID returns the UID the per-execution relay socket should be
// owned by so the script process can connect to it. It mirrors the executor's
// execution-context UID resolution. On resolution failure (e.g. no user is
// logged in for a logged_in_user script) it falls back to the steward process
// UID; the executor independently fails the run with the same underlying error,
// so the fallback never produces an inconsistent outcome.
func resolveRelayUID(execCtx script.ExecutionContext, logger logging.Logger) int {
	uid, err := script.ResolveExecutionUID(execCtx)
	if err != nil {
		logger.Debug("execute_script: relay UID resolution fell back to process UID",
			"execution_context", string(execCtx),
			"error", err)
		return os.Getuid()
	}
	return uid
}

// applyOutputCap enforces a combined hard cap on stdout+stderr.
// stdout is filled first; remaining capacity goes to stderr.
// Appends execOutputTruncMarker to whichever buffer is truncated.
// Returns unchanged strings when len(stdout)+len(stderr) <= capBytes.
func applyOutputCap(stdout, stderr string, capBytes int) (string, string) {
	if len(stdout)+len(stderr) <= capBytes {
		return stdout, stderr
	}
	markerLen := len(execOutputTruncMarker)
	available := capBytes - markerLen
	if available < 0 {
		available = 0
	}
	if len(stdout) >= available {
		// stdout alone fills or exceeds the available budget; drop stderr.
		return stdout[:available] + execOutputTruncMarker, ""
	}
	// stdout fits; give stderr the remaining budget.
	remaining := available - len(stdout)
	return stdout, stderr[:remaining] + execOutputTruncMarker
}

// truncatePreview returns at most maxBytes bytes of s; excess is silently dropped.
func truncatePreview(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes]
}

// newEventID returns a monotonic event identifier.
func newEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

// preflightScriptSignature verifies the script signature of a CommandExecuteScript
// command before goroutine dispatch. Returns ErrUnauthenticatedCommand on rejection.
//
// Library scripts (non-empty script_id): always verified against TrustedKeys; missing
// or invalid signatures are always rejected regardless of require_signed_adhoc.
//
// Inline (ad-hoc) commands (Issue #3694): operator-signature verification is now
// mandatory and unconditional — the prior "skip verification when require_signed_adhoc
// is false" branch is gone. An inline command is the only execution path that reaches
// a steward with no library-script trust check at all, so making its enforcement
// configurable made it the weakest link; require_signed_adhoc no longer gates it. The
// signature must be over operatorpayload.CanonicalBytes of the reconstructed envelope
// (content, shell, targets, nonce, expiry) — a signature computed over content alone
// (the pre-#3694 format) does not verify against these bytes and is rejected. The
// envelope must also name this steward's own ID in Targets, must not be expired, and
// its nonce must not have been seen before (independent of the outer SignedCommand's
// own replay window — see envelopeNonceCache).
func (h *Handler) preflightScriptSignature(cmd *cpTypes.Command) error {
	scriptID, _ := cmd.Params["script_id"].(string)
	sigAlgorithm, _ := cmd.Params["signature_algorithm"].(string)
	sigValue, _ := cmd.Params["signature_value"].(string)
	sigPublicKey, _ := cmd.Params["signature_public_key"].(string)
	shellStr, _ := cmd.Params["shell"].(string)
	scriptContentB64, _ := cmd.Params["script_content"].(string)

	isLibraryScript := scriptID != ""

	// Decode base64 content. Fail closed for library scripts and for inline commands
	// that carry a require_signed_adhoc-independent mandatory check; the legacy
	// fail-open branch is retained only for the case require_signed_adhoc reports
	// (a malformed inline payload that would fail identically when actually executed).
	contentBytes, err := base64.StdEncoding.DecodeString(scriptContentB64)
	if err != nil {
		if isLibraryScript || h.requireSignedAdhoc {
			return fmt.Errorf("%w: invalid script_content encoding", ErrUnauthenticatedCommand)
		}
		return nil
	}

	hasSig := sigAlgorithm != "" && sigValue != "" && sigPublicKey != ""

	if isLibraryScript {
		// Library scripts always require a valid CI signature via TrustedKeys mode.
		// TrustModeAnyValid would accept any attacker key — explicitly use TrustedKeys.
		if !hasSig {
			return fmt.Errorf("%w: library script requires a script signature", ErrUnauthenticatedCommand)
		}
		// Thumbprint is computed from the actual public key material — never from params,
		// which are attacker-controlled. Using sig.Thumbprint from params would let an
		// attacker set thumbprint to a trusted value while signing with an untrusted key.
		sig := &script.ScriptSignature{
			Algorithm:  sigAlgorithm,
			Signature:  sigValue,
			PublicKey:  sigPublicKey,
			Thumbprint: computeThumbprintFromPEM(sigPublicKey),
		}
		libraryCfg := script.ModuleSigningConfig{
			TrustMode:   script.TrustModeTrustedKeys,
			TrustedKeys: h.signingConfig.TrustedKeys,
		}
		if err := script.VerifyScriptSignature(contentBytes, sig, script.ShellType(shellStr), libraryCfg); err != nil {
			return fmt.Errorf("%w: library script verification failed: %v", ErrUnauthenticatedCommand, err)
		}
		return nil
	}

	// Inline ad-hoc command: operator-envelope verification is mandatory, over either
	// credential type (Issue #3697 adds the WebAuthn branch alongside X.509).
	webauthnAuthDataB64, _ := cmd.Params["webauthn_authenticator_data"].(string)
	webauthnClientDataB64, _ := cmd.Params["webauthn_client_data_json"].(string)
	webauthnSigB64, _ := cmd.Params["webauthn_signature"].(string)
	webauthnCredIDB64, _ := cmd.Params["webauthn_credential_id"].(string)
	webauthnManifestJSON, _ := cmd.Params["webauthn_manifest"].(string)
	hasWebAuthn := webauthnAuthDataB64 != "" && webauthnClientDataB64 != "" && webauthnSigB64 != "" && webauthnCredIDB64 != ""

	if !hasSig && !hasWebAuthn {
		return ErrUnauthenticatedCommand
	}

	targets := extractStringSlice(cmd.Params["targets"])
	nonce, _ := cmd.Params["nonce"].(string)
	expiresAtStr, _ := cmd.Params["expires_at"].(string)
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return fmt.Errorf("%w: missing or invalid operator envelope expiry", ErrUnauthenticatedCommand)
	}

	envelope := operatorpayload.Envelope{
		Content:   contentBytes,
		Shell:     shellStr,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}

	if hasSig {
		if err := h.verifyX509OperatorSignature(envelope, shellStr, sigAlgorithm, sigValue, sigPublicKey); err != nil {
			return err
		}
	} else {
		if err := h.verifyWebAuthnOperatorSignature(envelope,
			webauthnAuthDataB64, webauthnClientDataB64, webauthnSigB64, webauthnCredIDB64, webauthnManifestJSON); err != nil {
			return err
		}
	}

	// Target-set binding (Issue #3694): this steward's own ID must be among the
	// resolved, signed target list — a legitimately-signed envelope re-addressed to a
	// different target set in transit does not authorize execution here.
	targeted := false
	for _, target := range targets {
		if target == h.stewardID {
			targeted = true
			break
		}
	}
	if !targeted {
		return fmt.Errorf("%w: steward is not in the signed target list", ErrUnauthenticatedCommand)
	}

	// Expiry (Issue #3694): reject an envelope past its bound validity window.
	if time.Now().After(expiresAt) {
		return fmt.Errorf("%w: operator envelope has expired", ErrUnauthenticatedCommand)
	}

	// Nonce replay (Issue #3694): single-use, independent of the outer SignedCommand's
	// own replay window (handler.go's replayCache, keyed by cmd.ID) — a captured
	// operator-signed envelope re-wrapped in a fresh outer command (new ID, new
	// timestamp) is still caught here because the nonce is bound into what the
	// operator actually signed.
	if !h.envelopeNonceCache.Add(nonce) {
		return fmt.Errorf("%w: operator envelope nonce already used", ErrUnauthenticatedCommand)
	}

	return nil
}

// verifyX509OperatorSignature performs the mTLS/CSR-credential inline verification
// (Issue #3694/#3696): a raw signature over the canonical envelope bytes, then CA-chain
// and payload-signing-marker verification of the operator certificate.
func (h *Handler) verifyX509OperatorSignature(envelope operatorpayload.Envelope, shellStr, sigAlgorithm, sigValue, sigPublicKey string) error {
	canonicalBytes, err := operatorpayload.CanonicalBytes(envelope)
	if err != nil {
		return fmt.Errorf("%w: invalid operator envelope: %v", ErrUnauthenticatedCommand, err)
	}

	sig := &script.ScriptSignature{
		Algorithm: sigAlgorithm,
		Signature: sigValue,
		PublicKey: sigPublicKey,
	}
	// Cryptographic verification over the canonical envelope bytes — NOT raw content —
	// with any_valid mode; CA chain and marker check is separate below. Reusing
	// VerifyScriptSignature unmodified is deliberate (Issue #3694 Implementation
	// Notes): only the bytes fed to it change. A signature computed over content alone
	// (the pre-#3694 wire format) does not verify here, because contentBytes is only
	// one component of canonicalBytes.
	inlineCfg := script.ModuleSigningConfig{
		TrustMode: script.TrustModeAnyValid,
	}
	if err := script.VerifyScriptSignature(canonicalBytes, sig, script.ShellType(shellStr), inlineCfg); err != nil {
		return fmt.Errorf("%w: inline script verification failed: %v", ErrUnauthenticatedCommand, err)
	}

	// Operator credential verification: the signing credential must be trusted and
	// carry payload-signing authority. Skipped when no CA roots are configured (e.g.
	// standalone mode or tests without a controller CA) — same as before #3694.
	// Routed through OperatorCredentialVerifier (Issue #3694 Implementation Notes):
	// x509OperatorCredentialVerifier and webauthnOperatorCredentialVerifier
	// (webauthn_credential_verifier.go, Issue #3697) are its two implementations.
	if h.controllerCARoots != nil {
		credVerifier := OperatorCredentialVerifier(&x509OperatorCredentialVerifier{
			caRoots:            h.controllerCARoots,
			revocationVerifier: h.revocationVerifier,
		})
		if err := credVerifier.Verify(envelope, []byte(sigPublicKey)); err != nil {
			return fmt.Errorf("%w: operator cert: %v", ErrUnauthenticatedCommand, err)
		}
	}
	return nil
}

// verifyWebAuthnOperatorSignature verifies a WebAuthn-signed operator envelope (Issue
// #3697) via webauthnOperatorCredentialVerifier (webauthn_credential_verifier.go).
// Unlike verifyX509OperatorSignature, there is no "any_valid, no CA roots configured"
// relaxation: a WebAuthn credential's public key has no source other than the
// CA-verified manifest carried in webauthnManifestJSON, so this fails closed when no CA
// roots are configured rather than silently skipping verification
// (TestExecuteScriptHandler_WebAuthnSignedPayload_NoCARoots_Rejected asserts that
// branch directly, so a regression back to fail-open cannot ship unnoticed).
//
// The steward's own tenant path and its manifest freshness high-water mark are passed to
// the verifier: the roster is fleet-wide, so the entry's tenant must cover this steward,
// and a manifest older than one already accepted here must not resurrect a credential
// that has since been removed from the roster.
func (h *Handler) verifyWebAuthnOperatorSignature(envelope operatorpayload.Envelope, authDataB64, clientDataB64, sigB64, credIDB64, manifestJSON string) error {
	if h.controllerCARoots == nil {
		return fmt.Errorf("%w: webauthn verification requires a configured controller CA", ErrUnauthenticatedCommand)
	}

	authData, err := base64.StdEncoding.DecodeString(authDataB64)
	if err != nil {
		return fmt.Errorf("%w: invalid webauthn authenticator_data encoding", ErrUnauthenticatedCommand)
	}
	clientDataJSON, err := base64.StdEncoding.DecodeString(clientDataB64)
	if err != nil {
		return fmt.Errorf("%w: invalid webauthn client_data_json encoding", ErrUnauthenticatedCommand)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: invalid webauthn signature encoding", ErrUnauthenticatedCommand)
	}
	credID, err := base64.StdEncoding.DecodeString(credIDB64)
	if err != nil {
		return fmt.Errorf("%w: invalid webauthn credential_id encoding", ErrUnauthenticatedCommand)
	}

	proof, err := json.Marshal(webauthnAssertionProof{
		AuthenticatorData:  authData,
		ClientDataJSON:     clientDataJSON,
		Signature:          sigBytes,
		CredentialID:       credID,
		SignedManifestJSON: manifestJSON,
	})
	if err != nil {
		return fmt.Errorf("%w: failed to build webauthn proof: %v", ErrUnauthenticatedCommand, err)
	}

	credVerifier := OperatorCredentialVerifier(&webauthnOperatorCredentialVerifier{
		caRoots:       h.controllerCARoots,
		stewardTenant: h.tenantID,
		freshness:     h.webauthnManifestFloor,
	})
	if err := credVerifier.Verify(envelope, proof); err != nil {
		return fmt.Errorf("%w: webauthn credential: %v", ErrUnauthenticatedCommand, err)
	}
	return nil
}

// computeThumbprintFromPEM returns hex(sha256(DER)) of the first PEM block in pemStr.
// Works for both X.509 certificates and PKIX public keys — block.Bytes is the raw DER
// in both cases. Returns empty string when pemStr contains no valid PEM block.
func computeThumbprintFromPEM(pemStr string) string {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// extractStringSlice converts an interface{} value (as stored in cmd.Params after
// JSON deserialisation) to []string. Accepts []interface{} (from JSON) or []string.
func extractStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	if s, ok := v.([]interface{}); ok {
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok && str != "" {
				result = append(result, str)
			}
		}
		return result
	}
	if s, ok := v.([]string); ok {
		return s
	}
	return nil
}

// mergeEnv merges additional key-value pairs into base, returning a new map.
// base may be nil.
func mergeEnv(base, additional map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(additional))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range additional {
		out[k] = v
	}
	return out
}

// OperatorCredentialVerifier verifies that an operator credential (proof) authorizes
// envelope. It is the seam Issue #3694's Implementation Notes call for: two
// implementations exist — x509OperatorCredentialVerifier wraps the X.509 certificate
// check, whose marker requirement Issue #3696 switched from the admin-bundle marker to
// the CSR-issued payload-signing marker, and webauthnOperatorCredentialVerifier
// (webauthn_credential_verifier.go, Issue #3697) verifies a WebAuthn assertion for the
// browser-only-operator path — preflightScriptSignature calls through this interface
// rather than a single hardcoded verification path so neither change requires
// touching it again.
type OperatorCredentialVerifier interface {
	// Verify reports whether proof authorizes envelope under this credential type.
	Verify(envelope operatorpayload.Envelope, proof []byte) error
}

// x509OperatorCredentialVerifier is the current OperatorCredentialVerifier
// implementation: proof is the PEM-encoded operator certificate (signature_public_key),
// verified against caRoots with the payload-signing marker check (verifyOperatorCert,
// HasPayloadSigningMarker per Issue #3696 — the admin-bundle marker no longer qualifies
// a certificate to sign an operator payload). It does not use envelope: the
// cryptographic binding of the envelope to the signature is verified separately, by
// script.VerifyScriptSignature, before this is ever called.
type x509OperatorCredentialVerifier struct {
	caRoots *x509.CertPool

	// revocationVerifier answers whether the certificate's serial has been revoked
	// (Issue #3699). Nil disables the check — the same degrade-safe default as an
	// unconfigured controllerCARoots elsewhere in this file.
	revocationVerifier *operatorroster.RevocationVerifier
}

func (v *x509OperatorCredentialVerifier) Verify(_ operatorpayload.Envelope, proof []byte) error {
	return verifyOperatorCert(string(proof), v.caRoots, v.revocationVerifier)
}

// verifyOperatorCert parses publicKeyPEM as an X.509 certificate and verifies that it
// chains to caRoots with client-auth EKU, has not expired, carries the CFGMS
// payload-signing marker (Issue #3696), and has not been revoked (Issue #3699). An
// admin-bundle certificate — carrying AdminMarkerOID but not PayloadSigningMarkerOID —
// chains and has the right EKU but is rejected here: it authenticates mTLS transport,
// not operator payload signing.
func verifyOperatorCert(publicKeyPEM string, caRoots *x509.CertPool, revocationVerifier *operatorroster.RevocationVerifier) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("no PEM block found in signature_public_key")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	opts := x509.VerifyOptions{
		Roots:     caRoots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := parsedCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification: %w", err)
	}
	if !cert.HasPayloadSigningMarker(parsedCert) {
		return fmt.Errorf("operator certificate is not a payload-signing certificate")
	}
	if revocationVerifier != nil && revocationVerifier.IsRevoked(parsedCert.SerialNumber.String()) {
		return fmt.Errorf("operator certificate has been revoked")
	}
	return nil
}
