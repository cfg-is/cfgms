// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/modules/script"
	scriptrelay "github.com/cfgis/cfgms/features/steward/script_relay"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

const (
	scriptPreviewMaxBytes   = 4096
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
	var relay *scriptrelay.Relay
	if len(requiredAPIScope) > 0 {
		r, err := scriptrelay.NewRelay(executionID, h.stewardID, h.sendStatus, h.logger)
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
		},
	})
	return nil
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
// Inline commands: verified only when require_signed_adhoc is true. When a signature
// is present, cryptographic verification and (when controllerCARoots is set) operator
// CA chain verification are performed.
func (h *Handler) preflightScriptSignature(cmd *cpTypes.Command) error {
	scriptID, _ := cmd.Params["script_id"].(string)
	sigAlgorithm, _ := cmd.Params["signature_algorithm"].(string)
	sigValue, _ := cmd.Params["signature_value"].(string)
	sigPublicKey, _ := cmd.Params["signature_public_key"].(string)
	shellStr, _ := cmd.Params["shell"].(string)
	scriptContentB64, _ := cmd.Params["script_content"].(string)

	isLibraryScript := scriptID != ""

	// Decode base64 content. Fail closed when signature enforcement is active; fail open
	// only for plain inline commands where require_signed_adhoc is false.
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

	// Inline command: enforce signature only when require_signed_adhoc is set.
	if !h.requireSignedAdhoc {
		return nil
	}
	if !hasSig {
		return ErrUnauthenticatedCommand
	}
	sig := &script.ScriptSignature{
		Algorithm: sigAlgorithm,
		Signature: sigValue,
		PublicKey: sigPublicKey,
	}
	// Cryptographic verification with any_valid mode; CA chain check is separate below.
	inlineCfg := script.ModuleSigningConfig{
		TrustMode: script.TrustModeAnyValid,
	}
	if err := script.VerifyScriptSignature(contentBytes, sig, script.ShellType(shellStr), inlineCfg); err != nil {
		return fmt.Errorf("%w: inline script verification failed: %v", ErrUnauthenticatedCommand, err)
	}
	// Operator cert chain verification: the signing cert must chain to the controller CA
	// with client-auth EKU and must not be expired. This check is skipped when no CA
	// roots are configured (e.g. standalone mode or tests without a controller CA).
	if h.controllerCARoots != nil {
		if err := verifyOperatorCert(sigPublicKey, h.controllerCARoots); err != nil {
			return fmt.Errorf("%w: operator cert: %v", ErrUnauthenticatedCommand, err)
		}
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

// verifyOperatorCert parses publicKeyPEM as an X.509 certificate and verifies that it
// chains to caRoots with client-auth EKU and has not expired.
func verifyOperatorCert(publicKeyPEM string, caRoots *x509.CertPool) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("no PEM block found in signature_public_key")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	opts := x509.VerifyOptions{
		Roots:     caRoots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification: %w", err)
	}
	return nil
}
