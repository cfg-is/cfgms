// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package client exercises the CommandExecuteScript handler registered in setupCommandHandler.
//
// Issue #1669: setupCommandHandler must call handler.RegisterExecuteScriptHandler()
// so a controller-sent execute_script command is dispatched through the script
// module executor and produces EventScriptCompleted — not EventCommandFailed
// ("no handler for command type").
package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/cert"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// platformShell returns a shell supported by the current OS. bash is unavailable
// on Windows runners, so Windows uses powershell; both are recognised by the
// script-module executor (Issue #1669).
func platformShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// echoScriptBody returns a script body that writes s to stdout using the syntax
// of the current platform's shell (see platformShell).
func echoScriptBody(s string) string {
	if runtime.GOOS == "windows" {
		return "Write-Output '" + s + "'"
	}
	return "echo '" + s + "'"
}

// signedInlineExecuteScriptParams builds the cmd.Params entries
// preflightScriptSignature requires for an inline (ad-hoc) command as of Issue
// #3694: script_content, shell, execution_id, plus a valid operator envelope —
// targeted at stewardID, a fresh nonce, and a 5-minute expiry — signed by an
// operator certificate (payload-signing marker) issued by a test CA. The handler
// refuses inline commands when it has no controller CA roots (Issue #5356), so the
// result also carries the CA PEM the steward must trust, plus a controller signing
// certificate and signer: once a CA is configured the steward verifies the outer
// command signature too.
type inlineExecuteScriptFixture struct {
	params         map[string]interface{}
	caPEM          string
	signingCertPEM string
	signer         signature.Signer
}

func signedInlineExecuteScriptParams(t *testing.T, content []byte, shell, stewardID, executionID string) inlineExecuteScriptFixture {
	t.Helper()
	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "Test Controller CA",
		Country:      "US",
		ValidityDays: 365,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))
	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	signingCert, err := ca.GenerateSigningCertificate(&cert.SigningCertConfig{
		CommonName:   "controller-signing-test",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	signer, err := signature.NewSigner(&signature.SignerConfig{
		PrivateKeyPEM:  signingCert.PrivateKeyPEM,
		CertificatePEM: signingCert.CertificatePEM,
	})
	require.NoError(t, err)

	operator, err := ca.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "operator.test",
		ValidityDays:     365,
		KeySize:          2048,
		TemplateModifier: cert.SetPayloadSigningMarker,
	})
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(operator.PrivateKeyPEM)
	require.NotNil(t, keyBlock)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)

	nonceBytes := make([]byte, 16)
	_, err = rand.Read(nonceBytes)
	require.NoError(t, err)

	env := operatorpayload.Envelope{
		Content:   content,
		Shell:     shell,
		Targets:   []string{stewardID},
		Nonce:     hex.EncodeToString(nonceBytes),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	canonical, err := operatorpayload.CanonicalBytes(env)
	require.NoError(t, err)

	digest := sha256.Sum256(canonical)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)

	params := map[string]interface{}{
		"script_content":       base64.StdEncoding.EncodeToString(content),
		"shell":                shell,
		"execution_id":         executionID,
		"signature_algorithm":  "rsa-sha256",
		"signature_value":      base64.StdEncoding.EncodeToString(sigBytes),
		"signature_public_key": string(operator.CertificatePEM),
		"targets":              env.Targets,
		"nonce":                env.Nonce,
		"expires_at":           env.ExpiresAt.UTC().Format(time.RFC3339),
	}
	return inlineExecuteScriptFixture{
		params:         params,
		caPEM:          string(caPEM),
		signingCertPEM: string(signingCert.CertificatePEM),
		signer:         signer,
	}
}

// TestSetupCommandHandler_RegistersExecuteScript verifies that the command
// handler built by setupCommandHandler dispatches CommandExecuteScript through
// the production registration path. A real TransportClient with an in-process
// eventCapture control plane is used — no mocks (Issue #1669).
func TestSetupCommandHandler_RegistersExecuteScript(t *testing.T) {
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	fx := signedInlineExecuteScriptParams(t, []byte(echoScriptBody("hello")), platformShell(),
		"steward-exec-script", "exec-1669-test")

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, newTestSession(), exec, capture, "steward-exec-script", "tenant-exec-script")
	c.mu.Lock()
	c.caCertPEM = fx.caPEM
	c.signingCertPEMs = []string{fx.signingCertPEM}
	c.mu.Unlock()

	handler, err := c.setupCommandHandler(context.Background(), "steward-exec-script")
	require.NoError(t, err)

	cmd := &cpTypes.Command{
		ID:        "cmd-exec-script-1",
		Type:      cpTypes.CommandExecuteScript,
		StewardID: "steward-exec-script",
		TenantID:  "tenant-exec-script",
		Timestamp: time.Now(),
		Params:    fx.params,
	}
	cmd.SigningPayloadVersion = cpTypes.SigningPayloadV2
	signingBytes, err := cpTypes.CommandSigningBytesVersion(cmd, cpTypes.InterfaceParamsToStringMap(cmd.Params), cpTypes.SigningPayloadV2)
	require.NoError(t, err)
	sig, err := fx.signer.Sign(signingBytes)
	require.NoError(t, err)
	signed := &cpTypes.SignedCommand{Command: *cmd, Signature: sig}
	require.NoError(t, handler.HandleCommand(context.Background(), signed))
	handler.Wait()

	events := drainEvents(capture.events)
	require.NotEmpty(t, events, "execute_script dispatch must publish a status event")

	var completed *cpTypes.Event
	for _, evt := range events {
		require.NotEqualf(t, cpTypes.EventCommandFailed, evt.Type,
			"execute_script must be registered in setupCommandHandler — got EventCommandFailed: %v", evt.Details)
		if evt.Type == cpTypes.EventScriptCompleted {
			completed = evt
		}
	}
	require.NotNil(t, completed, "execute_script dispatch must publish EventScriptCompleted")
	require.Equal(t, "exec-1669-test", completed.Details["execution_id"])
	require.Equal(t, 0, completed.Details["exit_code"])
}
