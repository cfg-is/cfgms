// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	"github.com/cfgis/cfgms/pkg/softauthn"
)

const (
	operatorPayloadSignBeginPath  = "/api/v1/operator-payload/sign/begin"
	operatorPayloadSignFinishPath = "/api/v1/operator-payload/sign/finish"

	// maxPasskeySignResponseBytes bounds each sign-ceremony response body read.
	maxPasskeySignResponseBytes = 1 << 20
)

// stewardExecPasskey is the value of `cfg steward exec --passkey`.
var stewardExecPasskey bool

func init() {
	stewardExecCmd.Flags().BoolVar(&stewardExecPasskey, "passkey", false, "Sign the command with a passkey from a software authenticator instead of the X.509 signing credential; requires --authenticator")
}

// errPasskeyNeedsAuthenticator is returned, before any network call, when --passkey
// is used without an authenticator: the sign ceremony needs the cookie session an
// authenticator login produces.
var errPasskeyNeedsAuthenticator = errors.New("--passkey requires --authenticator <name> (or CFGMS_AUTHENTICATOR): the operator-payload sign ceremony needs a web session from a software authenticator")

// checkPasskeyExecFlags refuses flag combinations --passkey cannot honour. It makes
// no network call and accepts everything when --passkey is not set.
func checkPasskeyExecFlags() error {
	if !stewardExecPasskey {
		return nil
	}
	if selectedAuthenticator() == "" {
		return errPasskeyNeedsAuthenticator
	}
	if signingCredentialSelector != "" {
		return errors.New("--passkey cannot be combined with --signing-credential: provide exactly one operator proof")
	}
	return nil
}

// passkeySignedEnvelope is the envelope the sign begin endpoint returns, in the
// controller's JSON view (operatorpayload.Envelope with JSON tags).
type passkeySignedEnvelope struct {
	Content          []byte    `json:"content"`
	Shell            string    `json:"shell"`
	Targets          []string  `json:"targets"`
	Nonce            string    `json:"nonce"`
	ExpiresAt        time.Time `json:"expires_at"`
	ExecutionContext string    `json:"execution_context,omitempty"`
}

func (e passkeySignedEnvelope) envelope() operatorpayload.Envelope {
	return operatorpayload.Envelope{
		Content:          e.Content,
		Shell:            e.Shell,
		Targets:          e.Targets,
		Nonce:            e.Nonce,
		ExpiresAt:        e.ExpiresAt,
		ExecutionContext: e.ExecutionContext,
	}
}

// passkeySignBeginResponse is the data of the sign begin response.
type passkeySignBeginResponse struct {
	Assertion json.RawMessage       `json:"assertion"`
	Envelope  passkeySignedEnvelope `json:"envelope"`
}

// passkeyWebAuthnProof is the `webauthn` object of POST /api/v1/runs/command: the
// raw assertion the sign finish endpoint returns.
type passkeyWebAuthnProof struct {
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
	CredentialID      []byte `json:"credential_id"`
}

// passkeyExecRequestBody runs the operator-payload sign ceremony with the selected
// software authenticator and returns the POST /api/v1/runs/command body that carries
// its proof: `webauthn` and no `signature`, with the targets, nonce and expiry of the
// envelope the controller issued. The body has no execution_context, so the steward's
// default execution context applies.
//
// resolvedIDs are the steward IDs this CLI resolved itself. The begin response is
// checked before the authenticator signs anything (see checkPasskeyBeginResponse); on
// a mismatch no finish call is made.
func passkeyExecRequestBody(ctx context.Context, client *APIClient, selector string, content []byte, shell string, resolvedIDs []string) (map[string]interface{}, error) {
	auth, err := loadSelectedSoftAuthenticator(ctx)
	if err != nil {
		return nil, err
	}

	begin, err := client.passkeySignBegin(ctx, selector, content, shell)
	if err != nil {
		return nil, err
	}
	if err := checkPasskeyBeginResponse(begin, content, shell, resolvedIDs); err != nil {
		return nil, err
	}

	assertion, err := auth.Assert(begin.Assertion)
	if err != nil {
		return nil, fmt.Errorf("passkey signing refused: %w", err)
	}
	proof, err := client.passkeySignFinish(ctx, assertion)
	if err != nil {
		return nil, err
	}

	env := begin.Envelope
	return map[string]interface{}{
		"target":     selector,
		"content":    base64.StdEncoding.EncodeToString(env.Content),
		"shell":      env.Shell,
		"webauthn":   proof,
		"targets":    env.Targets,
		"nonce":      env.Nonce,
		"expires_at": env.ExpiresAt.UTC().Format(time.RFC3339),
	}, nil
}

// loadSelectedSoftAuthenticator returns the software authenticator named by
// --authenticator / CFGMS_AUTHENTICATOR.
func loadSelectedSoftAuthenticator(ctx context.Context) (*softauthn.Authenticator, error) {
	name := selectedAuthenticator()
	if name == "" {
		return nil, errPasskeyNeedsAuthenticator
	}
	rec, err := loadRegisteredAuthenticator(ctx, name)
	if err != nil {
		return nil, err
	}
	return rec.authenticator()
}

// checkPasskeyBeginResponse refuses a begin response the signer must not sign: the
// content, shell or execution context differ from what was requested, a target is not
// one this CLI resolved, or the assertion challenge is not the challenge hash of the
// returned envelope. The signer signs only what it chose.
func checkPasskeyBeginResponse(begin *passkeySignBeginResponse, content []byte, shell string, resolvedIDs []string) error {
	env := begin.Envelope
	if !bytes.Equal(env.Content, content) {
		return errors.New("refusing to sign: the controller's envelope content differs from the requested command")
	}
	if env.Shell != shell {
		return errors.New("refusing to sign: the controller's envelope shell differs from the requested shell")
	}
	if env.ExecutionContext != "" {
		return errors.New("refusing to sign: the controller's envelope sets an execution context this command did not request")
	}
	if err := checkPasskeyBeginTargets(env.Targets, resolvedIDs); err != nil {
		return err
	}

	want, err := operatorpayload.ChallengeHash(env.envelope())
	if err != nil {
		return fmt.Errorf("refusing to sign: the controller's envelope is invalid: %w", err)
	}
	var opts protocol.CredentialAssertion
	if err := json.Unmarshal(begin.Assertion, &opts); err != nil {
		return errors.New("refusing to sign: the controller's assertion options are malformed")
	}
	if !bytes.Equal(opts.Response.Challenge, want[:]) {
		return errors.New("refusing to sign: the controller's challenge does not match its envelope")
	}
	return nil
}

// checkPasskeyBeginTargets refuses an envelope with no targets or with a target the CLI
// did not resolve itself.
func checkPasskeyBeginTargets(targets, resolvedIDs []string) error {
	if len(targets) == 0 {
		return errors.New("refusing to sign: the controller's envelope has no targets")
	}
	resolved := make(map[string]struct{}, len(resolvedIDs))
	for _, id := range resolvedIDs {
		resolved[id] = struct{}{}
	}
	for _, id := range targets {
		if _, ok := resolved[id]; !ok {
			return fmt.Errorf("refusing to sign: the controller's envelope targets steward %q, which this command did not resolve", logging.SanitizeLogValue(id))
		}
	}
	return nil
}

// passkeySignBegin calls POST /api/v1/operator-payload/sign/begin.
func (c *APIClient) passkeySignBegin(ctx context.Context, selector string, content []byte, shell string) (*passkeySignBeginResponse, error) {
	body, err := json.Marshal(map[string]interface{}{
		"selector": selector,
		"content":  content,
		"shell":    shell,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode sign request: %w", err)
	}
	var out passkeySignBeginResponse
	if err := c.passkeySignStep(ctx, operatorPayloadSignBeginPath, body, "begin", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// passkeySignFinish calls POST /api/v1/operator-payload/sign/finish with the signed
// assertion and returns the proof for the dispatch.
func (c *APIClient) passkeySignFinish(ctx context.Context, assertion []byte) (*passkeyWebAuthnProof, error) {
	var out passkeyWebAuthnProof
	if err := c.passkeySignStep(ctx, operatorPayloadSignFinishPath, assertion, "finish", &out); err != nil {
		return nil, err
	}
	if len(out.AuthenticatorData) == 0 || len(out.ClientDataJSON) == 0 || len(out.Signature) == 0 || len(out.CredentialID) == 0 {
		return nil, errors.New("passkey sign finish returned an incomplete proof")
	}
	return &out, nil
}

// passkeySignStep POSTs body to path and decodes the API envelope's data into out.
func (c *APIClient) passkeySignStep(ctx context.Context, path string, body []byte, step string, out interface{}) error {
	resp, err := c.doRequest(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("passkey sign %s failed: %w", step, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("passkey sign %s failed: %w", step, c.parseError(resp))
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPasskeySignResponseBytes))
	if err != nil {
		return fmt.Errorf("passkey sign %s failed: could not read the controller's response", step)
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Data) == 0 {
		return fmt.Errorf("passkey sign %s failed: the controller's response is malformed", step)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("passkey sign %s failed: the controller's response is malformed", step)
	}
	return nil
}
