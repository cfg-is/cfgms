// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package operatorpayload

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WorkflowShell is the Envelope.Shell value for an operator-signed published workflow
// version. The shell is part of the signed bytes and is deliberately NOT a member of the
// script shell allow-list: a signature made to publish a workflow version can never
// authorize a script, a steward action or a terminal, nor the reverse. It must never
// join the script shell allow-list.
const WorkflowShell = "workflow-version"

// WorkflowEnvelopeMaxTTL bounds the publish ceremony only: the window between the
// controller issuing the WebAuthn challenge (begin) and the operator's assertion being
// accepted (finish). It equals ActionEnvelopeMaxTTL.
//
// It does NOT bound the stored signature. A published version's signature is kept
// long-term, and its validity is the hash binding to the exact version, so verifying a
// stored signature must not apply this TTL or compare ExpiresAt against the current time.
const WorkflowEnvelopeMaxTTL = ActionEnvelopeMaxTTL

// workflowContentVersion is the versioned prefix field ("v") of the workflow content.
const workflowContentVersion = 1

// workflowContentHashHexLen is the length of a hex-encoded SHA-256 digest.
const workflowContentHashHexLen = 64

// WorkflowVersion identifies the exact workflow version a tenant publishes. ContentHash
// is the lowercase hex SHA-256 of the canonical YAML of the workflow definition; this
// package takes it as input and does not compute it.
type WorkflowVersion struct {
	TenantID    string
	Name        string
	Version     string
	ContentHash string
}

// workflowContent fixes the key order of the canonical JSON.
type workflowContent struct {
	V           int    `json:"v"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
}

// validate rejects empty fields, control characters, invalid UTF-8, a malformed content
// hash and tenant IDs that cannot be an envelope target.
func (w WorkflowVersion) validate() error {
	for _, f := range []struct{ name, value string }{
		{"tenant ID", w.TenantID},
		{"name", w.Name},
		{"version", w.Version},
		{"content hash", w.ContentHash},
	} {
		if f.value == "" {
			return fmt.Errorf("%w: workflow %s is empty", ErrInvalidEnvelope, f.name)
		}
		if err := rejectControlChars("workflow "+f.name, f.value); err != nil {
			return err
		}
	}
	if err := requireCleanField("workflow tenant ID", w.TenantID); err != nil {
		return err
	}
	if strings.Contains(w.TenantID, envelopeTargetSep) {
		return fmt.Errorf("%w: workflow tenant ID contains the reserved %q separator",
			ErrInvalidEnvelope, envelopeTargetSep)
	}
	if len(w.ContentHash) != workflowContentHashHexLen || w.ContentHash != strings.ToLower(w.ContentHash) {
		return fmt.Errorf("%w: workflow content hash is not a lowercase hex SHA-256", ErrInvalidEnvelope)
	}
	if _, err := hex.DecodeString(w.ContentHash); err != nil {
		return fmt.Errorf("%w: workflow content hash is not a lowercase hex SHA-256", ErrInvalidEnvelope)
	}
	return nil
}

// WorkflowContent returns the deterministic canonical JSON an operator signs as
// Envelope.Content for w: a fixed key order, no insignificant whitespace and a leading
// "v":1 field.
func WorkflowContent(w WorkflowVersion) ([]byte, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(workflowContent{
		V:           workflowContentVersion,
		TenantID:    w.TenantID,
		Name:        w.Name,
		Version:     w.Version,
		ContentHash: w.ContentHash,
	}); err != nil {
		return nil, fmt.Errorf("%w: encode workflow: %v", ErrInvalidEnvelope, err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// WorkflowEnvelope returns the Envelope an operator signs to publish w. Targets is the
// single tenant ID, so a signature for tenant A cannot validate under tenant B. The
// canonical bytes and challenge hash come from CanonicalBytes and ChallengeHash.
//
// expiresAt bounds the ceremony only (see WorkflowEnvelopeMaxTTL); callers must not
// re-apply it when verifying a stored signature.
func WorkflowEnvelope(w WorkflowVersion, nonce string, expiresAt time.Time) (Envelope, error) {
	content, err := WorkflowContent(w)
	if err != nil {
		return Envelope{}, err
	}
	e := Envelope{
		Content:   content,
		Shell:     WorkflowShell,
		Targets:   []string{w.TenantID},
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}
	if _, err := CanonicalBytes(e); err != nil {
		return Envelope{}, err
	}
	return e, nil
}
