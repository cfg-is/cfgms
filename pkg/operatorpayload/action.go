// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package operatorpayload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"
)

// ActionShell is the Envelope.Shell value for an operator-signed steward action.
// CanonicalBytes requires a non-empty shell, and the shell is part of the signed
// bytes. It is deliberately NOT a member of the script shell allow-list and not a
// valid script shell: a signature made for a steward action can never authorize a
// script execution, and the reverse, because the shell differs in the signed bytes.
const ActionShell = "steward-action"

// ActionEnvelopeMaxTTL is the longest validity window an action envelope may carry.
// It equals the existing sign ceremony's expiry (operatorPayloadSignExpiryTTL). The
// shorter bound on a stale action lives on the queue entry, not on the envelope. The
// steward-action handler, not the shared envelope verifier, applies this ceiling.
const ActionEnvelopeMaxTTL = 5 * time.Minute

// actionContentVersion is the versioned prefix field ("v") of the action content.
const actionContentVersion = 1

// Action is what an operator signs for a steward action: the verb, the kind and name
// of its target, and its parameters. Binding all of them into the signed envelope
// stops the controller altering them in transit.
type Action struct {
	Verb       string
	TargetKind string
	TargetName string
	Parameters map[string]string
}

// actionContent fixes the key order of the canonical JSON. Parameter keys are sorted by
// encoding/json when it marshals a map.
type actionContent struct {
	V          int               `json:"v"`
	Verb       string            `json:"verb"`
	TargetKind string            `json:"target_kind"`
	TargetName string            `json:"target_name"`
	Parameters map[string]string `json:"parameters"`
}

// ActionContent returns the deterministic canonical JSON an operator signs as
// Envelope.Content for a, with Envelope.Shell set to ActionShell: a fixed key order,
// sorted parameter keys, no insignificant whitespace, and a leading "v":1 field.
//
// It rejects an empty verb, target kind or target name, an empty parameter key, and
// any field containing a control character.
func ActionContent(a Action) ([]byte, error) {
	for _, f := range []struct{ name, value string }{
		{"verb", a.Verb},
		{"target kind", a.TargetKind},
		{"target name", a.TargetName},
	} {
		if f.value == "" {
			return nil, fmt.Errorf("%w: action %s is empty", ErrInvalidEnvelope, f.name)
		}
		if err := rejectControlChars(f.name, f.value); err != nil {
			return nil, err
		}
	}
	params := make(map[string]string, len(a.Parameters))
	for k, v := range a.Parameters {
		if k == "" {
			return nil, fmt.Errorf("%w: action parameter key is empty", ErrInvalidEnvelope)
		}
		if err := rejectControlChars("parameter key", k); err != nil {
			return nil, err
		}
		if err := rejectControlChars("parameter value", v); err != nil {
			return nil, err
		}
		params[k] = v
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(actionContent{
		V:          actionContentVersion,
		Verb:       a.Verb,
		TargetKind: a.TargetKind,
		TargetName: a.TargetName,
		Parameters: params,
	}); err != nil {
		return nil, fmt.Errorf("%w: encode action: %v", ErrInvalidEnvelope, err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func rejectControlChars(name, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: action %s is not valid UTF-8", ErrInvalidEnvelope, name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: action %s contains a control character", ErrInvalidEnvelope, name)
		}
	}
	return nil
}
