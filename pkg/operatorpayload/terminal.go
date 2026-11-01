// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package operatorpayload

import "fmt"

// TerminalShell is the Envelope.Shell value for an operator-signed request to open a
// terminal on a steward. The shell is part of the signed bytes, so a signature made
// for a terminal can never authorize a script execution or a steward action, nor the
// reverse. It must never join the script shell allow-list.
const TerminalShell = "terminal-open"

// TerminalVerb is the action verb bound into the terminal-open content.
const TerminalVerb = "terminal.open"

// TerminalEnvelopeMaxTTL is the longest validity window a terminal-open envelope may
// carry. It equals ActionEnvelopeMaxTTL.
const TerminalEnvelopeMaxTTL = ActionEnvelopeMaxTTL

// terminalTargetKind is the target kind of a terminal-open action.
const terminalTargetKind = "steward"

// TerminalContent returns the deterministic canonical JSON an operator signs as
// Envelope.Content, with Envelope.Shell set to TerminalShell, to open a terminal
// running shell on stewardID. It is built on ActionContent, so the canonical form and
// control-character rejection are shared; an empty steward ID or shell is rejected.
func TerminalContent(stewardID, shell string) ([]byte, error) {
	if shell == "" {
		return nil, fmt.Errorf("%w: terminal shell is empty", ErrInvalidEnvelope)
	}
	return ActionContent(Action{
		Verb:       TerminalVerb,
		TargetKind: terminalTargetKind,
		TargetName: stewardID,
		Parameters: map[string]string{"shell": shell},
	})
}
