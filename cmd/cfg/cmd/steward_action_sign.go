// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"fmt"

	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// buildAndSignActionEnvelope signs one operator envelope for a steward action. The
// content comes from operatorpayload.ActionContent, the shell is
// operatorpayload.ActionShell, and the signed targets are exactly stewardID, so the
// API's one-target rule holds. The expiry is operatorEnvelopeExpiry, which equals the
// API's operatorpayload.ActionEnvelopeMaxTTL. Every call draws a fresh nonce.
func buildAndSignActionEnvelope(action operatorpayload.Action, stewardID string) (*commandSignature, operatorpayload.Envelope, error) {
	content, err := operatorpayload.ActionContent(action)
	if err != nil {
		return nil, operatorpayload.Envelope{}, fmt.Errorf("build steward action: %w", err)
	}
	return buildAndSignEnvelope(content, operatorpayload.ActionShell, []string{stewardID})
}
