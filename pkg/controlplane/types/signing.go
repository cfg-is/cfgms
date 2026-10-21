// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import (
	"fmt"

	"github.com/cfgis/cfgms/features/config/signature"
)

// SignCommand wraps cmd in a SignedCommand and, when signer is non-nil, signs it
// over the term-covering v2 payload (#5285). This is the one signing path for
// outbound controller commands. The input command is not modified; the returned
// command carries SigningPayloadVersion = SigningPayloadV2.
func SignCommand(cmd *Command, signer signature.Signer) (*SignedCommand, error) {
	sc := &SignedCommand{Command: *cmd}
	sc.Command.SigningPayloadVersion = SigningPayloadV2
	if signer == nil {
		return sc, nil
	}
	// Sign the canonical form (string params + UTC timestamp) that survives the
	// proto round-trip without type mutations. See CommandSigningBytes for details.
	rawParams := InterfaceParamsToStringMap(sc.Command.Params)
	signBytes, err := CommandSigningBytesVersion(&sc.Command, rawParams, SigningPayloadV2)
	if err != nil {
		return nil, fmt.Errorf("marshal command for signing: %w", err)
	}
	sig, err := signer.Sign(signBytes)
	if err != nil {
		return nil, fmt.Errorf("sign command: %w", err)
	}
	sc.Signature = sig
	return sc, nil
}
