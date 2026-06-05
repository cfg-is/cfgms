// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust

import (
	"encoding/base64"
	"fmt"
)

// cfgmsPublisherPublicKey is the base64-encoded Ed25519 public key for the CFGMS
// publisher. This is a placeholder (32 zero bytes) for development builds.
//
// The real key is injected by the release pipeline at build time:
//
//	go build -ldflags "-X github.com/cfgis/cfgms/pkg/modules/trust.cfgmsPublisherPublicKey=<base64>"
//
// The variable (not const) declaration is required to allow ldflags injection.
var cfgmsPublisherPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// CFGMSPublisherIdentity returns the PublisherIdentity for the CFGMS module
// publisher, decoded from the package-level cfgmsPublisherPublicKey variable.
// Panics if the variable contains invalid base64 or the decoded key is not 32 bytes
// (which would indicate a broken build pipeline).
func CFGMSPublisherIdentity() PublisherIdentity {
	keyBytes, err := base64.StdEncoding.DecodeString(cfgmsPublisherPublicKey)
	if err != nil {
		panic(fmt.Sprintf("pkg/modules/trust: cfgmsPublisherPublicKey is not valid base64: %v", err))
	}
	if len(keyBytes) != 32 {
		panic(fmt.Sprintf("pkg/modules/trust: cfgmsPublisherPublicKey decoded to %d bytes, expected 32", len(keyBytes)))
	}
	return PublisherIdentity{
		Name:      "cfgms",
		PublicKey: keyBytes,
		Algorithm: algorithmEd25519,
	}
}
