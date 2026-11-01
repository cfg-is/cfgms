// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// probe prints the base64-encoded Ed25519 public key from CFGMSPublisherIdentity()
// to stdout. Used only by the publisher-key ldflags round-trip test in identity_test.go;
// not part of any shipped binary or public API.
package main

import (
	"encoding/base64"
	"fmt"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

func main() {
	fmt.Print(base64.StdEncoding.EncodeToString(trust.CFGMSPublisherIdentity().PublicKey))
}
