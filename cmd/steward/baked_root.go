// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cfgis/cfgms/features/steward/commands"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// ControllerRootFingerprints is the controller root CA fingerprint list baked
// in at build time via ldflags:
//
//	go build -ldflags "-X main.ControllerRootFingerprints=<fp>[,<fp>...]"
//
// Each entry is the lowercase hex SHA-256 of the root certificate DER (64 hex
// characters); at most maxBakedRoots entries. A locked steward verifies
// operator tools only against this list, never against trust material in the
// data folder. Empty means no baked root. This is the ONLY way to set the
// value: there is no environment, flag, config or file override.
var ControllerRootFingerprints string

const (
	maxBakedRoots    = 4
	bakedRootHexSize = 64
)

var (
	// errNoBakedRoot means no fingerprint was baked into this binary.
	errNoBakedRoot = errors.New("no controller root CA fingerprint baked into this binary")
	// errBakedRootMalformed means the baked value is not a valid fingerprint list.
	errBakedRootMalformed = errors.New("baked controller root CA fingerprint list is malformed")
)

// bakedRootFingerprints parses and validates ControllerRootFingerprints.
// Any error means the caller must treat the binary as having no baked root.
func bakedRootFingerprints() ([]string, error) {
	return parseBakedRootFingerprints(ControllerRootFingerprints)
}

func parseBakedRootFingerprints(raw string) ([]string, error) {
	if raw == "" {
		return nil, errNoBakedRoot
	}
	entries := strings.Split(raw, ",")
	if len(entries) > maxBakedRoots {
		return nil, fmt.Errorf("%w: more than %d entries", errBakedRootMalformed, maxBakedRoots)
	}
	for _, e := range entries {
		if len(e) != bakedRootHexSize {
			return nil, fmt.Errorf("%w: entry must be %d lowercase hex characters", errBakedRootMalformed, bakedRootHexSize)
		}
		for i := 0; i < len(e); i++ {
			c := e[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return nil, fmt.Errorf("%w: entry must be lowercase hex", errBakedRootMalformed)
			}
		}
	}
	return entries, nil
}

// matchesBakedRoot reports whether cert is a self-signed CA whose SHA-256
// fingerprint is in the baked list. It fails closed: any error is false.
func matchesBakedRoot(cert *x509.Certificate) bool {
	if !isSelfSignedCA(cert) {
		return false
	}
	fps, err := bakedRootFingerprints()
	if err != nil {
		return false
	}
	fp, err := computeCAPEMFingerprint(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	if err != nil {
		return false
	}
	return slices.Contains(fps, fp)
}

// bakedRootReason returns the locked-tools reason code for an unusable baked
// list, or "" when there is a usable baked root.
func bakedRootReason() string {
	_, err := bakedRootFingerprints()
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errNoBakedRoot):
		return cpTypes.ReasonCodeLockedNoBakedRoot
	default:
		return cpTypes.ReasonCodeLockedBakedRootMalformed
	}
}

func init() {
	// The repair path verifies its signer through commands.VerifyLockedSigner,
	// which never reads the baked list itself.
	commands.SetBakedRootMatcher(matchesBakedRoot)
}

// isSelfSignedCA reports whether cert is a non-empty CA certificate whose
// issuer equals its subject and whose signature verifies under its own key.
func isSelfSignedCA(cert *x509.Certificate) bool {
	if cert == nil || len(cert.Raw) == 0 {
		return false
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false
	}
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil
}

// bakedRootStatusLine renders the baked fingerprints for the status command,
// or "none" when there is no usable baked root.
func bakedRootStatusLine() string {
	fps, err := bakedRootFingerprints()
	if err != nil {
		return "none"
	}
	return strings.Join(fps, ",")
}
