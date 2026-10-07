// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types_test

import (
	"testing"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// FuzzParseEID fuzzes the hand-rolled ParseEID parser (eid.go:61), which splits
// on the first '/' and then on the first ':'. Covers all five registered
// authority types. Any panic is a bug; errors are expected for adversarial input.
func FuzzParseEID(f *testing.F) {
	// Seed corpus: valid EIDs covering all five registered authority types.
	seeds := []string{
		// host
		"host:web-01",
		"host:web-01/fragment-abc",
		"host:a1b2/file:/etc/hosts",
		"host:a1b2c3/service:sshd",
		// cluster
		"cluster:hv-east-guid",
		"cluster:k8s-prod/node:worker-3",
		// directory
		"directory:ldap-corp",
		"directory:ldap-corp/user:jdoe",
		// m365
		"m365:tenant-contoso",
		"m365:tenant-acme/device:laptop-01",
		// cfgms
		"cfgms:root",
		"cfgms:root/policy:baseline",
		// edge cases with long local IDs
		"host:srv-01/file:/var/log/syslog",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		eid, err := types.ParseEID(s)
		if err != nil {
			return
		}
		// Round-trip invariant: a successfully parsed EID must produce a string
		// that parses back to an equal EID.
		reparsed, err := types.ParseEID(eid.String())
		if err != nil {
			t.Fatalf("round-trip parse failed for %q (string=%q): %v", s, eid.String(), err)
		}
		if eid.String() != reparsed.String() {
			t.Fatalf("round-trip mismatch: original=%q reparsed=%q", eid.String(), reparsed.String())
		}
	})
}
