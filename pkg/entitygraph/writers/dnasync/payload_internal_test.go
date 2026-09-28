// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Internal test for buildPayload's tenant-field stripping (Issue #4319). Lives
// in package dnasync (rather than dnasync_test) so it can call the unexported
// buildPayload directly, mirroring correlator/writer_internal_test.go.
package dnasync

import (
	"encoding/binary"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// encodeStringCanonMap builds a valid canonical byte encoding for a
// string-keyed map of string values, matching the wire format decodeMap/
// decodeValue expect. Self-contained (rather than importing the dnasync_test
// package's equivalent helper) since this file lives in package dnasync.
func encodeStringCanonMap(fields map[string]string) []byte {
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(fields))
	for k, v := range fields {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	var buf []byte
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(pairs)))
	buf = append(buf, hdr...)
	for _, p := range pairs {
		klen := make([]byte, 4)
		binary.BigEndian.PutUint32(klen, uint32(len(p.k)))
		buf = append(buf, klen...)
		buf = append(buf, p.k...)
		vlen := make([]byte, 4)
		binary.BigEndian.PutUint32(vlen, uint32(len(p.v)))
		buf = append(buf, 'S')
		buf = append(buf, vlen...)
		buf = append(buf, p.v...)
	}
	return buf
}

// TestBuildPayloadStripsAssertedTenantFields verifies that buildPayload
// unconditionally removes tenant_path/owning_tenant decoded from canonical
// bytes, mirroring how fragment_hash is derived rather than copied — a
// steward's fragment can decode either key just as easily as any other
// attribute, and neither may survive into the persisted payload.
func TestBuildPayloadStripsAssertedTenantFields(t *testing.T) {
	frag := &commonpb.Fragment{
		FragmentId: "file:/etc/hosts",
		Authority:  "enforcing-module:file",
		CanonicalBytes: encodeStringCanonMap(map[string]string{
			"tenant_path":   "root/should-not-survive",
			"owning_tenant": "root/should-not-survive-either",
			"state":         "present",
		}),
	}
	payload := buildPayload(frag, types.ConfidenceHigh)

	_, hasTenantPath := payload["tenant_path"]
	require.False(t, hasTenantPath, "tenant_path decoded from a fragment must never survive into the payload")
	_, hasOwningTenant := payload["owning_tenant"]
	require.False(t, hasOwningTenant, "owning_tenant decoded from a fragment must never survive into the payload")
}
