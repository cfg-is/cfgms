// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// scriptApprovalDomain separates script approval hashes from every other hash
// built with ApprovalDigest.
const scriptApprovalDomain = "cfgms/content-approval/script/v1"

// ApprovalDigest returns the hex SHA-256 over a domain prefix and an ordered
// list of fields. Every part is length-prefixed, so no two different inputs
// can produce the same byte stream by shifting bytes between neighbouring
// fields. It is the shared encoding behind the script and workflow approval
// hashes (ADR-036 section 2).
func ApprovalDigest(domain string, fields ...string) string {
	h := sha256.New()
	write := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	write(domain)
	for _, f := range fields {
		write(f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ScriptApprovalHash returns the hash an approval of a library script is bound
// to. It covers everything that changes what runs, not only the content hash:
// Shell, Timeout and the parameters schema (name, type, required, default,
// allowed values, DNA path) sit outside vs.Hash. The owner tenant is part of the
// hash, so an approval of one owner's script can never satisfy a lookup that
// resolved to another owner's script with identical content.
//
// Signature verification stays on Content only; this hash is never sent to a
// steward. It returns "" for a script without metadata or with an unencodable
// parameter default, which no approval record can carry.
func ScriptApprovalHash(ownerTenant string, vs *VersionedScript) string {
	if vs == nil || vs.Metadata == nil {
		return ""
	}
	m := vs.Metadata
	version := ""
	if m.Version != nil {
		version = m.Version.String()
	}
	params, ok := canonicalParameters(m.Parameters)
	if !ok {
		return ""
	}
	return ApprovalDigest(scriptApprovalDomain,
		ownerTenant,
		m.ID,
		version,
		vs.Hash,
		string(m.Shell),
		strconv.FormatInt(int64(m.Timeout), 10),
		params,
	)
}

// canonicalParameters encodes the parameters schema deterministically. Order is
// significant: a reordered schema is a different schema and fails closed.
// Description is documentation and does not affect execution.
func canonicalParameters(params []ScriptParameter) (string, bool) {
	type canonParam struct {
		Name          string   `json:"name"`
		Type          string   `json:"type"`
		Required      bool     `json:"required"`
		Default       any      `json:"default"`
		AllowedValues []string `json:"allowed_values"`
		DNAPath       string   `json:"dna_path"`
	}
	out := make([]canonParam, 0, len(params))
	for _, p := range params {
		allowed := p.AllowedValues
		if allowed == nil {
			allowed = []string{}
		}
		out = append(out, canonParam{p.Name, p.Type, p.Required, p.Default, allowed, p.DNAPath})
	}
	// json.Marshal sorts map keys, so a map-valued default encodes stably.
	b, err := json.Marshal(out)
	if err != nil {
		// An unencodable default cannot be canonicalised; the caller yields no
		// hash, which no approval record can carry.
		return "", false
	}
	return string(b), true
}
