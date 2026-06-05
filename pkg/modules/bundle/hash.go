// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import (
	"crypto/sha256"
	"encoding/base64"
	"sort"
)

// ContentAddress uniquely identifies a module bundle by publisher, name, version,
// and the deterministic hash of its binary content and manifest.
type ContentAddress struct {
	Publisher   string `yaml:"publisher" json:"publisher"`
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	ContentHash string `yaml:"content_hash" json:"content_hash"`
}

// ComputeContentHash produces a deterministic SHA-256 hash over binary content and
// the manifest YAML bytes.
//
// Determinism is achieved by sorting the (os-arch, binary-content) pairs
// lexicographically before hashing so the result is independent of map iteration
// order. The manifest bytes are hashed last, after all binaries.
func ComputeContentHash(binaries map[string][]byte, manifestBytes []byte) (string, error) {
	type entry struct {
		key     string
		content []byte
	}

	entries := make([]entry, 0, len(binaries))
	for k, v := range binaries {
		entries = append(entries, entry{key: k, content: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].key < entries[j].key
	})

	h := sha256.New()
	for _, e := range entries {
		h.Write([]byte(e.key))
		h.Write(e.content)
	}
	h.Write(manifestBytes)

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
