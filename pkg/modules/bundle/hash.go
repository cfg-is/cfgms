// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package bundle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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

// contentHashFormatTag versions the byte stream fed into the content-hash digest.
const contentHashFormatTag = "cfgms-module-content-v1"

// platformKeys is the os-arch allowlist: windows|darwin|linux x amd64|arm64.
var platformKeys = map[string]struct{}{
	"windows-amd64": {}, "windows-arm64": {},
	"darwin-amd64": {}, "darwin-arm64": {},
	"linux-amd64": {}, "linux-arm64": {},
}

// ValidPlatformKey reports whether key is an allowed os-arch binary key.
func ValidPlatformKey(key string) bool {
	_, ok := platformKeys[key]
	return ok
}

// ComputeContentHash hashes each binary with SHA-256 and delegates to
// ComputeContentHashFromDigests.
func ComputeContentHash(binaries map[string][]byte, manifestBytes []byte) (string, error) {
	digests := make(map[string][32]byte, len(binaries))
	for k, v := range binaries {
		digests[k] = sha256.Sum256(v)
	}
	return ComputeContentHashFromDigests(digests, manifestBytes)
}

// ComputeContentHashFromDigests is the only code that feeds bytes into the
// content-hash digest. The hashed stream is length-framed so no two distinct inputs
// share a byte stream: the format tag; then for each entry sorted by key, a
// uint32 big-endian length-prefixed os-arch key followed by its fixed-width 32-byte
// SHA-256 digest; then the uint64 big-endian length-prefixed manifest bytes.
// A holder of the digests can therefore recompute the hash without the binaries.
// Keys must be unique allowlisted os-arch keys (see ValidPlatformKey); Go maps
// cannot hold duplicate keys, so uniqueness is structural.
func ComputeContentHashFromDigests(digests map[string][32]byte, manifestBytes []byte) (string, error) {
	keys := make([]string, 0, len(digests))
	for k := range digests {
		if !ValidPlatformKey(k) {
			return "", fmt.Errorf("bundle: platform key %q is not an allowed os-arch key", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	h.Write([]byte(contentHashFormatTag))
	var n4 [4]byte
	for _, k := range keys {
		binary.BigEndian.PutUint32(n4[:], uint32(len(k)))
		h.Write(n4[:])
		h.Write([]byte(k))
		d := digests[k]
		h.Write(d[:])
	}
	var n8 [8]byte
	binary.BigEndian.PutUint64(n8[:], uint64(len(manifestBytes)))
	h.Write(n8[:])
	h.Write(manifestBytes)

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
