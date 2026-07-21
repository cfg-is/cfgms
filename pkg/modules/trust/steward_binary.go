// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// ErrInvalidSignatureMessage is returned when steward-binary signature coordinates
// cannot form a canonical message — an empty field, or a field containing the
// reserved separator. It is deliberately a hard error rather than a sanitization:
// stripping the separator would let two distinct coordinate sets collide on one
// message, which is exactly the ambiguity the binding exists to remove.
var ErrInvalidSignatureMessage = errors.New("invalid steward binary signature message")

// stewardBinaryMessageSep separates the coordinates in the canonical message. It is
// absent from every legitimate field: content hashes are hex, versions match
// ^v\d+\.\d+\.\d+(-[a-zA-Z0-9][a-zA-Z0-9.-]*)?$, and platform/arch come from fixed
// allow-lists. Fields carrying it are rejected rather than escaped.
const stewardBinaryMessageSep = "|"

// StewardBinaryMessage returns the canonical Ed25519 message for a steward-binary
// publisher signature: contentHash|version|platform|arch.
//
// Binding the release coordinates — not just the content hash — is what closes the
// rollback gap (Issue #2834). With a content-hash-only signature, a compromised
// controller could serve a genuinely signed OLDER binary at a NEWER version's URL:
// the signature would verify, the SHA-256 would match, and the downgrade guard would
// be bypassed because the version is controller-attested rather than signed.
//
// The ONLY normalization applied is the leading "v" on the version. Anything that
// collapsed semantically distinct versions — lowercasing, stripping build metadata,
// treating v1.2.3-rc1 as v1.2.3 — would let one signature cover two releases and
// partially reopen the gap this function exists to close.
//
// All three steward-binary touch points (the publish signer, the controller's
// verify-on-upload, and the steward's verify) must derive their message from this
// single helper so the signed and verified bytes match exactly.
func StewardBinaryMessage(contentHash, version, platform, arch string) (string, error) {
	for _, f := range []struct{ name, value string }{
		{"content hash", contentHash},
		{"version", version},
		{"platform", platform},
		{"arch", arch},
	} {
		if f.value == "" {
			return "", fmt.Errorf("%w: %s is empty", ErrInvalidSignatureMessage, f.name)
		}
		if strings.Contains(f.value, stewardBinaryMessageSep) {
			return "", fmt.Errorf("%w: %s contains the reserved %q separator",
				ErrInvalidSignatureMessage, f.name, stewardBinaryMessageSep)
		}
	}

	return strings.Join([]string{
		contentHash,
		canonicalStewardBinaryVersion(version),
		platform,
		arch,
	}, stewardBinaryMessageSep), nil
}

// canonicalStewardBinaryVersion normalizes the leading "v" and nothing else, so that
// "0.9.41" and "v0.9.41" produce an identical message while every other distinction
// in the version string is preserved.
func canonicalStewardBinaryVersion(version string) string {
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

// VerifyStewardBinarySignature verifies a steward-binary publisher signature over the
// canonical (contentHash, version, platform, arch) message.
//
// The caller MUST pass coordinates it derived itself — the locally recomputed digest
// of the downloaded bytes and its own requested version / detected platform+arch —
// never values echoed back by the serving controller. Sourcing any coordinate from a
// controller-supplied header would let a compromised controller name the coordinates
// its old signature already covers, reopening the rollback path.
//
// The composite is carried in bundle.Bundle.ContentHash because VerifyBundleSignature
// signs that field verbatim. That shared primitive is intentionally left untouched: it
// also gates module auto-approval and steward module-execution trust, where bundles are
// multi-platform and sign the bare content hash. Confining the composite to this
// wrapper keeps already-published module bundles verifying.
func VerifyStewardBinarySignature(contentHash, version, platform, arch string, sig bundle.BundleSignature, store TrustStore) error {
	message, err := StewardBinaryMessage(contentHash, version, platform, arch)
	if err != nil {
		return err
	}
	return VerifyBundleSignature(&bundle.Bundle{ContentHash: message}, sig, store)
}
