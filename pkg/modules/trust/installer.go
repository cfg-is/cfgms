// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust

import (
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// installerMessageDomain is the fixed domain tag that starts every installer message.
// A steward-binary message starts with a hex content hash, which can never equal this
// tag, so no installer message can equal any StewardBinaryMessage output and the
// reverse. A signature for one artifact class therefore never verifies for the other.
const installerMessageDomain = "cfgms-installer-v2"

// InstallerMessage returns the canonical Ed25519 message for an installer-artifact
// publisher signature: cfgms-installer-v2|contentHash|version|platform|arch.
//
// The version is the steward release version, canonicalized like StewardBinaryMessage
// (a leading "v" is added when absent), so a signature binds the release coordinate
// and an older signed installer cannot be passed off as a newer one. Empty fields and
// fields containing the separator return ErrInvalidSignatureMessage.
func InstallerMessage(contentHash, version, platform, arch string) (string, error) {
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
	return strings.Join([]string{installerMessageDomain, contentHash, canonicalStewardBinaryVersion(version), platform, arch}, stewardBinaryMessageSep), nil
}

// VerifyInstallerSignature verifies a publisher signature over the canonical
// (contentHash, version, platform, arch) installer message. The caller must pass a content
// hash it computed itself from the bytes it is about to store.
func VerifyInstallerSignature(contentHash, version, platform, arch string, sig bundle.BundleSignature, store TrustStore) error {
	message, err := InstallerMessage(contentHash, version, platform, arch)
	if err != nil {
		return err
	}
	return verifySignatureOverContentHash(message, sig, store)
}
