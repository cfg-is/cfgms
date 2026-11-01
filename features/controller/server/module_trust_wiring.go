// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Module trust store construction (Issue #4984). The trust store is built once at
// startup from the controller.cfg-only module_trust section; nothing at runtime
// adds, changes or removes a publisher.
package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// newModuleTrustStore builds the controller's module trust store: the publishers
// declared in controller.cfg plus the baked-in CFGMS identity when its key is
// usable (an unsigned development build carries a placeholder key and is left
// out). An empty module_trust section yields the CFGMS identity only. Any invalid
// declaration is a startup error.
func newModuleTrustStore(cfg *config.Config, logger logging.Logger) (trust.TrustStore, error) {
	declared, err := cfg.ModuleTrustPublishers()
	if err != nil {
		return nil, fmt.Errorf("invalid module_trust config: %w", err)
	}

	store := trust.NewInMemoryTrustStore()
	if cfgms := trust.CFGMSPublisherIdentity(); trust.IsUsableIdentityKey(cfgms) {
		if err := store.AddPublisher(cfgms); err != nil {
			return nil, fmt.Errorf("register CFGMS publisher identity: %w", err)
		}
		logger.Info("Module trust: baked-in publisher trusted",
			"publisher", logging.SanitizeLogValue(cfgms.Name),
			"key_fingerprint", moduleKeyFingerprint(cfgms.PublicKey))
	} else {
		logger.Warn("Module trust: baked-in CFGMS publisher key is not usable (unsigned build); only publishers declared in module_trust are trusted")
	}
	for _, id := range declared {
		if err := store.AddPublisher(id); err != nil {
			return nil, fmt.Errorf("register module_trust publisher: %w", err)
		}
		logger.Info("Module trust: publisher trusted from controller.cfg",
			"publisher", logging.SanitizeLogValue(id.Name),
			"key_fingerprint", moduleKeyFingerprint(id.PublicKey))
	}
	return store, nil
}

// moduleKeyFingerprint is the lowercase hex SHA-256 of the raw public key, the
// same value `cfg module pubkey` prints.
func moduleKeyFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
