// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"github.com/cfgis/cfgms/pkg/audit"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newProvenanceChecker builds the admission-time provenance checker (ADR-034
// §2) over the fleet steward store: it scores a connecting host's attributes
// against the approved baseline with registration.ProvenanceMatcher at
// registration.ProvenanceMatchThreshold, records the baseline on first
// admission, and audits a divergence as steward_provenance_divergence.
//
// A store error never refuses a connection: the check fails toward the
// pre-provenance behaviour (admit as unknown), because the revocation and
// approval gates that precede it are the ones that fail closed.
func newProvenanceChecker(store business.StewardStore, auditManager *audit.Manager, logger logging.Logger) grpcCP.ProvenanceChecker {
	return grpcCP.NewStewardStoreProvenanceChecker(store, auditManager, logger)
}
