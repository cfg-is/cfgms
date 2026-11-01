// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	dataplaneInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// BulkSyncResponder runs the steward's real bulk-lane SYNC_DNA handler against a
// fixed set of fragments and an explicit data plane session. It exists so that
// controller-side integration tests drive the production steward code (not a
// re-implementation of it) across an in-process data plane; it adds no behavior.
type BulkSyncResponder struct {
	c *TransportClient
}

// NewBulkSyncResponder returns a responder for a steward holding fragments, of
// which those whose id starts with one of bulkKinds form the bulk lane.
func NewBulkSyncResponder(logger logging.Logger, stewardID, tenantID string, bulkKinds []string,
	session dataplaneInterfaces.DataPlaneSession, fragments []*commonpb.Fragment) *BulkSyncResponder {
	c := &TransportClient{
		stewardID: stewardID,
		tenantID:  tenantID,
		logger:    logger,
		bulkKinds: make(map[string]bool, len(bulkKinds)),
	}
	for _, k := range bulkKinds {
		c.bulkKinds[k] = true
	}
	c.mu.Lock()
	c.dataPlaneSession = session
	c.mu.Unlock()
	r := &BulkSyncResponder{c: c}
	r.SetFragments(fragments)
	return r
}

// SetFragments replaces the steward's fragment state, as a collection sweep does.
func (r *BulkSyncResponder) SetFragments(fragments []*commonpb.Fragment) {
	r.c.setCurrentDNAFragments(fragments)
}

// BulkRoot is the bulk root the steward reports on its heartbeat.
func (r *BulkSyncResponder) BulkRoot() string {
	r.c.dnaMu.RLock()
	defer r.c.dnaMu.RUnlock()
	return r.c.currentBulkRoot
}

// Handle answers one bulk-lane SYNC_DNA command.
func (r *BulkSyncResponder) Handle(ctx context.Context, session dataplaneInterfaces.DataPlaneSession, cmd *cpTypes.Command) error {
	mode, _ := cmd.Params[cpTypes.SyncDNAParamBulk].(string)
	return r.c.handleSyncDNABulk(ctx, session, r.c.stewardID, r.c.tenantID, cmd, mode)
}
