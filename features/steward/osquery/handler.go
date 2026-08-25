// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package osquery implements the steward-side ad-hoc osquery query handler for
// Epic #2855 (Issue #3566).
//
// # Security invariants
//
//  1. Catalog-ID lookup and parameter validation happen together in a single
//     front-door admission step inside Execute. No code path reaches runQuery
//     having skipped either check.
//
//  2. Raw SQL is never accepted from the wire. The handler receives an
//     OsqueryQueryRequest carrying a catalog_id; SQL text is derived from the
//     bundle-embedded catalog after admission. A request without a recognised
//     catalog_id is rejected before any query text is touched.
//
//  3. Parameter values containing SQL metacharacters (', --, ;, UNION) are
//     rejected at admission for any parameter whose declared type does not
//     explicitly allow them — rejected, never escaped-and-passed.
//
//  4. Every osquery-derived result value logged for diagnostics goes through
//     logging.SanitizeLogValue before being included in a log entry.
//
// # Handler roles
//
// OsqueryHandler serves two roles in the system:
//
//   - Execute: the steward-side execution path. Receives an OsqueryQueryRequest,
//     runs the single front-door admission step (catalog lookup + parameter
//     validation), constructs the final SQL from the bundle-embedded catalog, and
//     delivers it to runQuery via stdin. Called by the steward's stream handler
//     for each OsqueryQueryRequest received from the controller.
//
//   - HandleGRPC: the controller-side stream handler. Called by
//     compositeTransportServer.OsqueryQuery when the steward opens the
//     OsqueryQuery bidi stream. Extracts the mTLS peer ID, registers the stream,
//     and manages the send/receive loop for the controller side.
package osquery

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	osquerymodule "github.com/cfgis/cfgms/features/modules/extended/osquery"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// OsqueryHandler validates catalog-query requests and executes them via runQuery
// on the steward side, and handles the controller-side OsqueryQuery gRPC stream.
//
// The front-door admission check (catalog-ID lookup + parameter validation)
// happens in Execute — a single, atomic step before any query text is constructed
// or runQuery is called. HandleGRPC delegates to Execute for each request
// received from the controller.
type OsqueryHandler struct {
	logger  logging.Logger
	binPath string // absolute path to the verified osquery binary on this host
}

// NewOsqueryHandler returns an OsqueryHandler. binPath is the verified osquery
// binary path returned by PreExecVerifier.VerifyBeforeExec; the handler does not
// re-verify on each Execute call (pre-exec verification is the caller's
// responsibility per Story #3561 / ADR-006).
func NewOsqueryHandler(logger logging.Logger, binPath string) *OsqueryHandler {
	return &OsqueryHandler{
		logger:  logger,
		binPath: binPath,
	}
}

// Execute is the steward-side request handler. It performs the front-door
// admission check — catalog-ID lookup and parameter validation in one atomic
// step — and only calls runQuery after both pass.
//
// Admission rejects:
//   - Unknown catalog IDs (no query text is constructed)
//   - Parameters not declared in the catalog entry's schema
//   - Parameter values containing SQL metacharacters for charset-typed params
//   - Missing required parameters
//
// On admission failure, Execute returns a non-nil error and nil rows without
// calling runQuery. On success, Execute returns the query result rows.
func (h *OsqueryHandler) Execute(ctx context.Context, req *transportpb.OsqueryQueryRequest) ([]*transportpb.OsqueryRow, error) {
	// === Front-door admission: catalog-ID lookup AND parameter validation ===
	// Both checks happen here, atomically, before any query text is accessed.
	entry, err := osquerymodule.LookupCatalogEntry(req.GetCatalogId())
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("osquery admission rejected: unknown catalog ID",
				"catalog_id", logging.SanitizeLogValue(req.GetCatalogId()))
		}
		return nil, status.Errorf(codes.InvalidArgument, "osquery: %s", err)
	}

	if err := osquerymodule.ValidateParams(entry, req.GetParams()); err != nil {
		if h.logger != nil {
			h.logger.Warn("osquery admission rejected: parameter validation failed",
				"catalog_id", logging.SanitizeLogValue(req.GetCatalogId()),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil, status.Errorf(codes.InvalidArgument, "osquery: %s", err)
	}
	// === Admission passed — construct query and call runQuery ===

	query := entry.BuildQuery(req.GetParams())
	rawRows, err := osquerymodule.RunQuery(ctx, h.binPath, query)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("osquery execution failed",
				"catalog_id", logging.SanitizeLogValue(req.GetCatalogId()),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil, status.Errorf(codes.Internal, "osquery execution failed")
	}

	rows := make([]*transportpb.OsqueryRow, 0, len(rawRows))
	for _, rawRow := range rawRows {
		pbRow := &transportpb.OsqueryRow{
			Columns: make(map[string]string, len(rawRow)),
		}
		for k, v := range rawRow {
			pbRow.Columns[k] = v
		}
		rows = append(rows, pbRow)
	}

	if h.logger != nil {
		h.logger.Debug("osquery query completed",
			"catalog_id", logging.SanitizeLogValue(req.GetCatalogId()),
			"row_count", len(rows))
	}
	return rows, nil
}

// HandleGRPC processes an OsqueryQuery bidi stream on the controller side.
//
// The steward (client) opens this stream and sends OsqueryQueryResponse result
// frames; the controller (server) sends OsqueryQueryRequest frames. HandleGRPC:
//
//   - Extracts the steward's mTLS peer ID (returns Unauthenticated if absent)
//   - Receives OsqueryQueryResponse frames from the steward and logs them
//   - Returns when the steward closes the stream or the context is cancelled
//
// Dispatching query requests to a specific steward's open stream is handled by
// the controller-side query dispatcher (a separate story in Epic #2855); this
// handler establishes the stream lifetime and peer identity.
func (h *OsqueryHandler) HandleGRPC(stream grpc.BidiStreamingServer[transportpb.OsqueryQueryResponse, transportpb.OsqueryQueryRequest]) error {
	ctx := stream.Context()

	peerID, err := extractMTLSPeerID(ctx)
	if err != nil {
		return err
	}

	if h.logger != nil {
		h.logger.Debug("osquery stream opened",
			"steward_id", logging.SanitizeLogValue(peerID))
	}
	defer func() {
		if h.logger != nil {
			h.logger.Debug("osquery stream closed",
				"steward_id", logging.SanitizeLogValue(peerID))
		}
	}()

	for {
		resp, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("osquery stream recv: %w", err)
		}
		if h.logger != nil {
			h.logger.Debug("osquery response received from steward",
				"steward_id", logging.SanitizeLogValue(peerID),
				"catalog_id", logging.SanitizeLogValue(resp.GetCatalogId()),
				"row_count", len(resp.GetRows()))
		}
	}
}

// extractMTLSPeerID extracts the steward ID from the mTLS peer certificate in ctx.
// Returns Unauthenticated if the peer is absent, non-TLS, or has an empty CN.
func extractMTLSPeerID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	id, err := quictransport.PeerStewardID(tlsInfo.State)
	if err != nil || id == "" {
		return "", status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	return id, nil
}
