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
//
//   - QuerySteward: the controller-side dispatch path (Issue #3569). Sends an
//     OsqueryQueryRequest to a connected steward's open stream and waits for
//     the OsqueryQueryResponse. Used by the REST handler POST /api/v1/osquery/query.
package osquery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

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

// osqueryStreamEntry tracks one steward's open OsqueryQuery bidi stream.
// mu serialises queries so only one is in-flight per steward at a time (v1).
type osqueryStreamEntry struct {
	mu      sync.Mutex
	stream  grpc.BidiStreamingServer[transportpb.OsqueryQueryResponse, transportpb.OsqueryQueryRequest]
	waiting chan *transportpb.OsqueryQueryResponse // non-nil while a query is in-flight
	done    chan struct{}                          // closed when the stream ends
}

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

	// streams is the controller-side registry of connected steward streams (Issue #3569).
	// guarded by streamsMu; populated by HandleGRPC, queried by QuerySteward.
	streamsMu sync.RWMutex
	streams   map[string]*osqueryStreamEntry // stewardID → stream entry
}

// NewOsqueryHandler returns an OsqueryHandler. binPath is the verified osquery
// binary path returned by PreExecVerifier.VerifyBeforeExec; the handler does not
// re-verify on each Execute call (pre-exec verification is the caller's
// responsibility per Story #3561 / ADR-006).
func NewOsqueryHandler(logger logging.Logger, binPath string) *OsqueryHandler {
	return &OsqueryHandler{
		logger:  logger,
		binPath: binPath,
		streams: make(map[string]*osqueryStreamEntry),
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
//   - Registers the stream in the controller-side stream registry (Issue #3569)
//   - Receives OsqueryQueryResponse frames and routes them to waiting QuerySteward callers
//   - Returns when the steward closes the stream or the context is cancelled
func (h *OsqueryHandler) HandleGRPC(stream grpc.BidiStreamingServer[transportpb.OsqueryQueryResponse, transportpb.OsqueryQueryRequest]) error {
	ctx := stream.Context()

	peerID, err := extractMTLSPeerID(ctx)
	if err != nil {
		return err
	}

	entry := &osqueryStreamEntry{
		stream: stream,
		done:   make(chan struct{}),
	}

	h.streamsMu.Lock()
	h.streams[peerID] = entry
	h.streamsMu.Unlock()
	defer func() {
		h.streamsMu.Lock()
		delete(h.streams, peerID)
		h.streamsMu.Unlock()
		close(entry.done)
	}()

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

		// Route response to a waiting QuerySteward caller (Issue #3569).
		entry.mu.Lock()
		ch := entry.waiting
		entry.waiting = nil
		entry.mu.Unlock()

		if ch != nil {
			ch <- resp
		} else if h.logger != nil {
			h.logger.Debug("osquery response received with no waiting caller (response dropped)",
				"steward_id", logging.SanitizeLogValue(peerID),
				"catalog_id", logging.SanitizeLogValue(resp.GetCatalogId()))
		}
	}
}

// QuerySteward sends an OsqueryQueryRequest to a connected steward and returns
// the response rows (Issue #3569). It is called by the REST handler
// POST /api/v1/osquery/query for each targeted steward.
//
// Only one query may be in-flight per steward at a time (v1 constraint). A second
// concurrent call for the same steward returns an error immediately rather than
// blocking. The caller is responsible for retrying or reporting the error.
//
// Returns ErrStewardNotConnected when the steward has no open OsqueryQuery stream.
func (h *OsqueryHandler) QuerySteward(ctx context.Context, stewardID, catalogID string, params map[string]string) ([]*transportpb.OsqueryRow, error) {
	h.streamsMu.RLock()
	entry := h.streams[stewardID]
	h.streamsMu.RUnlock()

	if entry == nil {
		return nil, ErrStewardNotConnected
	}

	entry.mu.Lock()
	if entry.waiting != nil {
		entry.mu.Unlock()
		return nil, errors.New("osquery: query already in-flight for this steward")
	}
	respCh := make(chan *transportpb.OsqueryQueryResponse, 1)
	entry.waiting = respCh

	req := &transportpb.OsqueryQueryRequest{
		StewardId: stewardID,
		CatalogId: catalogID,
		Params:    params,
	}
	if err := entry.stream.Send(req); err != nil {
		entry.waiting = nil
		entry.mu.Unlock()
		return nil, fmt.Errorf("osquery: sending request to steward: %w", err)
	}
	entry.mu.Unlock()

	select {
	case resp := <-respCh:
		if resp == nil {
			return nil, errors.New("osquery: stream ended without response")
		}
		return resp.GetRows(), nil
	case <-ctx.Done():
		entry.mu.Lock()
		if entry.waiting == respCh {
			entry.waiting = nil
		}
		entry.mu.Unlock()
		return nil, ctx.Err()
	case <-entry.done:
		return nil, errors.New("osquery: steward disconnected during query")
	}
}

// ErrStewardNotConnected is returned by QuerySteward when the target steward
// has no open OsqueryQuery bidi stream on this controller node.
var ErrStewardNotConnected = errors.New("osquery: steward not connected to osquery stream")

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
