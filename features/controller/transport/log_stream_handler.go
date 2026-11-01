// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"io"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
	loggingInterfaces "github.com/cfgis/cfgms/pkg/logging/interfaces"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// LogStreamConfig holds rate-limiting configuration for LogStream ingestion.
type LogStreamConfig struct {
	// RateLimitPerSteward is the maximum log entries per second per steward.
	RateLimitPerSteward int
}

// DefaultLogStreamConfig returns the default LogStream configuration.
func DefaultLogStreamConfig() LogStreamConfig {
	return LogStreamConfig{
		RateLimitPerSteward: 100,
	}
}

// tokenBucket implements a simple token-bucket rate limiter for per-steward ingest.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64 // tokens per second
	lastFill time.Time
}

func newTokenBucket(ratePerSecond int) *tokenBucket {
	cap := float64(ratePerSecond)
	return &tokenBucket{
		tokens:   cap,
		capacity: cap,
		rate:     cap,
		lastFill: time.Now(),
	}
}

// tryConsume attempts to consume one token. Returns true if consumed, false if
// the bucket is empty (entry should be dropped).
func (tb *tokenBucket) tryConsume() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.lastFill).Seconds()
	tb.lastFill = now
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	if tb.tokens < 1 {
		return false
	}
	tb.tokens--
	return true
}

// LogStreamHandler handles LogStream RPCs from stewards. Each ingested LogEntry
// is CN-matched to the authenticated mTLS peer, tenant-derived server-side from
// the fleet registry, rate-limited per steward, and written via the dedicated
// steward-event LoggingManager (Issue #2140).
type LogStreamHandler struct {
	loggingManager    *logging.LoggingManager
	controllerService *service.ControllerService
	logger            logging.Logger
	config            LogStreamConfig

	mu           sync.Mutex
	dropCounters map[string]int64
	tokenBuckets map[string]*tokenBucket
}

// NewLogStreamHandler creates a new LogStreamHandler.
func NewLogStreamHandler(
	loggingManager *logging.LoggingManager,
	controllerService *service.ControllerService,
	logger logging.Logger,
	config LogStreamConfig,
) *LogStreamHandler {
	return &LogStreamHandler{
		loggingManager:    loggingManager,
		controllerService: controllerService,
		logger:            logger,
		config:            config,
		dropCounters:      make(map[string]int64),
		tokenBuckets:      make(map[string]*tokenBucket),
	}
}

// GetDropCount returns the number of dropped entries for the given steward.
func (h *LogStreamHandler) GetDropCount(stewardID string) int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dropCounters[stewardID]
}

func (h *LogStreamHandler) getOrCreateBucket(stewardID string) *tokenBucket {
	h.mu.Lock()
	defer h.mu.Unlock()
	if b, ok := h.tokenBuckets[stewardID]; ok {
		return b
	}
	b := newTokenBucket(h.config.RateLimitPerSteward)
	h.tokenBuckets[stewardID] = b
	return b
}

func (h *LogStreamHandler) incrementDropCounter(stewardID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropCounters[stewardID]++
}

// HandleGRPC processes a LogStream RPC.
//
//  1. Extracts the CN from the mTLS peer — fails closed if absent or empty.
//  2. CN-matches every received LogEntry against the peer CN; mismatches return
//     PermissionDenied without disclosing the peer CN in the error message.
//  3. Derives TenantID server-side from the fleet registry; any wire-supplied
//     tenant value is ignored to prevent a compromised steward from stamping
//     another tenant's events.
//  4. Applies a per-steward token-bucket rate limit; entries above the limit are
//     dropped (non-blocking) and counted per steward.
//  5. Maps each accepted entry to a loggingInterfaces.LogEntry and calls
//     WriteEntry on the steward-event LoggingManager.
//
// On clean EOF, returns LogStreamResponse{EntriesReceived: N, Acknowledged: true}.
func (h *LogStreamHandler) HandleGRPC(stream grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse]) error {
	ctx := stream.Context()

	// Extract mTLS peer CN — fail closed if missing or empty.
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}
	peerID, err := quictransport.PeerStewardID(tlsInfo.State)
	if err != nil || peerID == "" {
		return status.Error(codes.Unauthenticated, "mTLS certificate required")
	}

	// Derive TenantID server-side from the authenticated peer's fleet-registry record.
	tenantID := ""
	if h.controllerService != nil {
		if info, ok := h.controllerService.GetStewardInfo(peerID); ok {
			tenantID = info.TenantID
		}
	}

	bucket := h.getOrCreateBucket(peerID)
	var received int64

	for {
		entry, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return recvErr
		}

		// CN-match: entry StewardID must equal the authenticated peer CN.
		if entry.GetStewardId() != peerID {
			return status.Error(codes.PermissionDenied, "steward ID mismatch")
		}

		// Rate-limit: drop entries above per-steward budget without blocking.
		if !bucket.tryConsume() {
			h.incrementDropCounter(peerID)
			if h.logger != nil {
				h.logger.Warn("LogStream entry dropped: rate limit exceeded",
					"steward_id", logging.SanitizeLogValue(peerID),
					"drops", h.GetDropCount(peerID))
			}
			continue
		}

		logEntry := mapLogEntry(entry, peerID, tenantID)

		written := true
		if h.loggingManager != nil {
			if writeErr := h.loggingManager.WriteEntry(ctx, logEntry); writeErr != nil {
				written = false
				if h.logger != nil {
					h.logger.Warn("LogStream WriteEntry failed",
						"steward_id", logging.SanitizeLogValue(peerID),
						"error", writeErr)
				}
			}
		}
		if written {
			received++
		}
	}

	return stream.SendAndClose(&transportpb.LogStreamResponse{
		EntriesReceived: received,
		Acknowledged:    true,
	})
}

// mapLogEntry converts a transport-layer LogEntry proto to a loggingInterfaces.LogEntry.
// peerID (CN-verified) is always stamped into Fields["steward_id"], overriding
// any wire-supplied value so events are attributable per steward. TenantID is
// always the server-derived registry value.
func mapLogEntry(entry *transportpb.LogEntry, peerID, tenantID string) loggingInterfaces.LogEntry {
	fields := make(map[string]interface{}, len(entry.GetFields())+1)
	for k, v := range entry.GetFields() {
		fields[k] = v
	}
	// Stamp CN-verified steward identity (overrides any wire-supplied steward_id).
	fields["steward_id"] = peerID

	ts := time.Now()
	if entry.GetTimestamp() != nil {
		ts = entry.GetTimestamp().AsTime()
	}

	return loggingInterfaces.LogEntry{
		Timestamp:     ts,
		Level:         mapSeverityToLevel(entry.GetLevel()),
		Message:       entry.GetMessage(),
		TenantID:      tenantID,
		CorrelationID: entry.GetCorrelationId(),
		Fields:        fields,
	}
}

// mapSeverityToLevel converts a transport Severity to a logging level string.
func mapSeverityToLevel(s transportpb.Severity) string {
	switch s {
	case transportpb.Severity_SEVERITY_WARNING:
		return "WARN"
	case transportpb.Severity_SEVERITY_ERROR, transportpb.Severity_SEVERITY_CRITICAL:
		return "ERROR"
	default:
		return "INFO"
	}
}
