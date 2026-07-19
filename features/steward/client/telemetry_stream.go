// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package client

import (
	"context"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/steward/telemetry"
	"github.com/cfgis/cfgms/pkg/logging"
)

// minTelemetryIntervalMs is the floor applied to any interval_ms received in
// an inbound TelemetryRequest. Values below this are clamped to it so a
// rogue or misconfigured controller cannot drive the steward into a tight
// sampling loop (defense in depth — the actual untrusted-input boundary is
// story #2765 on the controller side).
const minTelemetryIntervalMs = 1000

// TelemetryStreamConfig holds configuration for [TelemetryStream].
type TelemetryStreamConfig struct {
	// Client is the gRPC client used to dial TelemetryStream.
	Client transportpb.StewardTransportClient
	// StewardID is stamped into every outbound TelemetrySnapshot.
	StewardID string
	// Collector provides point-in-time process/service snapshots. It is the
	// real platform [telemetry.Collector] (obtained via [telemetry.NewCollector]);
	// the field is the interface type so the steward's own host collector is
	// injected without this package importing a specific platform build.
	Collector telemetry.Collector
	// Logger receives warnings about stream failures and reconnects.
	Logger logging.Logger
}

// TelemetryStream dials the TelemetryStream bidi RPC and manages the
// subscription lifecycle on behalf of the steward. It reacts to inbound
// TelemetryRequest frames from the controller:
//
//   - subscribe=true  → starts a ticker at the clamped interval_ms and calls
//     Snapshot() on each tick, streaming the result to the controller.
//   - subscribe=false → stops the ticker; no further Snapshot() calls until
//     the next subscribe=true.
//
// No Snapshot() calls happen outside an active subscribe window.
// The stream reconnects with exponential back-off after any RPC error.
type TelemetryStream struct {
	client    transportpb.StewardTransportClient
	stewardID string
	collector telemetry.Collector
	logger    logging.Logger

	mu        sync.Mutex
	started   atomic.Bool
	closeOnce sync.Once
	stop      chan struct{} // closed by Close()
	done      chan struct{} // closed when goroutine exits
}

// NewTelemetryStream creates a TelemetryStream. Call Start to begin the
// background stream goroutine.
func NewTelemetryStream(cfg TelemetryStreamConfig) *TelemetryStream {
	logger := cfg.Logger
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &TelemetryStream{
		client:    cfg.Client,
		stewardID: cfg.StewardID,
		collector: cfg.Collector,
		logger:    logger,
		done:      make(chan struct{}),
	}
}

// Start launches the background stream goroutine. Subsequent calls are no-ops.
func (t *TelemetryStream) Start(ctx context.Context) {
	if !t.started.CompareAndSwap(false, true) {
		return
	}
	stop := make(chan struct{})
	t.mu.Lock()
	t.stop = stop
	t.mu.Unlock()
	go func() {
		defer close(t.done)
		t.streamLoop(ctx, stop)
	}()
}

// Close signals the stream goroutine to stop and waits for it to exit.
// Safe to call before Start or multiple times.
func (t *TelemetryStream) Close() {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		stop := t.stop
		t.mu.Unlock()
		if stop == nil {
			return
		}
		close(stop)
		<-t.done
	})
}

// streamLoop opens TelemetryStream RPCs with exponential back-off, reconnecting
// after any failure. stop is closed by Close().
func (t *TelemetryStream) streamLoop(ctx context.Context, stop <-chan struct{}) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		default:
		}
		if err := t.runStream(ctx, stop); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			default:
			}
			t.logger.Warn("TelemetryStream: stream failed, reconnecting",
				"error", err, "attempt", attempt)
			delay := emitterBackoff(attempt)
			attempt++
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-time.After(delay):
			}
			continue
		}
		// runStream returned nil — stop or ctx was signalled; exit cleanly.
		return
	}
}

// runStream opens one TelemetryStream RPC, drives the subscription lifecycle,
// and returns when stop is closed, ctx is done, or a fatal stream error occurs.
// A nil return means clean shutdown (stop/ctx); a non-nil return triggers
// reconnection by streamLoop.
func (t *TelemetryStream) runStream(ctx context.Context, stop <-chan struct{}) error {
	stream, err := t.client.TelemetryStream(ctx)
	if err != nil {
		return err
	}

	// recvCh carries inbound TelemetryRequest messages. recvErr carries the
	// terminal error (non-nil) when the recv goroutine exits.
	// Control frames (subscribe/unsubscribe) must never be dropped; the send is
	// blocking so the main loop always sees every frame it is supposed to act on.
	// The main loop drains recvCh promptly between ticks, so the small buffer is
	// only a courtesy to avoid a spurious context-switch when subscribe+unsubscribe
	// arrive in close succession.
	recvCh := make(chan *transportpb.TelemetryRequest, 4)
	recvErr := make(chan error, 1)
	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case recvCh <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	var (
		ticker *time.Ticker
		tickCh <-chan time.Time
	)
	defer func() {
		if ticker != nil {
			ticker.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if err := stream.CloseSend(); err != nil {
				t.logger.Warn("TelemetryStream: CloseSend on context cancel", "error", err)
			}
			return nil
		case <-stop:
			if err := stream.CloseSend(); err != nil {
				t.logger.Warn("TelemetryStream: CloseSend on stop", "error", err)
			}
			return nil
		case err := <-recvErr:
			// EOF means the controller closed the stream gracefully.
			if err == io.EOF {
				return nil
			}
			return err
		case req := <-recvCh:
			if req.GetSubscribe() {
				interval := clampTelemetryInterval(req.GetIntervalMs())
				if ticker != nil {
					ticker.Stop()
				}
				ticker = time.NewTicker(interval)
				tickCh = ticker.C
			} else {
				if ticker != nil {
					ticker.Stop()
					ticker = nil
					tickCh = nil
				}
			}
		case <-tickCh:
			snap, err := t.collector.Snapshot(ctx)
			if err != nil {
				t.logger.Warn("TelemetryStream: Snapshot failed", "error", err)
				continue
			}
			pb := telemetryToProto(snap, t.stewardID)
			if sendErr := stream.Send(pb); sendErr != nil {
				return sendErr
			}
		}
	}
}

// clampTelemetryInterval returns the requested interval clamped to
// [minTelemetryIntervalMs, ∞). Any value below 1 s is treated as if the
// controller sent 1 s — it prevents a misconfigured or hostile request from
// driving Snapshot() in a tight loop.
func clampTelemetryInterval(ms int32) time.Duration {
	if ms < minTelemetryIntervalMs {
		return time.Duration(minTelemetryIntervalMs) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

// safePID converts an OS PID (int, architecture-dependent width) to int32 for
// the proto wire type. OS PIDs on supported platforms fit well within int32
// range (Linux max is 2^22, Windows HANDLE-carried PIDs are similar); the
// explicit bounds check satisfies the narrowing-conversion invariant.
func safePID(pid int) int32 {
	if pid > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(pid)
}

// telemetryToProto converts a [telemetry.Telemetry] snapshot into the proto
// wire type, stamping stewardID and a current timestamp.
func telemetryToProto(t telemetry.Telemetry, stewardID string) *transportpb.TelemetrySnapshot {
	processes := make([]*transportpb.ProcessSnapshot, len(t.Processes))
	for i, p := range t.Processes {
		processes[i] = &transportpb.ProcessSnapshot{
			FragmentId:     p.FragmentID,
			Pid:            safePID(p.PID),
			Name:           p.Name,
			CpuPercent:     p.CPUPercent,
			MemoryBytes:    p.MemoryBytes,
			DiskReadBytes:  p.DiskReadBytes,
			DiskWriteBytes: p.DiskWriteBytes,
			NetRxBytes:     p.NetRxBytes,
			NetTxBytes:     p.NetTxBytes,
		}
	}
	services := make([]*transportpb.ServiceSnapshot, len(t.Services))
	for i, s := range t.Services {
		services[i] = &transportpb.ServiceSnapshot{
			FragmentId: s.FragmentID,
			Name:       s.Name,
			State:      s.State,
		}
	}
	return &transportpb.TelemetrySnapshot{
		StewardId: stewardID,
		Processes: processes,
		Services:  services,
		Timestamp: timestamppb.Now(),
	}
}
