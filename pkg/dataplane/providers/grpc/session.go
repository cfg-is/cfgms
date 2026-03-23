// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
	"google.golang.org/grpc"
)

// Session implements DataPlaneSession for the gRPC data plane provider.
//
// Client-mode sessions use a StewardTransportClient to initiate RPCs.
// Server-mode sessions read from the dataPlaneHandler's pending-request
// channels to serve RPCs initiated by connected stewards.
type Session struct {
	mu sync.RWMutex

	id         string
	peerID     string
	mode       string // "server" or "client"
	localAddr  string
	remoteAddr string

	// Client mode
	client transportpb.StewardTransportClient

	// Server mode
	handler *dataPlaneHandler

	// Provider back-reference for stats
	provider *Provider

	closed atomic.Bool
}

// ID returns the session identifier.
func (s *Session) ID() string { return s.id }

// PeerID returns the peer identifier.
func (s *Session) PeerID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerID
}

// --- Configuration Transfers ---

// SendConfig sends configuration to the peer.
//
// Server mode: waits for an incoming SyncConfig RPC then streams chunks back.
// Client mode: not the typical direction for SyncConfig (controller → steward);
// returns an error directing callers to use ReceiveConfig instead.
func (s *Session) SendConfig(ctx context.Context, config *types.ConfigTransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	switch s.mode {
	case "server":
		return s.serverSendConfig(ctx, config)
	default:
		return fmt.Errorf("SendConfig is a server-side operation (controller streams config to steward); use ReceiveConfig on the steward side")
	}
}

func (s *Session) serverSendConfig(ctx context.Context, config *types.ConfigTransfer) error {
	select {
	case pending := <-s.handler.syncConfigReqs:
		chunks, err := configTransferToChunks(config)
		if err != nil {
			s.provider.stats.transferErrors.Add(1)
			select {
			case pending.errCh <- err:
			default:
			}
			return fmt.Errorf("failed to chunk config: %w", err)
		}

		for _, chunk := range chunks {
			if err := pending.stream.Send(chunk); err != nil {
				s.provider.stats.transferErrors.Add(1)
				select {
				case pending.errCh <- err:
				default:
				}
				return fmt.Errorf("failed to send config chunk: %w", err)
			}
			s.provider.stats.bytesSent.Add(int64(len(chunk.Data)))
		}

		select {
		case pending.errCh <- nil:
		default:
		}
		s.provider.stats.configsSent.Add(1)
		return nil

	case <-ctx.Done():
		s.provider.stats.timeoutErrors.Add(1)
		return ctx.Err()
	case <-s.handler.done:
		return fmt.Errorf("server shutting down")
	}
}

// ReceiveConfig receives configuration from the controller.
//
// Client mode: calls the SyncConfig RPC and collects config chunks.
// Server mode: not the typical direction; returns an error.
func (s *Session) ReceiveConfig(ctx context.Context) (*types.ConfigTransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	switch s.mode {
	case "client":
		return s.clientReceiveConfig(ctx)
	default:
		return nil, fmt.Errorf("ReceiveConfig is a client-side operation (steward receives config from controller); use SendConfig on the server side")
	}
}

func (s *Session) clientReceiveConfig(ctx context.Context) (*types.ConfigTransfer, error) {
	req := &transportpb.ConfigSyncRequest{
		StewardId: s.provider.stewardID,
	}

	stream, err := s.client.SyncConfig(ctx, req)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to initiate SyncConfig RPC: %w", err)
	}

	var chunks []*transportpb.ConfigChunk
	for {
		chunk, err := stream.Recv()
		if isEOF(err) {
			break
		}
		if err != nil {
			s.provider.stats.transferErrors.Add(1)
			return nil, fmt.Errorf("failed to receive config chunk: %w", err)
		}
		chunks = append(chunks, chunk)
		s.provider.stats.bytesReceived.Add(int64(len(chunk.Data)))
	}

	cfg, err := chunksToConfigTransfer(chunks)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to reassemble config: %w", err)
	}

	s.provider.stats.configsReceived.Add(1)
	return cfg, nil
}

// --- DNA Transfers ---

// SendDNA sends DNA data to the controller.
//
// Client mode: calls the SyncDNA RPC, streams DNA chunks, and reads the response.
// Server mode: not the typical direction; returns an error.
func (s *Session) SendDNA(ctx context.Context, dna *types.DNATransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	switch s.mode {
	case "client":
		return s.clientSendDNA(ctx, dna)
	default:
		return fmt.Errorf("SendDNA is a client-side operation (steward streams DNA to controller); use ReceiveDNA on the server side")
	}
}

func (s *Session) clientSendDNA(ctx context.Context, dna *types.DNATransfer) error {
	stream, err := s.client.SyncDNA(ctx)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to initiate SyncDNA RPC: %w", err)
	}

	chunks, err := dnaTransferToChunks(dna)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to chunk DNA: %w", err)
	}

	for _, chunk := range chunks {
		if err := stream.Send(chunk); err != nil {
			s.provider.stats.transferErrors.Add(1)
			return fmt.Errorf("failed to send DNA chunk: %w", err)
		}
		s.provider.stats.bytesSent.Add(int64(len(chunk.Data)))
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to close DNA stream: %w", err)
	}
	if !resp.GetAccepted() {
		return fmt.Errorf("DNA sync rejected by controller: %s", resp.GetMessage())
	}

	s.provider.stats.dnaSent.Add(1)
	return nil
}

// ReceiveDNA receives DNA data from a steward.
//
// Server mode: waits for an incoming SyncDNA RPC, collects chunks, and returns
// the assembled DNA transfer.
// Client mode: not the typical direction; returns an error.
func (s *Session) ReceiveDNA(ctx context.Context) (*types.DNATransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	switch s.mode {
	case "server":
		return s.serverReceiveDNA(ctx)
	default:
		return nil, fmt.Errorf("ReceiveDNA is a server-side operation (controller receives DNA from steward); use SendDNA on the client side")
	}
}

func (s *Session) serverReceiveDNA(ctx context.Context) (*types.DNATransfer, error) {
	select {
	case pending := <-s.handler.syncDNAReqs:
		var chunks []*transportpb.DNAChunk
		for {
			chunk, err := pending.stream.Recv()
			if isEOF(err) {
				break
			}
			if err != nil {
				s.provider.stats.transferErrors.Add(1)
				select {
				case pending.errCh <- err:
				default:
				}
				return nil, fmt.Errorf("failed to receive DNA chunk: %w", err)
			}
			chunks = append(chunks, chunk)
			s.provider.stats.bytesReceived.Add(int64(len(chunk.Data)))
		}

		dna, err := chunksToDNATransfer(chunks)
		if err != nil {
			s.provider.stats.transferErrors.Add(1)
			select {
			case pending.errCh <- err:
			default:
			}
			return nil, fmt.Errorf("failed to reassemble DNA: %w", err)
		}

		// Send acceptance response
		if err := pending.stream.SendAndClose(&transportpb.DNASyncResponse{
			Accepted: true,
			Message:  "accepted",
		}); err != nil {
			s.provider.stats.transferErrors.Add(1)
			select {
			case pending.errCh <- err:
			default:
			}
			return nil, fmt.Errorf("failed to send DNA sync response: %w", err)
		}

		select {
		case pending.errCh <- nil:
		default:
		}
		s.provider.stats.dnaReceived.Add(1)
		return dna, nil

	case <-ctx.Done():
		s.provider.stats.timeoutErrors.Add(1)
		return nil, ctx.Err()
	case <-s.handler.done:
		return nil, fmt.Errorf("server shutting down")
	}
}

// --- Bulk Transfers ---

// SendBulk sends bulk data to the peer.
//
// Client mode: opens a BulkTransfer bidi stream and sends chunks.
// Server mode: reads the pending BulkTransfer stream and sends response chunks.
func (s *Session) SendBulk(ctx context.Context, bulk *types.BulkTransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	switch s.mode {
	case "client":
		return s.clientSendBulk(ctx, bulk)
	case "server":
		return s.serverSendBulk(ctx, bulk)
	default:
		return fmt.Errorf("unsupported mode: %s", s.mode)
	}
}

func (s *Session) clientSendBulk(ctx context.Context, bulk *types.BulkTransfer) error {
	stream, err := s.client.BulkTransfer(ctx)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to initiate BulkTransfer RPC: %w", err)
	}

	chunks, err := bulkTransferToChunks(bulk)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to chunk bulk data: %w", err)
	}

	for _, chunk := range chunks {
		if err := stream.Send(chunk); err != nil {
			s.provider.stats.transferErrors.Add(1)
			return fmt.Errorf("failed to send bulk chunk: %w", err)
		}
		s.provider.stats.bytesSent.Add(int64(len(chunk.Data)))
	}

	if err := stream.CloseSend(); err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to close bulk send: %w", err)
	}

	s.provider.stats.bulkSent.Add(1)
	return nil
}

func (s *Session) serverSendBulk(ctx context.Context, bulk *types.BulkTransfer) error {
	select {
	case pending := <-s.handler.bulkReqs:
		chunks, err := bulkTransferToChunks(bulk)
		if err != nil {
			s.provider.stats.transferErrors.Add(1)
			select {
			case pending.errCh <- err:
			default:
			}
			return fmt.Errorf("failed to chunk bulk data: %w", err)
		}

		for _, chunk := range chunks {
			if err := pending.stream.Send(chunk); err != nil {
				s.provider.stats.transferErrors.Add(1)
				select {
				case pending.errCh <- err:
				default:
				}
				return fmt.Errorf("failed to send bulk chunk: %w", err)
			}
			s.provider.stats.bytesSent.Add(int64(len(chunk.Data)))
		}

		select {
		case pending.errCh <- nil:
		default:
		}
		s.provider.stats.bulkSent.Add(1)
		return nil

	case <-ctx.Done():
		s.provider.stats.timeoutErrors.Add(1)
		return ctx.Err()
	case <-s.handler.done:
		return fmt.Errorf("server shutting down")
	}
}

// ReceiveBulk receives bulk data from the peer.
//
// Client mode: reads from a BulkTransfer bidi stream.
// Server mode: waits for an incoming BulkTransfer RPC and reads chunks.
func (s *Session) ReceiveBulk(ctx context.Context) (*types.BulkTransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	switch s.mode {
	case "client":
		return s.clientReceiveBulk(ctx)
	case "server":
		return s.serverReceiveBulk(ctx)
	default:
		return nil, fmt.Errorf("unsupported mode: %s", s.mode)
	}
}

func (s *Session) clientReceiveBulk(ctx context.Context) (*types.BulkTransfer, error) {
	stream, err := s.client.BulkTransfer(ctx)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to initiate BulkTransfer RPC: %w", err)
	}

	var chunks []*transportpb.BulkChunk
	for {
		chunk, err := stream.Recv()
		if isEOF(err) {
			break
		}
		if err != nil {
			s.provider.stats.transferErrors.Add(1)
			return nil, fmt.Errorf("failed to receive bulk chunk: %w", err)
		}
		chunks = append(chunks, chunk)
		s.provider.stats.bytesReceived.Add(int64(len(chunk.Data)))
	}

	bulk, err := chunksToBulkTransfer(chunks)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to reassemble bulk: %w", err)
	}

	s.provider.stats.bulkReceived.Add(1)
	return bulk, nil
}

func (s *Session) serverReceiveBulk(ctx context.Context) (*types.BulkTransfer, error) {
	select {
	case pending := <-s.handler.bulkReqs:
		var chunks []*transportpb.BulkChunk
		for {
			chunk, err := pending.stream.Recv()
			if isEOF(err) {
				break
			}
			if err != nil {
				s.provider.stats.transferErrors.Add(1)
				select {
				case pending.errCh <- err:
				default:
				}
				return nil, fmt.Errorf("failed to receive bulk chunk: %w", err)
			}
			chunks = append(chunks, chunk)
			s.provider.stats.bytesReceived.Add(int64(len(chunk.Data)))
		}

		bulk, err := chunksToBulkTransfer(chunks)
		if err != nil {
			s.provider.stats.transferErrors.Add(1)
			select {
			case pending.errCh <- err:
			default:
			}
			return nil, fmt.Errorf("failed to reassemble bulk: %w", err)
		}

		select {
		case pending.errCh <- nil:
		default:
		}
		s.provider.stats.bulkReceived.Add(1)
		return bulk, nil

	case <-ctx.Done():
		s.provider.stats.timeoutErrors.Add(1)
		return nil, ctx.Err()
	case <-s.handler.done:
		return nil, fmt.Errorf("server shutting down")
	}
}

// --- Raw Streams (not supported) ---

// OpenStream is not supported by the gRPC provider.
// Use the typed transfer methods (SendConfig, SendDNA, SendBulk) instead.
func (s *Session) OpenStream(_ context.Context, _ types.StreamType) (interfaces.Stream, error) {
	return nil, fmt.Errorf("gRPC provider does not support raw streams: use SendConfig, SendDNA, or SendBulk instead")
}

// AcceptStream is not supported by the gRPC provider.
// Use the typed transfer methods (ReceiveConfig, ReceiveDNA, ReceiveBulk) instead.
func (s *Session) AcceptStream(_ context.Context) (interfaces.Stream, types.StreamType, error) {
	return nil, "", fmt.Errorf("gRPC provider does not support raw streams: use ReceiveConfig, ReceiveDNA, or ReceiveBulk instead")
}

// --- Session Management ---

// Close gracefully closes the session.
func (s *Session) Close(_ context.Context) error {
	s.closed.Store(true)
	return nil
}

// IsClosed reports whether the session has been closed.
func (s *Session) IsClosed() bool {
	return s.closed.Load()
}

// LocalAddr returns the local network address.
func (s *Session) LocalAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localAddr
}

// RemoteAddr returns the peer's network address.
func (s *Session) RemoteAddr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.remoteAddr
}

// --- gRPC server handler ---

// pendingSyncConfig represents an in-flight SyncConfig RPC waiting to be served.
type pendingSyncConfig struct {
	req    *transportpb.ConfigSyncRequest
	stream grpc.ServerStreamingServer[transportpb.ConfigChunk]
	errCh  chan error
}

// pendingSyncDNA represents an in-flight SyncDNA RPC waiting to be served.
type pendingSyncDNA struct {
	stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]
	errCh  chan error
}

// pendingBulk represents an in-flight BulkTransfer RPC waiting to be served.
type pendingBulk struct {
	stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]
	errCh  chan error
}

// dataPlaneHandler implements the StewardTransportServer data-transfer methods.
//
// Incoming RPCs are queued in buffered channels. Sessions drain those channels
// by calling the appropriate transfer method (SendConfig, ReceiveDNA, etc.).
type dataPlaneHandler struct {
	transportpb.UnimplementedStewardTransportServer
	syncConfigReqs chan *pendingSyncConfig
	syncDNAReqs    chan *pendingSyncDNA
	bulkReqs       chan *pendingBulk
	done           chan struct{}
}

func newDataPlaneHandler() *dataPlaneHandler {
	return &dataPlaneHandler{
		// Buffer 16 concurrent RPCs per type before back-pressure kicks in.
		syncConfigReqs: make(chan *pendingSyncConfig, 16),
		syncDNAReqs:    make(chan *pendingSyncDNA, 16),
		bulkReqs:       make(chan *pendingBulk, 16),
		done:           make(chan struct{}),
	}
}

func (h *dataPlaneHandler) close() {
	select {
	case <-h.done:
		// already closed
	default:
		close(h.done)
	}
}

// SyncConfig queues the incoming request and waits for the session to serve it.
func (h *dataPlaneHandler) SyncConfig(req *transportpb.ConfigSyncRequest, stream grpc.ServerStreamingServer[transportpb.ConfigChunk]) error {
	p := &pendingSyncConfig{
		req:    req,
		stream: stream,
		errCh:  make(chan error, 1),
	}

	select {
	case h.syncConfigReqs <- p:
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-h.done:
		return fmt.Errorf("server shutting down")
	}

	select {
	case err := <-p.errCh:
		return err
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-h.done:
		return fmt.Errorf("server shutting down")
	}
}

// SyncDNA queues the incoming stream and waits for the session to serve it.
func (h *dataPlaneHandler) SyncDNA(stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	p := &pendingSyncDNA{
		stream: stream,
		errCh:  make(chan error, 1),
	}

	select {
	case h.syncDNAReqs <- p:
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-h.done:
		return fmt.Errorf("server shutting down")
	}

	select {
	case err := <-p.errCh:
		return err
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-h.done:
		return fmt.Errorf("server shutting down")
	}
}

// BulkTransfer queues the incoming stream and waits for the session to serve it.
func (h *dataPlaneHandler) BulkTransfer(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	p := &pendingBulk{
		stream: stream,
		errCh:  make(chan error, 1),
	}

	select {
	case h.bulkReqs <- p:
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-h.done:
		return fmt.Errorf("server shutting down")
	}

	select {
	case err := <-p.errCh:
		return err
	case <-stream.Context().Done():
		return stream.Context().Err()
	case <-h.done:
		return fmt.Errorf("server shutting down")
	}
}
