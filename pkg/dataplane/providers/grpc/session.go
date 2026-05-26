// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package grpc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// Session implements DataPlaneSession for the gRPC data plane provider.
//
// Client-mode sessions use a StewardTransportClient to initiate RPCs.
// Server-mode sessions no longer queue RPCs via channels; incoming DNA,
// Bulk, and Config RPCs are handled directly by DNAHandler, BulkHandler,
// and ConfigHandler in the controller transport layer.
type Session struct {
	mu sync.RWMutex

	id         string
	peerID     string
	mode       string // "server" or "client"
	localAddr  string
	remoteAddr string

	// Client mode
	client transportpb.StewardTransportClient

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

// SendConfig is a server-side operation. After the direct-handler rewrite,
// server-side config streaming is handled by ConfigHandler.HandleGRPC directly.
// Client mode is not applicable for config sending.
func (s *Session) SendConfig(_ context.Context, _ *types.ConfigTransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	switch s.mode {
	case "server":
		return fmt.Errorf("SendConfig server mode not supported: use ConfigHandler directly")
	default:
		return fmt.Errorf("SendConfig is a server-side operation (controller streams config to steward); use ReceiveConfig on the steward side")
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

// ReceiveDNA receives DNA data from a steward. After the direct-handler rewrite,
// server-side DNA reception is handled by DNAHandler.HandleGRPC directly.
func (s *Session) ReceiveDNA(_ context.Context) (*types.DNATransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	switch s.mode {
	case "server":
		return nil, fmt.Errorf("ReceiveDNA server mode not supported: use DNAHandler directly")
	default:
		return nil, fmt.Errorf("ReceiveDNA is a server-side operation (controller receives DNA from steward); use SendDNA on the client side")
	}
}

// --- Bulk Transfers ---

// SendBulk sends bulk data to the peer.
//
// Client mode: opens a BulkTransfer bidi stream and sends chunks.
// Server mode: not supported after direct-handler rewrite; use BulkHandler directly.
func (s *Session) SendBulk(ctx context.Context, bulk *types.BulkTransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	switch s.mode {
	case "client":
		return s.clientSendBulk(ctx, bulk)
	case "server":
		return fmt.Errorf("SendBulk server mode not supported: use BulkHandler directly")
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

// ReceiveBulk receives bulk data from the peer. After the direct-handler rewrite,
// server-side bulk reception is handled by BulkHandler.HandleGRPC directly.
func (s *Session) ReceiveBulk(ctx context.Context) (*types.BulkTransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	switch s.mode {
	case "client":
		return s.clientReceiveBulk(ctx)
	case "server":
		return nil, fmt.Errorf("ReceiveBulk server mode not supported: use BulkHandler directly")
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

// --- Session Management ---

// Close gracefully closes the session and removes it from the provider's sessions map.
func (s *Session) Close(_ context.Context) error {
	s.closed.Store(true)
	s.provider.mu.Lock()
	delete(s.provider.sessions, s.id)
	s.provider.mu.Unlock()
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
