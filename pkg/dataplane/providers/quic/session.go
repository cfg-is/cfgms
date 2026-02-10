// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package quic provides QUIC data plane session implementation.
package quic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	quicClient "github.com/cfgis/cfgms/pkg/quic/client"
	quicServer "github.com/cfgis/cfgms/pkg/quic/server"
)

// Session implements the DataPlaneSession interface for QUIC.
type Session struct {
	mu sync.RWMutex

	// Identification
	id        string
	peerID    string
	localAddr string
	peerAddr  string

	// Underlying QUIC connection (server or client)
	server *quicServer.Session
	client *quicClient.Client

	// State
	closed    atomic.Bool
	createdAt time.Time

	// Provider reference
	provider *Provider

	// Logger
	logger logging.Logger
}

// ID returns the session identifier.
func (s *Session) ID() string {
	return s.id
}

// PeerID returns the peer identifier.
func (s *Session) PeerID() string {
	return s.peerID
}

// SendConfig sends configuration to the peer.
func (s *Session) SendConfig(ctx context.Context, config *types.ConfigTransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	s.logger.Debug("Sending configuration",
		"session_id", s.id,
		"config_id", config.ID,
		"version", config.Version,
		"size", len(config.Data))

	// Serialize config transfer
	data, err := json.Marshal(config)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Open a config stream
	stream, err := s.openStreamInternal(ctx, types.StreamConfig)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to open config stream: %w", err)
	}
	defer func() { _ = (*stream).Close() }()

	// Write config data
	if _, err := (*stream).Write(data); err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to write config: %w", err)
	}

	s.provider.stats.configsSent.Add(1)
	s.provider.stats.bytesSent.Add(int64(len(data)))
	s.logger.Debug("Configuration sent successfully", "config_id", config.ID)
	return nil
}

// ReceiveConfig receives configuration from the peer.
func (s *Session) ReceiveConfig(ctx context.Context) (*types.ConfigTransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	// Accept a config stream
	stream, streamType, err := s.acceptStreamInternal(ctx)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}
	defer func() { _ = (*stream).Close() }()

	if streamType != types.StreamConfig {
		s.provider.stats.protocolErrors.Add(1)
		return nil, fmt.Errorf("expected config stream, got %s", streamType)
	}

	// Read config data
	data, err := io.ReadAll(stream)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	// Deserialize config transfer
	var config types.ConfigTransfer
	if err := json.Unmarshal(data, &config); err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	s.provider.stats.configsReceived.Add(1)
	s.provider.stats.bytesReceived.Add(int64(len(data)))
	s.logger.Debug("Configuration received successfully",
		"config_id", config.ID,
		"version", config.Version)

	return &config, nil
}

// SendDNA sends DNA to the peer.
func (s *Session) SendDNA(ctx context.Context, dna *types.DNATransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	s.logger.Debug("Sending DNA",
		"session_id", s.id,
		"dna_id", dna.ID,
		"delta", dna.Delta,
		"size", len(dna.Attributes))

	// Serialize DNA transfer
	data, err := json.Marshal(dna)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to marshal DNA: %w", err)
	}

	// Open a DNA stream
	stream, err := s.openStreamInternal(ctx, types.StreamDNA)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to open DNA stream: %w", err)
	}
	defer func() { _ = (*stream).Close() }()

	// Write DNA data
	if _, err := (*stream).Write(data); err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to write DNA: %w", err)
	}

	s.provider.stats.dnaSent.Add(1)
	s.provider.stats.bytesSent.Add(int64(len(data)))
	s.logger.Debug("DNA sent successfully", "dna_id", dna.ID)
	return nil
}

// ReceiveDNA receives DNA from the peer.
func (s *Session) ReceiveDNA(ctx context.Context) (*types.DNATransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	// Accept a DNA stream
	stream, streamType, err := s.acceptStreamInternal(ctx)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}
	defer func() { _ = (*stream).Close() }()

	if streamType != types.StreamDNA {
		s.provider.stats.protocolErrors.Add(1)
		return nil, fmt.Errorf("expected DNA stream, got %s", streamType)
	}

	// Read DNA data
	data, err := io.ReadAll(stream)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to read DNA: %w", err)
	}

	// Deserialize DNA transfer
	var dna types.DNATransfer
	if err := json.Unmarshal(data, &dna); err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to unmarshal DNA: %w", err)
	}

	s.provider.stats.dnaReceived.Add(1)
	s.provider.stats.bytesReceived.Add(int64(len(data)))
	s.logger.Debug("DNA received successfully", "dna_id", dna.ID)

	return &dna, nil
}

// SendBulk sends bulk data to the peer.
func (s *Session) SendBulk(ctx context.Context, bulk *types.BulkTransfer) error {
	if s.closed.Load() {
		return fmt.Errorf("session closed")
	}

	s.logger.Debug("Sending bulk data",
		"session_id", s.id,
		"bulk_id", bulk.ID,
		"type", bulk.Type,
		"size", bulk.TotalSize)

	// Serialize bulk transfer
	data, err := json.Marshal(bulk)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to marshal bulk: %w", err)
	}

	// Open a bulk stream
	stream, err := s.openStreamInternal(ctx, types.StreamBulk)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to open bulk stream: %w", err)
	}
	defer func() { _ = (*stream).Close() }()

	// Write bulk data
	if _, err := (*stream).Write(data); err != nil {
		s.provider.stats.transferErrors.Add(1)
		return fmt.Errorf("failed to write bulk: %w", err)
	}

	s.provider.stats.bulkSent.Add(1)
	s.provider.stats.bytesSent.Add(int64(len(data)))
	s.logger.Debug("Bulk data sent successfully", "bulk_id", bulk.ID)
	return nil
}

// ReceiveBulk receives bulk data from the peer.
func (s *Session) ReceiveBulk(ctx context.Context) (*types.BulkTransfer, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	// Accept a bulk stream
	stream, streamType, err := s.acceptStreamInternal(ctx)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}
	defer func() { _ = (*stream).Close() }()

	if streamType != types.StreamBulk {
		s.provider.stats.protocolErrors.Add(1)
		return nil, fmt.Errorf("expected bulk stream, got %s", streamType)
	}

	// Read bulk data
	data, err := io.ReadAll(stream)
	if err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to read bulk: %w", err)
	}

	// Deserialize bulk transfer
	var bulk types.BulkTransfer
	if err := json.Unmarshal(data, &bulk); err != nil {
		s.provider.stats.transferErrors.Add(1)
		return nil, fmt.Errorf("failed to unmarshal bulk: %w", err)
	}

	s.provider.stats.bulkReceived.Add(1)
	s.provider.stats.bytesReceived.Add(int64(len(data)))
	s.logger.Debug("Bulk data received successfully", "bulk_id", bulk.ID)

	return &bulk, nil
}

// OpenStream opens a new stream of the specified type.
func (s *Session) OpenStream(ctx context.Context, streamType types.StreamType) (interfaces.Stream, error) {
	stream, err := s.openStreamInternal(ctx, streamType)
	if err != nil {
		return nil, err
	}
	return wrapStream(stream, streamType), nil
}

// AcceptStream accepts an incoming stream from the peer.
func (s *Session) AcceptStream(ctx context.Context) (interfaces.Stream, types.StreamType, error) {
	stream, streamType, err := s.acceptStreamInternal(ctx)
	if err != nil {
		return nil, "", err
	}
	return wrapStream(stream, streamType), streamType, nil
}

// openStreamInternal opens a QUIC stream (implementation detail).
func (s *Session) openStreamInternal(ctx context.Context, streamType types.StreamType) (*quicgo.Stream, error) {
	if s.client != nil {
		// Client-side: use client.OpenStream
		return s.client.OpenStream(ctx, hashStreamType(streamType))
	}

	// Server-side: use server connection
	if s.server != nil && s.server.Connection != nil {
		// OpenStreamSync returns *quic.Stream (pointer)
		return (*s.server.Connection).OpenStreamSync(ctx)
	}

	return nil, fmt.Errorf("no active QUIC connection")
}

// acceptStreamInternal accepts a QUIC stream (implementation detail).
func (s *Session) acceptStreamInternal(ctx context.Context) (*quicgo.Stream, types.StreamType, error) {
	// TODO: Implement stream acceptance with type detection
	// This requires enhancing pkg/quic/server to support AcceptStream
	// For now, return placeholder
	return nil, "", fmt.Errorf("AcceptStream not yet implemented")
}

// hashStreamType converts a stream type to a numeric stream ID.
func hashStreamType(streamType types.StreamType) int64 {
	switch streamType {
	case types.StreamConfig:
		return 1
	case types.StreamDNA:
		return 2
	case types.StreamBulk:
		return 3
	case types.StreamCustom:
		return 99
	default:
		return 0
	}
}

// Close closes the session.
func (s *Session) Close(ctx context.Context) error {
	if s.closed.Swap(true) {
		return nil // Already closed
	}

	s.logger.Info("Closing data plane session", "session_id", s.id)

	// Close client or server connection
	if s.client != nil {
		return s.client.Disconnect()
	}

	if s.server != nil && s.server.Connection != nil {
		return (*s.server.Connection).CloseWithError(0, "session closed")
	}

	return nil
}

// IsClosed reports whether the session is closed.
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
	return s.peerAddr
}
