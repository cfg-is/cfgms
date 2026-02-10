// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package quic provides stream wrapper for data plane interface compliance.
package quic

import (
	"context"

	quicgo "github.com/quic-go/quic-go"

	"github.com/cfgis/cfgms/pkg/dataplane/types"
)

// streamWrapper wraps a quic-go Stream to implement interfaces.Stream.
type streamWrapper struct {
	stream     *quicgo.Stream
	streamType types.StreamType
}

// Read reads data from the stream.
func (sw *streamWrapper) Read(p []byte) (n int, err error) {
	return (*sw.stream).Read(p)
}

// Write writes data to the stream.
func (sw *streamWrapper) Write(p []byte) (n int, err error) {
	return (*sw.stream).Write(p)
}

// Close closes the stream.
func (sw *streamWrapper) Close() error {
	return (*sw.stream).Close()
}

// ID returns the stream identifier.
func (sw *streamWrapper) ID() uint64 {
	return uint64((*sw.stream).StreamID())
}

// Type returns the stream type.
func (sw *streamWrapper) Type() types.StreamType {
	return sw.streamType
}

// SetDeadline sets read and write deadlines.
func (sw *streamWrapper) SetDeadline(deadline context.Context) error {
	// Extract deadline from context
	if dl, ok := deadline.Deadline(); ok {
		return (*sw.stream).SetDeadline(dl)
	}
	return nil
}

// wrapStream wraps a quic-go stream into our interface.
func wrapStream(stream *quicgo.Stream, streamType types.StreamType) *streamWrapper {
	return &streamWrapper{
		stream:     stream,
		streamType: streamType,
	}
}
