// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRelayExecutor_WriteData_ForwardsCopy verifies the happy path: WriteData
// enqueues an independent copy of the data on InputChan.
func TestRelayExecutor_WriteData_ForwardsCopy(t *testing.T) {
	r := NewRelayExecutor()

	input := []byte("ls -la\n")
	require.NoError(t, r.WriteData(context.Background(), input))

	select {
	case got := <-r.InputChan():
		assert.Equal(t, []byte("ls -la\n"), got, "WriteData must forward the data unchanged")
		// Mutating the caller's slice afterwards must not affect the queued copy.
		input[0] = 'X'
		assert.Equal(t, byte('l'), got[0], "WriteData must enqueue a defensive copy")
	case <-time.After(time.Second):
		t.Fatal("expected data on InputChan")
	}
}

// TestRelayExecutor_WriteData_DropsWhenClosed verifies the documented drop
// behaviour: after Close, WriteData silently drops (returns nil, enqueues
// nothing) so the WS read goroutine is never blocked on a torn-down relay.
func TestRelayExecutor_WriteData_DropsWhenClosed(t *testing.T) {
	r := NewRelayExecutor()
	require.NoError(t, r.Close(context.Background()))

	require.NoError(t, r.WriteData(context.Background(), []byte("post-close")),
		"WriteData after Close must not error")

	assert.Equal(t, 0, len(r.InputChan()),
		"WriteData after Close must drop the data (nothing enqueued)")
}

// TestRelayExecutor_WriteData_DropsWhenFull verifies the default-branch drop:
// when the input channel buffer is full (steward not consuming), WriteData must
// drop rather than block the WS goroutine.
func TestRelayExecutor_WriteData_DropsWhenFull(t *testing.T) {
	r := NewRelayExecutor()

	// Fill the buffered input channel to capacity.
	capacity := cap(r.inputCh)
	for i := 0; i < capacity; i++ {
		require.NoError(t, r.WriteData(context.Background(), []byte{byte(i)}))
	}
	require.Equal(t, capacity, len(r.InputChan()), "input channel must be full")

	// The next write must not block and must be dropped.
	done := make(chan struct{})
	go func() {
		_ = r.WriteData(context.Background(), []byte("overflow"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("WriteData blocked when input channel was full — must drop instead")
	}

	assert.Equal(t, capacity, len(r.InputChan()),
		"overflow write must be dropped, leaving the channel at capacity")
}

// TestRelayExecutor_Resize_ForwardsValue verifies the happy path for Resize.
func TestRelayExecutor_Resize_ForwardsValue(t *testing.T) {
	r := NewRelayExecutor()
	require.NoError(t, r.Resize(context.Background(), 120, 40))

	select {
	case dims := <-r.ResizeChan():
		assert.Equal(t, [2]int32{120, 40}, dims, "Resize must forward [cols, rows]")
	case <-time.After(time.Second):
		t.Fatal("expected dimensions on ResizeChan")
	}
}

// TestRelayExecutor_Resize_DropsWhenClosed verifies Resize drops after Close.
func TestRelayExecutor_Resize_DropsWhenClosed(t *testing.T) {
	r := NewRelayExecutor()
	require.NoError(t, r.Close(context.Background()))

	require.NoError(t, r.Resize(context.Background(), 100, 30),
		"Resize after Close must not error")

	assert.Equal(t, 0, len(r.ResizeChan()),
		"Resize after Close must drop (nothing enqueued)")
}

// TestRelayExecutor_Resize_DropsWhenFull verifies the default-branch drop for
// Resize when the resize channel buffer is full.
func TestRelayExecutor_Resize_DropsWhenFull(t *testing.T) {
	r := NewRelayExecutor()

	capacity := cap(r.resizeCh)
	for i := 0; i < capacity; i++ {
		require.NoError(t, r.Resize(context.Background(), 80+i, 24))
	}
	require.Equal(t, capacity, len(r.ResizeChan()), "resize channel must be full")

	done := make(chan struct{})
	go func() {
		_ = r.Resize(context.Background(), 200, 50)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Resize blocked when resize channel was full — must drop instead")
	}

	assert.Equal(t, capacity, len(r.ResizeChan()),
		"overflow resize must be dropped, leaving the channel at capacity")
}
