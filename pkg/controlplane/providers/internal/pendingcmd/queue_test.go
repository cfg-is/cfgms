// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package pendingcmd

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/controlplane/types"
)

func cmd(id string) *types.SignedCommand {
	return &types.SignedCommand{Command: types.Command{ID: id}}
}

// recorder is a handler that records command IDs in the order it sees them.
type recorder struct {
	mu  sync.Mutex
	ids []string
}

func (r *recorder) handle(_ context.Context, sc *types.SignedCommand) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, sc.Command.ID)
	return nil
}

func (r *recorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...)
}

// drainSync runs Drain to completion on the calling goroutine.
func drainSync(q *Queue) {
	q.Drain(func(h func(context.Context, *types.SignedCommand) error, sc *types.SignedCommand) {
		_ = h(context.Background(), sc)
	})
}

func TestQueue_HoldsCommandsUntilSubscribe(t *testing.T) {
	q := New(8)

	for _, id := range []string{"a", "b", "c"} {
		h, dropped := q.Admit(cmd(id))
		assert.Nil(t, h, "no handler is subscribed, so the command must be held")
		assert.False(t, dropped)
	}

	rec := &recorder{}
	require.True(t, q.Subscribe(rec.handle), "Subscribe must report a backlog to drain")
	drainSync(q)

	assert.Equal(t, []string{"a", "b", "c"}, rec.seen(), "held commands are delivered in arrival order")
}

func TestQueue_LiveAfterSubscribeWithEmptyBacklog(t *testing.T) {
	q := New(8)
	rec := &recorder{}
	assert.False(t, q.Subscribe(rec.handle), "no backlog, nothing to drain")

	h, dropped := q.Admit(cmd("live"))
	require.NotNil(t, h, "a subscribed queue with no backlog dispatches live")
	assert.False(t, dropped)
}

// Commands that arrive while the backlog drains are queued behind it, so a
// command received earlier is never handled after one received later.
func TestQueue_CommandsDuringDrainQueueBehindBacklog(t *testing.T) {
	q := New(8)
	_, _ = q.Admit(cmd("first"))

	rec := &recorder{}
	require.True(t, q.Subscribe(rec.handle))

	h, _ := q.Admit(cmd("second"))
	assert.Nil(t, h, "while draining, a new command must queue behind the backlog")

	drainSync(q)
	assert.Equal(t, []string{"first", "second"}, rec.seen())

	h, _ = q.Admit(cmd("third"))
	assert.NotNil(t, h, "once drained, commands dispatch live again")
}

func TestQueue_OverflowIsReported(t *testing.T) {
	q := New(2)
	_, dropped := q.Admit(cmd("a"))
	assert.False(t, dropped)
	_, dropped = q.Admit(cmd("b"))
	assert.False(t, dropped)
	_, dropped = q.Admit(cmd("c"))
	assert.True(t, dropped, "a command beyond the limit must be reported as dropped")

	rec := &recorder{}
	require.True(t, q.Subscribe(rec.handle))
	drainSync(q)
	assert.Equal(t, []string{"a", "b"}, rec.seen(), "the earliest commands are kept")
}

func TestQueue_ResetClearsHandlerAndBacklog(t *testing.T) {
	q := New(8)
	_, _ = q.Admit(cmd("stale"))
	q.Reset()

	rec := &recorder{}
	assert.False(t, q.Subscribe(rec.handle), "Reset must discard the backlog")

	q.Reset()
	h, _ := q.Admit(cmd("after-reset"))
	assert.Nil(t, h, "Reset must clear the handler")
}

// Concurrent admits while a drain runs must deliver every command exactly once.
func TestQueue_ConcurrentAdmitDuringDrain(t *testing.T) {
	const n = 200
	q := New(n * 2)
	for i := 0; i < n/2; i++ {
		_, _ = q.Admit(cmd(fmt.Sprintf("pre-%d", i)))
	}

	rec := &recorder{}
	require.True(t, q.Subscribe(rec.handle))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		drainSync(q)
	}()
	for i := 0; i < n/2; i++ {
		if h, _ := q.Admit(cmd(fmt.Sprintf("post-%d", i))); h != nil {
			_ = h(context.Background(), cmd(fmt.Sprintf("post-%d", i)))
		}
	}
	wg.Wait()

	require.Eventually(t, func() bool { return len(rec.seen()) == n }, 2*time.Second, time.Millisecond)
	seen := map[string]int{}
	for _, id := range rec.seen() {
		seen[id]++
	}
	for id, count := range seen {
		assert.Equal(t, 1, count, "command %s delivered %d times", id, count)
	}
	pre := rec.seen()[:n/2]
	for i, id := range pre {
		assert.Equal(t, fmt.Sprintf("pre-%d", i), id, "the backlog is delivered first, in order")
	}
}
