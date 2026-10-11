// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package commands

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// TestHandleCommand_ReceivedEventObservesInFlightExecution guards the ordering
// of the in-flight registration against the "received" status event (Issue
// #4904). A caller that reacts to the event by calling Wait — as a test cleanup
// does once it has seen the event — must not race WaitGroup.Add. Run under
// -race: with Add after the event, Wait at a zero counter races the Add.
func TestHandleCommand_ReceivedEventObservesInFlightExecution(t *testing.T) {
	for i := 0; i < 200; i++ {
		waited := make(chan struct{})
		var h *Handler
		h, err := New(&Config{
			StewardID: "steward-test",
			Logger:    newTestLogger(t),
			OnStatus: func(_ context.Context, ev *cpTypes.Event) {
				if ev.Type == cpTypes.EventCommandReceived {
					go func() {
						h.Wait()
						close(waited)
					}()
				}
			},
		})
		require.NoError(t, err)

		cmd := &cpTypes.SignedCommand{Command: cpTypes.Command{
			ID:        fmt.Sprintf("cmd-%d", i),
			Type:      cpTypes.CommandSyncConfig,
			StewardID: "steward-test",
			Timestamp: time.Now(),
		}}
		require.NoError(t, h.HandleCommand(context.Background(), cmd))

		select {
		case <-waited:
		case <-time.After(10 * time.Second):
			t.Fatal("Wait never returned for an accepted command")
		}
	}
}
