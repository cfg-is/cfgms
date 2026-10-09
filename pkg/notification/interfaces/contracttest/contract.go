// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package contracttest holds the provider-neutral behavior every notification
// provider must exhibit. Provider test suites call Run with a Notifier wired
// to a real (test) backend.
package contracttest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/notification/interfaces"
)

// Harness describes the backend behind the Notifier under test.
type Harness struct {
	// Notifier is the provider instance under test.
	Notifier interfaces.Notifier
	// GoodAddress is accepted by the backend; RejectedAddress is refused by it.
	GoodAddress, RejectedAddress string
	// Sent reports how many connections/requests the backend has seen so far,
	// so the contract can prove validation happens before network activity.
	Sent func() int
}

// Run executes the contract.
func Run(t *testing.T, h Harness) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("has a name", func(t *testing.T) {
		assert.NotEmpty(t, h.Notifier.Name())
	})

	t.Run("rejects empty recipients", func(t *testing.T) {
		before := h.Sent()
		res, err := h.Notifier.Send(ctx, interfaces.Message{Subject: "s", Body: "b"})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, before, h.Sent())
	})

	t.Run("rejects header injection before network activity", func(t *testing.T) {
		cases := map[string]interfaces.Message{
			"subject CR":  {To: []string{h.GoodAddress}, Subject: "a\rBcc: x@example.com", Body: "b"},
			"subject LF":  {To: []string{h.GoodAddress}, Subject: "a\nBcc: x@example.com", Body: "b"},
			"address CR":  {To: []string{"a@example.com\rBcc: x@example.com"}, Subject: "s", Body: "b"},
			"address LF":  {To: []string{"a@example.com\nBcc: x@example.com"}, Subject: "s", Body: "b"},
			"bad address": {To: []string{"not an address"}, Subject: "s", Body: "b"},
		}
		for name, msg := range cases {
			t.Run(name, func(t *testing.T) {
				before := h.Sent()
				res, err := h.Notifier.Send(ctx, msg)
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, before, h.Sent(), "no network activity expected")
			})
		}
	})

	t.Run("reports per-recipient results", func(t *testing.T) {
		res, err := h.Notifier.Send(ctx, interfaces.Message{
			To:      []string{h.GoodAddress, h.RejectedAddress},
			Subject: "contract", Body: "hello",
		})
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Len(t, res.Recipients, 2)
		assert.True(t, res.Recipients[0].Accepted)
		assert.False(t, res.Recipients[1].Accepted)
		assert.NotEmpty(t, res.Recipients[1].Reason)
	})
}
