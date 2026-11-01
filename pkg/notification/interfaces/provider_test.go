// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/notification/interfaces"
)

// recorder is a real, in-memory Notifier implementation used to exercise the
// registry and the contract without a network.
type recorder struct{ sent int }

func (r *recorder) Name() string { return "recorder" }
func (r *recorder) Send(_ context.Context, m interfaces.Message) (*interfaces.DeliveryResult, error) {
	res := &interfaces.DeliveryResult{}
	for _, to := range m.To {
		res.Recipients = append(res.Recipients, interfaces.RecipientResult{Address: to, Accepted: true})
	}
	r.sent++
	return res, nil
}

type recorderProvider struct{ name string }

func (p recorderProvider) Name() string        { return p.name }
func (p recorderProvider) Description() string { return "test" }
func (p recorderProvider) CreateNotifier(cfg map[string]interface{}) (interfaces.Notifier, error) {
	return &recorder{}, nil
}

func TestRegistry(t *testing.T) {
	const name = "registry-test"
	interfaces.RegisterNotifierProvider(recorderProvider{name})
	t.Cleanup(func() { interfaces.UnregisterNotifierProvider(name) })

	p, err := interfaces.GetNotifierProvider(name)
	require.NoError(t, err)
	assert.Equal(t, name, p.Name())
	assert.Contains(t, interfaces.GetRegisteredProviderNames(), name)

	n, err := interfaces.CreateNotifierFromConfig(name, nil)
	require.NoError(t, err)
	assert.Equal(t, "recorder", n.Name())

	assert.Panics(t, func() { interfaces.RegisterNotifierProvider(recorderProvider{name}) }, "duplicate")
	assert.Panics(t, func() { interfaces.RegisterNotifierProvider(recorderProvider{""}) }, "empty name")
	assert.Panics(t, func() { interfaces.RegisterNotifierProvider(nil) }, "nil")
}

func TestUnknownProvider(t *testing.T) {
	_, err := interfaces.GetNotifierProvider("nope")
	require.ErrorIs(t, err, interfaces.ErrUnknownProvider)
	_, err = interfaces.CreateNotifierFromConfig("nope", nil)
	require.ErrorIs(t, err, interfaces.ErrUnknownProvider)
}

func TestDeliveryResultHelpers(t *testing.T) {
	r := &interfaces.DeliveryResult{Recipients: []interfaces.RecipientResult{
		{Address: "a", Accepted: true}, {Address: "b", Reason: "no"},
	}}
	assert.Equal(t, []string{"a"}, r.Accepted())
	require.Len(t, r.Failed(), 1)
	assert.Equal(t, "b", r.Failed()[0].Address)
}
