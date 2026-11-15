// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestTransportAddressHook_OnConnect_SendsOneCommandMatchingRegistration(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	publisher, received := newDrainHookTestPublisher(t, "steward-s")
	transport := &controllerconfig.TransportConfig{ListenAddr: "0.0.0.0:4433", ExternalAddress: "external.example"}

	hook := service.NewTransportAddressHook(transport, nil, logging.NewNoopLogger())
	hook.SetPublisher(publisher)
	require.NoError(t, hook.OnConnect(context.Background(), "steward-s"))

	want, err := transport.ResolveAdvertisedAddress()
	require.NoError(t, err)
	require.Equal(t, "external.example:4433", want)

	select {
	case sc := <-received:
		require.NotNil(t, sc.Command)
		assert.Equal(t, controlplaneTypes.CommandAdvertiseTransportAddress, sc.Command.Type)
		assert.Equal(t, "steward-s", sc.Command.StewardID)
		assert.Equal(t, want, sc.Command.Params[controlplaneTypes.ParamTransportAddress])
	case <-time.After(2 * time.Second):
		t.Fatal("steward never received the advertise command")
	}
	select {
	case extra := <-received:
		t.Fatalf("expected exactly one command, got a second: %s", extra.Command.Type)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTransportAddressHook_OnConnect_FallbackMatchesRegistration(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	publisher, received := newDrainHookTestPublisher(t, "steward-s")
	transport := &controllerconfig.TransportConfig{ListenAddr: "192.168.1.10:4433"}

	hook := service.NewTransportAddressHook(transport, publisher, logging.NewNoopLogger())
	require.NoError(t, hook.OnConnect(context.Background(), "steward-s"))

	select {
	case sc := <-received:
		assert.Equal(t, "192.168.1.10:4433", sc.Command.Params[controlplaneTypes.ParamTransportAddress])
	case <-time.After(2 * time.Second):
		t.Fatal("steward never received the advertise command")
	}
}

func TestTransportAddressHook_OnConnect_UnresolvableAddressSendsNothing(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	publisher, received := newDrainHookTestPublisher(t, "steward-s")
	transport := &controllerconfig.TransportConfig{ListenAddr: "0.0.0.0:4433"}

	hook := service.NewTransportAddressHook(transport, publisher, logging.NewNoopLogger())
	require.NoError(t, hook.OnConnect(context.Background(), "steward-s"))

	select {
	case sc := <-received:
		t.Fatalf("no command expected, got %s", sc.Command.Type)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTransportAddressHook_OnConnect_NilPublisherSendsNothing(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	transport := &controllerconfig.TransportConfig{ListenAddr: "192.168.1.10:4433"}
	hook := service.NewTransportAddressHook(transport, nil, logging.NewNoopLogger())
	require.NoError(t, hook.OnConnect(context.Background(), "steward-s"))
}

func TestTransportAddressHook_OnConnect_NilConfigSendsNothing(t *testing.T) {
	publisher, received := newDrainHookTestPublisher(t, "steward-s")
	hook := service.NewTransportAddressHook(nil, publisher, logging.NewNoopLogger())
	require.NoError(t, hook.OnConnect(context.Background(), "steward-s"))

	select {
	case sc := <-received:
		t.Fatalf("no command expected, got %s", sc.Command.Type)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTransportAddressHook_OnConnect_PublishErrorReturned(t *testing.T) {
	t.Setenv("CFGMS_EXTERNAL_HOSTNAME", "")
	// No client is connected for steward-unknown, so the publish fails; the hook
	// returns that error (only ErrStewardLockedDown is swallowed).
	publisher, _ := newDrainHookTestPublisher(t, "steward-other")
	transport := &controllerconfig.TransportConfig{ListenAddr: "192.168.1.10:4433"}

	hook := service.NewTransportAddressHook(transport, publisher, logging.NewNoopLogger())
	require.Error(t, hook.OnConnect(context.Background(), "steward-unknown"))
}

// A nil hook (no signer configured, so none was built) must tolerate the
// server's unconditional SetPublisher wiring and OnConnect.
func TestTransportAddressHook_NilReceiverIsNoOp(t *testing.T) {
	publisher, _ := newDrainHookTestPublisher(t, "steward-s")
	var hook *service.TransportAddressHook
	require.NotPanics(t, func() { hook.SetPublisher(publisher) })
	require.NoError(t, hook.OnConnect(context.Background(), "steward-s"))
}
