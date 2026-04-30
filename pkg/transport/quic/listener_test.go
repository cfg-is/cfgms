// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors

package quic

import (
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultQuicConfig_TunedValues guards the intentional tuning decisions in
// defaultQuicConfig so that future refactors cannot silently regress them.
//
// HandshakeIdleTimeout 30s: quic-go defaults to 5s, which is too aggressive for
// macOS CI after many rapid socket open/close cycles (e.g. reconnect test suites).
// This value was deliberately increased; any change must be reviewed against
// macOS CI timing and documented.
func TestDefaultQuicConfig_TunedValues(t *testing.T) {
	cfg := defaultQuicConfig()

	if cfg.MaxIdleTimeout != 90*time.Second {
		t.Errorf("MaxIdleTimeout: want 90s, got %s (see Story #504 keepalive rationale)", cfg.MaxIdleTimeout)
	}
	if cfg.KeepAlivePeriod != 25*time.Second {
		t.Errorf("KeepAlivePeriod: want 25s, got %s (see Story #504 keepalive rationale)", cfg.KeepAlivePeriod)
	}
	if cfg.HandshakeIdleTimeout != 30*time.Second {
		t.Errorf("HandshakeIdleTimeout: want 30s, got %s (quic-go default 5s is too short for macOS CI under load)", cfg.HandshakeIdleTimeout)
	}
}

// TestListener_AcceptAndClose verifies that Accept returns a valid net.Conn
// with correct address fields.
func TestListener_AcceptAndClose(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)

	// Addr should be a valid non-empty address.
	require.NotNil(t, lis.Addr())
	assert.NotEmpty(t, lis.Addr().String())

	// Accept in a goroutine.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, aerr := lis.Accept()
		acceptCh <- acceptResult{conn: conn, err: aerr}
	}()

	// Dial and write a byte to trigger stream notification on the server side.
	clientConn, err := Dial(t.Context(), lis.Addr().String(), tlsPair.client, nil)
	require.NoError(t, err)
	defer func() { _ = clientConn.Close() }()

	_, err = clientConn.Write([]byte{0x00})
	require.NoError(t, err)

	// Wait for Accept with a bounded timeout.
	select {
	case result := <-acceptCh:
		require.NoError(t, result.err)
		require.NotNil(t, result.conn)
		assert.NotNil(t, result.conn.LocalAddr())
		assert.NotNil(t, result.conn.RemoteAddr())
		_ = result.conn.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Accept")
	}

	require.NoError(t, lis.Close())
}

// TestDefaultQuicConfig_Fields verifies all DoS-resilience field values set by
// defaultQuicConfig so that future refactors cannot silently regress them.
func TestDefaultQuicConfig_Fields(t *testing.T) {
	cfg := defaultQuicConfig()

	assert.Equal(t, int64(1), cfg.MaxIncomingStreams,
		"MaxIncomingStreams: one bidirectional stream per QUIC connection is the design contract (doc.go:17)")
	assert.Equal(t, int64(-1), cfg.MaxIncomingUniStreams,
		"MaxIncomingUniStreams: gRPC uses only bidirectional streams; unidirectional must be disabled")
	assert.Equal(t, uint64(512*1024), cfg.InitialStreamReceiveWindow,
		"InitialStreamReceiveWindow: 512 KB explicit default; set to document and protect the choice")
	assert.Equal(t, uint64(1*1024*1024), cfg.InitialConnectionReceiveWindow,
		"InitialConnectionReceiveWindow: 1 MB; with MaxIncomingStreams=1 effectively same as stream window")
	assert.False(t, cfg.Allow0RTT,
		"Allow0RTT: false; 0-RTT allows replay of early data, insecure for mTLS connections")
	assert.False(t, cfg.DisablePathMTUDiscovery,
		"DisablePathMTUDiscovery: false; MTU discovery is safe and useful, set explicitly to document intent")
}

// TestRequireAddressValidation verifies that requireAddressValidation allows verified
// addresses and rejects unverified ones.
func TestRequireAddressValidation(t *testing.T) {
	verified := &quicgo.ClientInfo{AddrVerified: true}
	cfg, err := requireAddressValidation(verified)
	assert.Nil(t, cfg, "verified address: config override should be nil (use server defaults)")
	assert.NoError(t, err, "verified address must be allowed")

	unverified := &quicgo.ClientInfo{AddrVerified: false}
	cfg, err = requireAddressValidation(unverified)
	assert.Nil(t, cfg, "unverified address: config override should be nil")
	assert.Error(t, err, "unverified address must be rejected")
}

// TestListen_RequiresAddressValidation verifies that address validation is configured
// on every listener and that honest clients are not blocked.
func TestListen_RequiresAddressValidation(t *testing.T) {
	// This test verifies Retry transparency: honest clients respond to Retry
	// tokens automatically via quic-go's built-in handling. It does NOT test
	// adversarial IP-spoofing rejection, which requires a crafted UDP packet
	// outside the scope of unit testing.

	tlsPair := newTestTLSPair(t)

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	// (1) GetConfigForClient must be non-nil on the effective listener config.
	require.NotNil(t, lis.cfg, "effective QUIC config must be stored on the listener")
	assert.NotNil(t, lis.cfg.GetConfigForClient,
		"GetConfigForClient must be injected by Listen() for address validation")

	// (2) A normal Dial+Listen round-trip must succeed: honest clients are not blocked.
	acceptCh := make(chan error, 1)
	go func() {
		conn, aerr := lis.Accept()
		if aerr == nil {
			_ = conn.Close()
		}
		acceptCh <- aerr
	}()

	clientConn, err := Dial(t.Context(), lis.Addr().String(), tlsPair.client, nil)
	require.NoError(t, err, "honest client must connect successfully despite address validation")
	defer func() { _ = clientConn.Close() }()

	_, err = clientConn.Write([]byte{0x00})
	require.NoError(t, err)

	select {
	case aerr := <-acceptCh:
		require.NoError(t, aerr, "honest client must not be blocked by address validation")
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Accept — honest client may have been blocked")
	}
}

// TestListen_PreservesCallerGetConfigForClient verifies that Listen() does not
// overwrite a caller-provided GetConfigForClient callback.
func TestListen_PreservesCallerGetConfigForClient(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	customCalled := false
	customCallback := func(info *quicgo.ClientInfo) (*quicgo.Config, error) {
		customCalled = true
		return nil, nil
	}

	customCfg := &quicgo.Config{
		GetConfigForClient: customCallback,
	}

	lis, err := Listen("127.0.0.1:0", tlsPair.server, customCfg)
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	// The caller's GetConfigForClient must be preserved, not overwritten.
	assert.NotNil(t, lis.cfg.GetConfigForClient, "GetConfigForClient must remain non-nil")

	// Verify it's the caller's callback (not requireAddressValidation) by calling it.
	_, _ = lis.cfg.GetConfigForClient(&quicgo.ClientInfo{AddrVerified: true})
	assert.True(t, customCalled, "Listen() must not overwrite a caller-provided GetConfigForClient")
}

// TestListen_DoesNotMutateCallerConfig verifies that Listen() does not modify
// the caller's *quicgo.Config pointer in-place.
func TestListen_DoesNotMutateCallerConfig(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	callerCfg := &quicgo.Config{
		MaxIdleTimeout: 60 * time.Second,
		// GetConfigForClient is intentionally nil to verify Listen() doesn't set it on the caller's struct.
	}

	lis, err := Listen("127.0.0.1:0", tlsPair.server, callerCfg)
	require.NoError(t, err)
	defer func() { _ = lis.Close() }()

	// Listen() must inject GetConfigForClient only on its internal copy, not on the caller's struct.
	assert.Nil(t, callerCfg.GetConfigForClient,
		"Listen() must not mutate the caller's *quicgo.Config in-place")
}

// TestListener_CloseUnblocksAccept verifies that Close causes a blocked Accept
// to return with an error rather than hanging indefinitely.
func TestListener_CloseUnblocksAccept(t *testing.T) {
	tlsPair := newTestTLSPair(t)

	lis, err := Listen("127.0.0.1:0", tlsPair.server, nil)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		_, aerr := lis.Accept()
		errCh <- aerr
	}()

	// Close the listener, which should unblock Accept.
	require.NoError(t, lis.Close())

	select {
	case err := <-errCh:
		assert.Error(t, err, "Accept should return an error after Close")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Accept to unblock after Close")
	}
}
