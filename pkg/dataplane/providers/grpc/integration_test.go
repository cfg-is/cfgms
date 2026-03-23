// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"

	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationEnv holds a matched server + client provider pair for integration tests.
type integrationEnv struct {
	serverProvider *Provider
	clientProvider *Provider
	serverSession  interfaces.DataPlaneSession
	clientSession  interfaces.DataPlaneSession
}

// newIntegrationEnv creates a matched server and client connected over real QUIC+mTLS.
func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()

	serverTLS, clientTLS := newTestTLSConfigs(t)

	// Start server
	sp := New()
	err := sp.Initialize(context.Background(), map[string]interface{}{
		"mode":        "server",
		"listen_addr": "127.0.0.1:0",
		"tls_config":  serverTLS,
	})
	require.NoError(t, err)

	err = sp.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sp.Stop(context.Background()) })

	listenAddr := sp.listenAddress()

	// Start client
	cp := New()
	err = cp.Initialize(context.Background(), map[string]interface{}{
		"mode":        "client",
		"server_addr": listenAddr,
		"tls_config":  clientTLS,
		"steward_id":  "steward-int-test",
	})
	require.NoError(t, err)

	err = cp.Start(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = cp.Stop(context.Background()) })

	return &integrationEnv{
		serverProvider: sp,
		clientProvider: cp,
	}
}

// getSessions creates server and client sessions for a test.
func (e *integrationEnv) getSessions(t *testing.T) (serverSess, clientSess interfaces.DataPlaneSession) {
	t.Helper()

	serverSess, err := e.serverProvider.AcceptConnection(context.Background())
	require.NoError(t, err)

	clientSess, err = e.clientProvider.Connect(context.Background(), "")
	require.NoError(t, err)

	return serverSess, clientSess
}

// newTestTLSConfigs creates matched server and client TLS configs for integration tests.
func newTestTLSConfigs(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	serverCert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	serverTLS, err = cfgcert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM,
		caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   "steward-int-test",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	clientTLS, err = cfgcert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM,
		caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)
	clientTLS.NextProtos = []string{quictransport.ALPNProtocol}

	return serverTLS, clientTLS
}

// TestGRPC_ConfigSync verifies server and client exchange config via SyncConfig RPC.
func TestGRPC_ConfigSync(t *testing.T) {
	env := newIntegrationEnv(t)
	serverSess, clientSess := env.getSessions(t)

	cfg := &types.ConfigTransfer{
		ID:        "cfg-sync-test",
		StewardID: "steward-int-test",
		TenantID:  "tenant-1",
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Truncate(time.Millisecond),
		Data:      []byte(`{"firewall":{"enabled":true}}`),
	}

	var received *types.ConfigTransfer
	var receiveErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received, receiveErr = clientSess.ReceiveConfig(context.Background())
	}()

	// Server sends after a short pause to let client initiate the RPC
	time.Sleep(50 * time.Millisecond)
	err := serverSess.SendConfig(context.Background(), cfg)
	require.NoError(t, err)

	wg.Wait()

	require.NoError(t, receiveErr)
	require.NotNil(t, received)
	assert.Equal(t, cfg.ID, received.ID)
	assert.Equal(t, cfg.Version, received.Version)
	assert.Equal(t, cfg.Data, received.Data)
}

// TestGRPC_DNASync verifies a steward streams DNA to the controller via SyncDNA RPC.
func TestGRPC_DNASync(t *testing.T) {
	env := newIntegrationEnv(t)
	serverSess, clientSess := env.getSessions(t)

	dna := &types.DNATransfer{
		ID:         "dna-sync-test",
		StewardID:  "steward-int-test",
		TenantID:   "tenant-1",
		Attributes: []byte(`{"os":"linux","arch":"arm64","hostname":"dev-01"}`),
		Delta:      false,
	}

	var received *types.DNATransfer
	var receiveErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received, receiveErr = serverSess.ReceiveDNA(context.Background())
	}()

	time.Sleep(50 * time.Millisecond)
	err := clientSess.SendDNA(context.Background(), dna)
	require.NoError(t, err)

	wg.Wait()

	require.NoError(t, receiveErr)
	require.NotNil(t, received)
	assert.Equal(t, dna.ID, received.ID)
	assert.Equal(t, dna.StewardID, received.StewardID)
	assert.Equal(t, dna.Attributes, received.Attributes)
	assert.Equal(t, dna.Delta, received.Delta)
}

// TestGRPC_BulkTransfer verifies bidirectional bulk transfer via BulkTransfer RPC.
func TestGRPC_BulkTransfer(t *testing.T) {
	env := newIntegrationEnv(t)
	_, clientSess := env.getSessions(t)

	data := []byte("bulk payload for transfer test")
	bulk := &types.BulkTransfer{
		ID:        "bulk-test",
		StewardID: "steward-int-test",
		TenantID:  "tenant-1",
		Direction: "to_controller",
		Type:      "logs",
		TotalSize: int64(len(data)),
		Data:      data,
		Metadata:  map[string]string{"filename": "app.log"},
	}

	// Client sends bulk data (to_controller direction)
	err := clientSess.SendBulk(context.Background(), bulk)
	require.NoError(t, err)
}

// TestGRPC_LargeConfigSync verifies a 1 MB config syncs correctly over multiple chunks.
func TestGRPC_LargeConfigSync(t *testing.T) {
	env := newIntegrationEnv(t)
	serverSess, clientSess := env.getSessions(t)

	// 1 MB payload
	payload := bytes.Repeat([]byte("L"), 1024*1024)
	cfg := &types.ConfigTransfer{
		ID:        "large-cfg",
		StewardID: "steward-int-test",
		TenantID:  "tenant-1",
		Version:   "2.0.0",
		Data:      payload,
	}

	var received *types.ConfigTransfer
	var receiveErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		received, receiveErr = clientSess.ReceiveConfig(context.Background())
	}()

	time.Sleep(50 * time.Millisecond)
	err := serverSess.SendConfig(context.Background(), cfg)
	require.NoError(t, err)

	wg.Wait()

	require.NoError(t, receiveErr)
	require.NotNil(t, received)
	assert.Equal(t, cfg.ID, received.ID)
	assert.Equal(t, payload, received.Data)
}

// TestGRPC_ConcurrentTransfers verifies 5 simultaneous config syncs on the same server.
//
// In the shared-queue model, the server handler processes incoming RPC calls
// in arrival order. Each server session dequeues the next pending request from
// the shared channel regardless of which client sent it. This test verifies
// that all 5 transfers complete without error (no deadlock, no data loss).
// It does not assert a 1-to-1 mapping between a specific server session and
// the client goroutine that sent the matching config.
func TestGRPC_ConcurrentTransfers(t *testing.T) {
	env := newIntegrationEnv(t)

	const numTransfers = 5
	var wg sync.WaitGroup

	// Track completed transfers
	var mu sync.Mutex
	completedIDs := make([]string, 0, numTransfers)

	for i := 0; i < numTransfers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			serverSess, clientSess := env.getSessions(t)

			cfg := &types.ConfigTransfer{
				ID:        fmt.Sprintf("concurrent-cfg-%d", i),
				StewardID: "steward-int-test",
				Version:   "1.0.0",
				Data:      []byte(fmt.Sprintf(`{"index":%d}`, i)),
			}

			var received *types.ConfigTransfer
			var receiveErr error
			var inner sync.WaitGroup
			inner.Add(1)
			go func() {
				defer inner.Done()
				received, receiveErr = clientSess.ReceiveConfig(context.Background())
			}()

			time.Sleep(20 * time.Millisecond)
			err := serverSess.SendConfig(context.Background(), cfg)
			assert.NoError(t, err, "goroutine %d SendConfig", i)

			inner.Wait()
			assert.NoError(t, receiveErr, "goroutine %d ReceiveConfig", i)
			if received != nil {
				// Verify the received config has a valid concurrent-cfg-N ID
				assert.Contains(t, received.ID, "concurrent-cfg-",
					"goroutine %d: received config should be one of the concurrent configs", i)
				mu.Lock()
				completedIDs = append(completedIDs, received.ID)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// All 5 transfers should have completed
	mu.Lock()
	assert.Len(t, completedIDs, numTransfers, "all concurrent transfers should complete")
	mu.Unlock()
}
