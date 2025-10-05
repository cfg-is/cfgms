package mochi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

func TestBroker_Name(t *testing.T) {
	broker := New()
	assert.Equal(t, "mochi", broker.Name())
}

func TestBroker_Description(t *testing.T) {
	broker := New()
	assert.Contains(t, broker.Description(), "mochi-mqtt")
}

func TestBroker_Initialize(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]interface{}{
				"listen_addr":    "127.0.0.1:0",
				"enable_tls":     false,
				"inline_client":  true,
				"max_clients":    1000,
				"max_message_size": 1048576,
			},
			wantErr: false,
		},
		{
			name: "empty config uses defaults",
			config: map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "invalid duration",
			config: map[string]interface{}{
				"inflight_expiry": "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broker := New()
			err := broker.Initialize(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBroker_StartStop(t *testing.T) {
	broker := New()

	// Initialize with non-TLS for testing
	err := broker.Initialize(map[string]interface{}{
		"listen_addr":   "127.0.0.1:0",
		"enable_tls":    false,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Start broker
	err = broker.Start(ctx)
	require.NoError(t, err)

	// Verify running
	assert.True(t, broker.running)

	// Try to start again (should fail)
	err = broker.Start(ctx)
	assert.Error(t, err)

	// Stop broker
	err = broker.Stop(ctx)
	require.NoError(t, err)

	// Verify stopped
	assert.False(t, broker.running)

	// Stop again (should succeed - idempotent)
	err = broker.Stop(ctx)
	assert.NoError(t, err)
}

func TestBroker_PublishSubscribe(t *testing.T) {
	broker := New()

	// Initialize with non-TLS
	err := broker.Initialize(map[string]interface{}{
		"listen_addr":   "127.0.0.1:0",
		"enable_tls":    false,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Start broker
	err = broker.Start(ctx)
	require.NoError(t, err)
	defer broker.Stop(ctx)

	// Test publish
	err = broker.Publish(ctx, "test/topic", []byte("hello"), 0, false)
	assert.NoError(t, err)

	// Test subscribe (note: actual message delivery requires inline client)
	handler := func(topic string, payload []byte, qos byte, retained bool) error {
		assert.Equal(t, "test/topic", topic)
		assert.Equal(t, []byte("hello"), payload)
		return nil
	}

	err = broker.Subscribe(ctx, "test/topic", 0, handler)
	assert.NoError(t, err)

	// Test unsubscribe
	err = broker.Unsubscribe(ctx, "test/topic")
	assert.NoError(t, err)
}

func TestBroker_GetStats(t *testing.T) {
	broker := New()

	// Initialize
	err := broker.Initialize(map[string]interface{}{
		"listen_addr":   "127.0.0.1:0",
		"enable_tls":    false,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Stats before start should fail
	_, err = broker.GetStats(ctx)
	assert.Error(t, err)

	// Start broker
	err = broker.Start(ctx)
	require.NoError(t, err)
	defer broker.Stop(ctx)

	// Wait briefly for server to fully initialize stats
	time.Sleep(10 * time.Millisecond)

	// Get stats
	stats, err := broker.GetStats(ctx)
	require.NoError(t, err)

	// Verify stats structure
	assert.GreaterOrEqual(t, stats.ClientsConnected, int64(0))
	assert.Greater(t, stats.Uptime, time.Duration(0))
}

func TestBroker_Available(t *testing.T) {
	tests := []struct {
		name      string
		config    map[string]interface{}
		available bool
	}{
		{
			name: "non-TLS always available",
			config: map[string]interface{}{
				"enable_tls": false,
			},
			available: true,
		},
		{
			name: "TLS without certs not available",
			config: map[string]interface{}{
				"enable_tls": true,
			},
			available: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broker := New()
			err := broker.Initialize(tt.config)
			require.NoError(t, err)

			available, err := broker.Available()
			if tt.available {
				assert.True(t, available)
			} else {
				assert.False(t, available)
				assert.Error(t, err)
			}
		})
	}
}

func TestBroker_GetCapabilities(t *testing.T) {
	broker := New()

	err := broker.Initialize(map[string]interface{}{
		"max_clients": 5000,
		"max_message_size": float64(2097152),
	})
	require.NoError(t, err)

	caps := broker.GetCapabilities()

	assert.Equal(t, 5000, caps.MaxClients)
	assert.Equal(t, int64(2097152), caps.MaxMessageSize)
	assert.True(t, caps.SupportsMQTT311)
	assert.True(t, caps.SupportsMQTT5)
	assert.True(t, caps.SupportsTLS)
	assert.False(t, caps.SupportsPersistence)
	assert.False(t, caps.SupportsClustering)
	assert.Equal(t, byte(2), caps.MaxQoS)
}

func TestBroker_GetListenAddress(t *testing.T) {
	broker := New()

	err := broker.Initialize(map[string]interface{}{
		"listen_addr": "127.0.0.1:1883",
		"enable_tls":  false,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = broker.Start(ctx)
	require.NoError(t, err)
	defer broker.Stop(ctx)

	addr := broker.GetListenAddress()
	assert.Equal(t, "127.0.0.1:1883", addr)
}

func TestBroker_AuthHandlers(t *testing.T) {
	broker := New()

	// Set auth handler
	broker.SetAuthHandler(func(clientID, username, password string) bool {
		return username == "valid"
	})

	// Set ACL handler
	broker.SetACLHandler(func(clientID, topic, operation string) bool {
		return operation == "subscribe"
	})

	assert.NotNil(t, broker.authHandler)
	assert.NotNil(t, broker.aclHandler)
}

func TestBroker_Registration(t *testing.T) {
	// Test that the broker is registered via init()
	broker := interfaces.GetBroker("mochi")
	require.NotNil(t, broker)
	assert.Equal(t, "mochi", broker.Name())
}
