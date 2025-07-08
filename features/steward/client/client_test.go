package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
)

func TestNew(t *testing.T) {
	logger := logging.NewLogger("debug")

	tests := []struct {
		name           string
		controllerAddr string
		useCerts       bool
		expectError    bool
	}{
		{
			name:           "valid parameters",
			controllerAddr: "localhost:8080",
			useCerts:       true,
			expectError:    false,
		},
		{
			name:           "missing controller address",
			controllerAddr: "",
			useCerts:       true,
			expectError:    true,
		},
		{
			name:           "missing cert path",
			controllerAddr: "localhost:8080",
			useCerts:       false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var certPath string
			var cleanup func()
			
			if tt.useCerts {
				certPath, cleanup = testutil.SetupTestCerts(t)
				t.Cleanup(cleanup)
			}
			
			client, err := New(tt.controllerAddr, certPath, logger)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.controllerAddr, client.controllerAddr)
				assert.Equal(t, certPath, client.certPath)
				assert.False(t, client.IsConnected())
				assert.False(t, client.IsRegistered())
			}
		})
	}
}

func TestClientState(t *testing.T) {
	logger := logging.NewLogger("debug")
	
	// Set up test certificates
	certPath, cleanup := testutil.SetupTestCerts(t)
	t.Cleanup(cleanup)
	
	// Note: This test doesn't actually connect since we don't have a running server
	client, err := New("localhost:8080", certPath, logger)
	require.NoError(t, err)
	
	// Test initial state
	assert.False(t, client.IsConnected())
	assert.False(t, client.IsRegistered())
	assert.Empty(t, client.GetStewardID())
	assert.True(t, client.GetLastHeartbeat().IsZero())
	
	// Test manual state changes (for testing purposes)
	client.mu.Lock()
	client.connected = true
	client.stewardID = "test-steward-123"
	client.lastHeartbeat = time.Now()
	client.mu.Unlock()
	
	assert.True(t, client.IsConnected())
	assert.True(t, client.IsRegistered())
	assert.Equal(t, "test-steward-123", client.GetStewardID())
	assert.False(t, client.GetLastHeartbeat().IsZero())
}

func TestDisconnect(t *testing.T) {
	logger := logging.NewLogger("debug")
	
	// Set up test certificates
	certPath, cleanup := testutil.SetupTestCerts(t)
	t.Cleanup(cleanup)
	
	client, err := New("localhost:8080", certPath, logger)
	require.NoError(t, err)
	
	// Test disconnect when not connected (should not error)
	err = client.Disconnect()
	assert.NoError(t, err)
	
	// Test disconnect when connected (simulate connection)
	client.mu.Lock()
	client.connected = true
	client.mu.Unlock()
	
	err = client.Disconnect()
	assert.NoError(t, err)
	assert.False(t, client.IsConnected())
}