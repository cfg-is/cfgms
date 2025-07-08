// Package client provides gRPC client functionality for steward-controller communication.
//
// This package implements the steward-side gRPC client for communicating with
// the CFGMS controller. It handles mTLS authentication, registration, heartbeats,
// and DNA synchronization.
//
// Basic usage:
//
//	client, err := client.New(controllerAddr, certPath, logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//	
//	ctx := context.Background()
//	err = client.Connect(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//	
//	// Register with controller
//	stewardID, err := client.Register(ctx, version, dna)
//	if err != nil {
//		log.Fatal(err)
//	}
//
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	commonpb "github.com/cfgis/cfgms/api/proto"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Client provides gRPC client functionality for steward-controller communication.
//
// The client handles mTLS authentication, registration with the controller,
// heartbeat mechanism, and DNA synchronization. All operations are thread-safe
// and support context cancellation.
type Client struct {
	mu sync.RWMutex

	// Connection details
	controllerAddr string
	certPath       string
	logger         logging.Logger

	// gRPC connection and client
	conn   *grpc.ClientConn
	client controllerpb.ControllerClient

	// Authentication state
	credentials *commonpb.Credentials
	token       *commonpb.Token
	stewardID   string

	// Connection state
	connected bool
	
	// Health and heartbeat
	lastHeartbeat time.Time
	heartbeatInterval time.Duration
	heartbeatStop chan struct{}
	
	// Health monitoring callback (optional)
	healthCallback func(connected bool, success bool)
}

// New creates a new gRPC client for controller communication.
//
// The client will use mTLS authentication with certificates from the specified
// certPath directory. The directory should contain:
//   - client.crt: Client certificate
//   - client.key: Client private key  
//   - ca.crt: Certificate authority certificate
//
// Returns an error if certificate loading fails or if required parameters are missing.
func New(controllerAddr, certPath string, logger logging.Logger) (*Client, error) {
	if controllerAddr == "" {
		return nil, fmt.Errorf("controller address is required")
	}
	if certPath == "" {
		return nil, fmt.Errorf("certificate path is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Load credentials from certificate files
	creds, err := loadCredentials(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	return &Client{
		controllerAddr:    controllerAddr,
		certPath:          certPath,
		logger:            logger,
		credentials:       creds,
		heartbeatInterval: 30 * time.Second,
		heartbeatStop:     make(chan struct{}),
	}, nil
}

// Connect establishes a gRPC connection to the controller with mTLS authentication.
//
// This method loads the client certificates and establishes a secure connection
// to the controller. The connection includes keepalive settings for reliability.
//
// Returns an error if certificate loading or connection establishment fails.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil // Already connected
	}

	c.logger.Info("Connecting to controller", "addr", c.controllerAddr)

	// Load TLS credentials
	tlsCreds, err := c.loadTLSCredentials()
	if err != nil {
		return fmt.Errorf("failed to load TLS credentials: %w", err)
	}

	// Set up gRPC connection with keepalive
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	conn, err := grpc.DialContext(ctx, c.controllerAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to controller: %w", err)
	}

	c.conn = conn
	c.client = controllerpb.NewControllerClient(conn)
	c.connected = true

	c.logger.Info("Connected to controller successfully")
	return nil
}

// Disconnect closes the gRPC connection to the controller.
//
// This method stops the heartbeat mechanism and closes the connection.
// It's safe to call multiple times.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil // Already disconnected
	}

	c.logger.Info("Disconnecting from controller")

	// Stop heartbeat
	close(c.heartbeatStop)
	c.heartbeatStop = make(chan struct{})

	// Close connection
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.client = nil
		
		if err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	// Always set connected to false, even if conn was nil
	c.connected = false

	c.logger.Info("Disconnected from controller")
	return nil
}

// Register registers this steward with the controller.
//
// This method sends the steward's version information and initial DNA to the
// controller for registration. On success, it returns the assigned steward ID
// and starts the heartbeat mechanism.
//
// Returns an error if registration fails or if not connected to the controller.
func (c *Client) Register(ctx context.Context, version string, dna *commonpb.DNA) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return "", fmt.Errorf("not connected to controller")
	}

	c.logger.Info("Registering with controller", "version", version)

	req := &controllerpb.RegisterRequest{
		Version:     version,
		InitialDna:  dna,
		Credentials: c.credentials,
	}

	resp, err := c.client.AcceptRegistration(ctx, req)
	if err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}

	if resp.Status.Code != commonpb.Status_OK {
		return "", fmt.Errorf("registration rejected: %s", resp.Status.Message)
	}

	c.stewardID = resp.StewardId
	c.token = resp.Token

	c.logger.Info("Registered successfully", "steward_id", c.stewardID)

	// Start heartbeat mechanism
	go c.startHeartbeat()

	return c.stewardID, nil
}

// SendHeartbeat sends a heartbeat to the controller with current health metrics.
//
// This method is called automatically by the heartbeat mechanism but can also
// be called manually to send immediate status updates.
//
// Returns an error if the heartbeat fails or if not registered with the controller.
func (c *Client) SendHeartbeat(ctx context.Context, status string, metrics map[string]string) error {
	c.mu.RLock()
	stewardID := c.stewardID
	client := c.client
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("not connected to controller")
	}
	if stewardID == "" {
		return fmt.Errorf("not registered with controller")
	}

	req := &controllerpb.HeartbeatRequest{
		StewardId: stewardID,
		Status:    status,
		Metrics:   metrics,
	}

	resp, err := client.ProcessHeartbeat(ctx, req)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}

	if resp.Code != commonpb.Status_OK {
		return fmt.Errorf("heartbeat rejected: %s", resp.Message)
	}

	c.mu.Lock()
	c.lastHeartbeat = time.Now()
	c.mu.Unlock()

	return nil
}

// SyncDNA synchronizes the steward's DNA with the controller.
//
// This method sends the current DNA to the controller for synchronization.
// The controller may use this information for configuration targeting.
//
// Returns an error if synchronization fails or if not connected to the controller.
func (c *Client) SyncDNA(ctx context.Context, dna *commonpb.DNA) error {
	c.mu.RLock()
	client := c.client
	connected := c.connected
	c.mu.RUnlock()

	if !connected {
		return fmt.Errorf("not connected to controller")
	}

	resp, err := client.SyncDNA(ctx, dna)
	if err != nil {
		return fmt.Errorf("DNA sync failed: %w", err)
	}

	if resp.Code != commonpb.Status_OK {
		return fmt.Errorf("DNA sync rejected: %s", resp.Message)
	}

	c.logger.Debug("DNA synchronized successfully")
	return nil
}

// IsConnected returns true if the client is connected to the controller.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// IsRegistered returns true if the steward is registered with the controller.
func (c *Client) IsRegistered() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID != ""
}

// GetStewardID returns the assigned steward ID, or empty string if not registered.
func (c *Client) GetStewardID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stewardID
}

// GetLastHeartbeat returns the timestamp of the last successful heartbeat.
func (c *Client) GetLastHeartbeat() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastHeartbeat
}

// SetHealthCallback sets a callback function for health monitoring updates.
//
// The callback will be called with the connection status and heartbeat success/failure.
// This is useful for integrating with the steward's health monitoring system.
func (c *Client) SetHealthCallback(callback func(connected bool, success bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.healthCallback = callback
}

// startHeartbeat starts the automatic heartbeat mechanism.
//
// This method runs in a separate goroutine and sends periodic heartbeats
// to the controller. It stops when the heartbeatStop channel is closed.
func (c *Client) startHeartbeat() {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	c.logger.Info("Starting heartbeat mechanism", "interval", c.heartbeatInterval)

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			
			// Create basic health metrics
			metrics := map[string]string{
				"last_heartbeat": c.lastHeartbeat.Format(time.RFC3339),
				"uptime":         time.Since(c.lastHeartbeat).String(),
			}
			
			err := c.SendHeartbeat(ctx, "healthy", metrics)
			
			// Notify health monitoring system
			c.mu.RLock()
			callback := c.healthCallback
			connected := c.connected
			c.mu.RUnlock()
			
			if callback != nil {
				callback(connected, err == nil)
			}
			
			if err != nil {
				c.logger.Error("Heartbeat failed", "error", err)
			}
			
			cancel()
			
		case <-c.heartbeatStop:
			c.logger.Info("Heartbeat mechanism stopped")
			return
		}
	}
}

// loadTLSCredentials loads the TLS credentials for mTLS authentication.
//
// This method loads the client certificate, private key, and CA certificate
// from the certificate directory and creates gRPC transport credentials.
func (c *Client) loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(c.certPath, "client.crt"),
		filepath.Join(c.certPath, "client.key"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCert, err := ioutil.ReadFile(filepath.Join(c.certPath, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "cfgms-controller", // Should match certificate
	}

	return credentials.NewTLS(tlsConfig), nil
}

// loadCredentials loads the credentials from certificate files.
//
// This method reads the client certificate and creates the credentials
// structure required for authentication with the controller.
func loadCredentials(certPath string) (*commonpb.Credentials, error) {
	// Load client certificate
	clientCertData, err := ioutil.ReadFile(filepath.Join(certPath, "client.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate: %w", err)
	}

	// For now, use placeholder values for tenant_id and client_id
	// These would normally be extracted from the certificate or configuration
	return &commonpb.Credentials{
		TenantId:    "default",
		ClientId:    "steward-client",
		Certificate: clientCertData,
	}, nil
}