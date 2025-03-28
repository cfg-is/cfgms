package testutil

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"cfgms/features/controller"
	"cfgms/features/controller/config"
	"cfgms/features/steward"
	testpkg "cfgms/pkg/testing"
)

// TestEnv provides a test environment for integration testing
type TestEnv struct {
	T             *testing.T
	TempDir       string
	Logger        *testpkg.MockLogger
	Controller    *controller.Controller
	ControllerCfg *config.Config
	Steward       *steward.Steward
	StewardCfg    *steward.Config
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewTestEnv creates a new test environment
func NewTestEnv(t *testing.T) *TestEnv {
	tempDir, err := ioutil.TempDir("", "cfgms-test-")
	require.NoError(t, err)

	logger := testpkg.NewMockLogger(false)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	controllerCfg := &config.Config{
		ListenAddr: "127.0.0.1:0", // Use random port
		CertPath:   filepath.Join(tempDir, "certs"),
		DataDir:    filepath.Join(tempDir, "controller-data"),
		LogLevel:   "debug",
	}

	// Create cert directory
	err = os.MkdirAll(controllerCfg.CertPath, 0755)
	require.NoError(t, err)

	// Create controller data directory
	err = os.MkdirAll(controllerCfg.DataDir, 0755)
	require.NoError(t, err)

	ctrl, err := controller.New(controllerCfg, logger)
	require.NoError(t, err)

	stewardCfg := &steward.Config{
		ControllerAddr: controllerCfg.ListenAddr,
		CertPath:       filepath.Join(tempDir, "certs"),
		DataDir:        filepath.Join(tempDir, "steward-data"),
		LogLevel:       "debug",
		ID:             "test-steward",
	}

	// Create steward data directory
	err = os.MkdirAll(stewardCfg.DataDir, 0755)
	require.NoError(t, err)

	s, err := steward.New(stewardCfg, logger)
	require.NoError(t, err)

	return &TestEnv{
		T:             t,
		TempDir:       tempDir,
		Logger:        logger,
		Controller:    ctrl,
		ControllerCfg: controllerCfg,
		Steward:       s,
		StewardCfg:    stewardCfg,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the controller and steward in the test environment
func (e *TestEnv) Start() {
	// Start the controller
	err := e.Controller.Start(e.ctx)
	require.NoError(e.T, err)

	// Start the steward
	err = e.Steward.Start(e.ctx)
	require.NoError(e.T, err)

	// Wait for components to initialize
	time.Sleep(100 * time.Millisecond)
}

// Stop stops the controller and steward in the test environment
func (e *TestEnv) Stop() {
	// Stop the steward
	err := e.Steward.Stop(e.ctx)
	require.NoError(e.T, err)

	// Stop the controller
	err = e.Controller.Stop(e.ctx)
	require.NoError(e.T, err)
}

// Cleanup cleans up the test environment
func (e *TestEnv) Cleanup() {
	e.cancel()

	// Remove temporary directory
	if e.TempDir != "" {
		os.RemoveAll(e.TempDir)
	}
}

// Reset resets the test environment for a new test
func (e *TestEnv) Reset() {
	e.Logger.Reset()
}

// GetContext returns the context for the test environment
func (e *TestEnv) GetContext() context.Context {
	return e.ctx
}
