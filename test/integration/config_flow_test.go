package integration

// TODO(Story #198): This entire file uses obsolete gRPC client - disabled for now
// Test functionality is now covered by mqtt_quic_flow_test.go

/*
import (
	"context"
	"time"

	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/steward/config"
	testpkg "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/test/integration/testutil"
)
*/

/*
// ConfigFlowTestSuite tests the configuration data flow between controller and steward
type ConfigFlowTestSuite struct {
	suite.Suite
	env *testutil.TestEnv
}

func (s *ConfigFlowTestSuite) SetupSuite() {
	s.env = testutil.NewTestEnv(s.T())
}

func (s *ConfigFlowTestSuite) TearDownSuite() {
	s.env.Cleanup()
}

func (s *ConfigFlowTestSuite) SetupTest() {
	s.env.Reset()
}

func (s *ConfigFlowTestSuite) TearDownTest() {
	// Stop components if they were started
}

func (s *ConfigFlowTestSuite) TestConfigurationDataFlow() {
	// Start the controller and steward
	s.env.Start()
	defer s.env.Stop()

	// Wait for components to initialize
	time.Sleep(200 * time.Millisecond)

	// Create a test steward client
	client, err := s.env.CreateStewardClient()
	s.Require().NoError(err)

	// Connect to controller
	ctx := context.Background()
	err = client.Connect(ctx)
	s.Require().NoError(err)
	defer func() {
		_ = client.Disconnect()
	}()

	// Create test DNA
	dna := &common.DNA{
		Id: "test-steward",
		Attributes: map[string]string{
			"hostname": "test-host",
			"os":       "linux",
			"arch":     "amd64",
		},
		LastUpdated: timestamppb.Now(),
	}

	// Register with controller
	stewardID, err := client.Register(ctx, "test-version", dna)
	s.Require().NoError(err)
	s.Require().NotEmpty(stewardID)

	// Create test configuration
	testConfig := &config.StewardConfig{
		Steward: config.StewardSettings{
			ID:   stewardID,
			Mode: config.ModeController,
			Logging: config.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: config.ErrorHandlingConfig{
				ModuleLoadFailure:  config.ActionContinue,
				ResourceFailure:    config.ActionWarn,
				ConfigurationError: config.ActionFail,
			},
		},
		Resources: []config.ResourceConfig{
			{
				Name:   "test-directory",
				Module: "directory",
				Config: map[string]interface{}{
					"path":        "/tmp/test",
					"permissions": "755",
				},
			},
			{
				Name:   "test-file",
				Module: "file",
				Config: map[string]interface{}{
					"path":    "/tmp/test/test.txt",
					"content": "Hello World",
				},
			},
		},
	}

	// Set configuration in controller
	configService := s.env.Controller.GetConfigurationService()
	s.Require().NotNil(configService)

	err = configService.SetConfiguration(stewardID, testConfig)
	s.Require().NoError(err)

	// Request configuration from controller
	retrievedConfig, version, err := client.GetConfiguration(ctx, nil)
	s.Require().NoError(err)
	s.Require().NotEmpty(version)
	s.Require().NotNil(retrievedConfig)

	// Verify configuration content
	s.Equal(stewardID, retrievedConfig.Steward.ID)
	s.Equal(config.ModeController, retrievedConfig.Steward.Mode)
	s.Len(retrievedConfig.Resources, 2)

	// Verify resource configurations
	s.Equal("test-directory", retrievedConfig.Resources[0].Name)
	s.Equal("directory", retrievedConfig.Resources[0].Module)
	s.Equal("test-file", retrievedConfig.Resources[1].Name)
	s.Equal("file", retrievedConfig.Resources[1].Module)

	// Test module filtering
	filteredConfig, _, err := client.GetConfiguration(ctx, []string{"directory"})
	s.Require().NoError(err)
	s.Len(filteredConfig.Resources, 1)
	s.Equal("directory", filteredConfig.Resources[0].Module)

	// Test configuration validation
	errors, err := client.ValidateConfiguration(ctx, testConfig, version)
	s.Require().NoError(err)
	s.Empty(errors)

	// Test configuration status reporting
	moduleStatuses := map[string]*controller.ModuleStatus{
		"directory": {
			Name:      "directory",
			Status:    &common.Status{Code: common.Status_OK, Message: "Directory created successfully"},
			Message:   "Directory created successfully",
			Timestamp: timestamppb.Now(),
		},
		"file": {
			Name:      "file",
			Status:    &common.Status{Code: common.Status_OK, Message: "File created successfully"},
			Message:   "File created successfully",
			Timestamp: timestamppb.Now(),
		},
	}

	err = client.ReportConfigurationStatus(ctx, version, common.Status_OK, "Configuration applied successfully", moduleStatuses)
	s.Require().NoError(err)

	// Verify logs indicate successful configuration flow
	infoLogs := s.env.Logger.GetLogs("info")
	s.True(s.containsLogMessage(infoLogs, "Configuration stored for tenant steward"))
	s.True(s.containsLogMessage(infoLogs, "Configuration status report processed"))
	
	// Configuration retrieval message is at DEBUG level, so check debug logs
	debugLogs := s.env.Logger.GetLogs("debug")
	s.True(s.containsLogMessage(debugLogs, "Configuration retrieved successfully"))
}

func (s *ConfigFlowTestSuite) TestConfigurationNotFound() {
	// Start the controller and steward
	s.env.Start()
	defer s.env.Stop()

	// Wait for components to initialize
	time.Sleep(200 * time.Millisecond)

	// Create a test steward client
	client, err := s.env.CreateStewardClient()
	s.Require().NoError(err)

	// Connect to controller
	ctx := context.Background()
	err = client.Connect(ctx)
	s.Require().NoError(err)
	defer func() {
		_ = client.Disconnect()
	}()

	// Create test DNA
	dna := &common.DNA{
		Id: "test-steward",
		Attributes: map[string]string{
			"hostname": "test-host",
		},
		LastUpdated: timestamppb.Now(),
	}

	// Register with controller
	_, err = client.Register(ctx, "test-version", dna)
	s.Require().NoError(err)

	// Request configuration without setting one first
	_, _, err = client.GetConfiguration(ctx, nil)
	s.Require().Error(err)
	s.Contains(err.Error(), "No configuration found for steward")
}

func (s *ConfigFlowTestSuite) TestConfigurationValidationFailure() {
	// Start the controller and steward
	s.env.Start()
	defer s.env.Stop()

	// Wait for components to initialize
	time.Sleep(200 * time.Millisecond)

	// Create a test steward client
	client, err := s.env.CreateStewardClient()
	s.Require().NoError(err)

	// Connect to controller
	ctx := context.Background()
	err = client.Connect(ctx)
	s.Require().NoError(err)
	defer func() {
		_ = client.Disconnect()
	}()

	// Create invalid configuration (missing required fields)
	invalidConfig := &config.StewardConfig{
		Steward: config.StewardSettings{
			// Missing ID field
			Mode: config.ModeController,
		},
		Resources: []config.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				// Missing Config field
			},
		},
	}

	// Test validation failure
	_, err = client.ValidateConfiguration(ctx, invalidConfig, "test-version")
	s.Require().Error(err)
	s.Contains(err.Error(), "validation failed")
}

// Helper method to check if logs contain a specific message
func (s *ConfigFlowTestSuite) containsLogMessage(logs []testpkg.LogEntry, message string) bool {
	for _, log := range logs {
		if log.Message == message {
			return true
		}
	}
	return false
}
*/