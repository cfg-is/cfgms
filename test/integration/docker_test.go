package integration

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/test/integration/testutil"
)

// DockerIntegrationTestSuite tests against standalone Docker controller
// This runs the same tests as DetailedIntegrationTestSuite but against
// the controller-standalone service in docker-compose.test.yml
type DockerIntegrationTestSuite struct {
	suite.Suite
	env *testutil.TestEnv
}

func (s *DockerIntegrationTestSuite) SetupSuite() {
	// Check if Docker controller is available
	dockerAddr := os.Getenv("CFGMS_TEST_DOCKER_CONTROLLER")
	if dockerAddr == "" {
		dockerAddr = "localhost:50054" // Default standalone controller address
	}

	// Test if Docker controller is reachable
	conn, err := net.DialTimeout("tcp", dockerAddr, 2*time.Second)
	if err != nil {
		s.T().Skipf("Docker controller not available at %s: %v", dockerAddr, err)
		return
	}
	conn.Close()

	s.T().Logf("Connecting to Docker controller at %s", dockerAddr)
	s.env = testutil.NewTestEnvWithDocker(s.T(), dockerAddr)
}

func (s *DockerIntegrationTestSuite) TearDownSuite() {
	if s.env != nil {
		s.env.Cleanup()
	}
}

func (s *DockerIntegrationTestSuite) SetupTest() {
	if s.env != nil {
		s.env.Reset()
	}
}

// TestHeartbeatProcessing validates heartbeat against Docker controller
func (s *DockerIntegrationTestSuite) TestHeartbeatProcessing() {
	s.env.Start()
	time.Sleep(2 * time.Second)
	s.env.Stop()

	infoLogs := s.env.Logger.GetLogs("info")
	hasConnected := false
	hasHeartbeatActivity := false

	for _, log := range infoLogs {
		if log.Message == "Connected to controller successfully" {
			hasConnected = true
		}
		if log.Message == "System DNA collected" ||
			log.Message == "Steward registered successfully" {
			hasHeartbeatActivity = true
		}
	}

	s.True(hasConnected, "Steward should have connected to Docker controller")
	s.True(hasHeartbeatActivity, "Should have heartbeat/health monitoring activity")
}

// TestDNASynchronization validates DNA sync against Docker controller
func (s *DockerIntegrationTestSuite) TestDNASynchronization() {
	s.env.Start()
	time.Sleep(1 * time.Second)
	s.env.Stop()

	infoLogs := s.env.Logger.GetLogs("info")
	hasDNACollection := false

	for _, log := range infoLogs {
		if log.Message == "System DNA collected" {
			hasDNACollection = true
			s.GreaterOrEqual(len(log.Data), 2, "Should have id and attributes data")
			break
		}
	}

	s.True(hasDNACollection, "Steward should have collected system DNA")
}

// TestMTLSAuthentication validates mTLS against Docker controller
func (s *DockerIntegrationTestSuite) TestMTLSAuthentication() {
	err := s.env.ValidateCertificateSetup()
	s.NoError(err, "Certificate setup should be valid for mTLS authentication")

	s.env.Start()
	time.Sleep(1 * time.Second)

	infoLogs := s.env.Logger.GetLogs("info")
	hasConnected := false

	for _, log := range infoLogs {
		if log.Message == "Connected to controller successfully" {
			hasConnected = true
			break
		}
	}

	s.env.Stop()
	s.True(hasConnected, "mTLS authentication should succeed with Docker controller")
}

func TestDockerIntegration(t *testing.T) {
	suite.Run(t, new(DockerIntegrationTestSuite))
}
