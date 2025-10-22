//go:build commercial
// +build commercial

package ha

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	isDockerRunning bool
	setupOnce       bool
)

// TestMain handles setup and teardown for all HA tests
// NOTE: Disabled in favor of per-test Docker management using DockerComposeHelper
// func TestMain(m *testing.M) {
// 	var exitCode int
// 	defer func() {
// 		// Cleanup
// 		if isDockerRunning {
// 			cleanupDocker()
// 		}
// 		os.Exit(exitCode)
// 	}()
//
// 	// Setup Docker infrastructure
// 	if err := setupDocker(); err != nil {
// 		fmt.Printf("Failed to setup Docker infrastructure: %v\n", err)
// 		exitCode = 1
// 		return
// 	}
//
// 	// Run tests
// 	exitCode = m.Run()
// }

// setupDocker starts the Docker Compose infrastructure for HA tests
func setupDocker() error {
	if setupOnce {
		return nil
	}
	setupOnce = true

	fmt.Println("Setting up Docker infrastructure for HA tests...")

	// Get the directory containing docker-compose.yml
	testDir, err := getTestDir()
	if err != nil {
		return fmt.Errorf("failed to get test directory: %w", err)
	}

	// Stop any existing containers to ensure clean state
	cleanupCmd := exec.Command("docker", "compose", "down", "-v", "--remove-orphans")
	cleanupCmd.Dir = testDir
	if err := cleanupCmd.Run(); err != nil {
		fmt.Printf("Warning: failed to cleanup existing containers: %v\n", err)
	}

	// Build images first
	fmt.Println("Building controller Docker image...")
	buildCmd := exec.Command("docker", "compose", "build", "--no-cache")
	buildCmd.Dir = testDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build Docker images: %w", err)
	}

	// Start services
	fmt.Println("Starting Docker Compose services...")
	startCmd := exec.Command("docker", "compose", "up", "-d")
	startCmd.Dir = testDir
	startCmd.Stdout = os.Stdout
	startCmd.Stderr = os.Stderr
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start Docker services: %w", err)
	}

	isDockerRunning = true

	// Wait for services to be healthy
	fmt.Println("Waiting for services to be healthy...")
	if err := waitForServices(testDir); err != nil {
		return fmt.Errorf("services failed to become healthy: %w", err)
	}

	fmt.Println("✓ Docker infrastructure is ready")
	return nil
}

// getTestDir returns the directory containing the docker-compose.yml file
func getTestDir() (string, error) {
	// This should be the test/integration/ha directory
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Check if we're in the right directory or need to navigate
	composePath := filepath.Join(wd, "docker-compose.yml")
	if _, err := os.Stat(composePath); err == nil {
		return wd, nil
	}

	// Try to find the test directory from project root
	// This handles cases where tests are run from different working directories
	projectRoot, err := findProjectRoot()
	if err != nil {
		return "", err
	}

	testDir := filepath.Join(projectRoot, "test", "integration", "ha")
	composePath = filepath.Join(testDir, "docker-compose.yml")
	if _, err := os.Stat(composePath); err != nil {
		return "", fmt.Errorf("docker-compose.yml not found in %s", testDir)
	}

	return testDir, nil
}

// findProjectRoot finds the project root by looking for go.mod
func findProjectRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := wd
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("project root not found (no go.mod)")
}

// waitForServices waits for all Docker services to be healthy
func waitForServices(testDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	services := []string{"timescaledb", "controller-east", "controller-central", "controller-west"}

	for _, service := range services {
		fmt.Printf("Waiting for %s to be healthy...\n", service)

		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout waiting for %s to be healthy", service)
			default:
			}

			// Check service health
			healthCmd := exec.Command("docker", "compose", "ps", "--format", "table")
			healthCmd.Dir = testDir
			output, err := healthCmd.Output()
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			// Check if service is healthy in the output
			if isServiceHealthy(string(output), service) {
				fmt.Printf("✓ %s is healthy\n", service)
				break
			}

			// Additional check for controllers - try to connect to their ports
			if service != "timescaledb" {
				var port string
				switch service {
				case "controller-east":
					port = "8080"
				case "controller-central":
					port = "8081"
				case "controller-west":
					port = "8082"
				}

				// Simple TCP connection test
				testCmd := exec.Command("nc", "-z", "localhost", port)
				if testCmd.Run() == nil {
					fmt.Printf("✓ %s is responding on port %s\n", service, port)
					break
				}
			}

			time.Sleep(2 * time.Second)
		}
	}

	// Give services additional time to fully initialize
	fmt.Println("Giving services additional time to initialize...")
	time.Sleep(10 * time.Second)

	return nil
}

// isServiceHealthy checks if a service is healthy in docker compose ps output
func isServiceHealthy(output, service string) bool {
	if len(output) == 0 {
		return false
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Look for lines containing the service name and (healthy) status
		if strings.Contains(line, service) && strings.Contains(line, "(healthy)") {
			return true
		}
	}

	return false
}

// EnsureDockerRunning ensures Docker infrastructure is running (for use in individual tests)
func EnsureDockerRunning(t *testing.T) {
	if !isDockerRunning {
		if err := setupDocker(); err != nil {
			t.Fatalf("Failed to setup Docker infrastructure: %v", err)
		}
	}
}
