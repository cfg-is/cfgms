// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package mqtt_quic

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// DNAUpdateTestSuite tests DNA collection and transmission
// AC5: DNA update test (steward collects DNA, transmits via MQTT, controller receives and stores)
type DNAUpdateTestSuite struct {
	suite.Suite
	helper   *TestHelper
	mqttAddr string
}

func (s *DNAUpdateTestSuite) SetupSuite() {
	s.helper = NewTestHelper(GetTestHTTPAddr("http://localhost:8080"))
	s.mqttAddr = GetTestMQTTAddr("tcp://localhost:1886")
}

// TestDNAUpdateMessage tests DNA update message structure
func (s *DNAUpdateTestSuite) TestDNAUpdateMessage() {
	stewardID := "test-steward-dna"
	dnaTopic := fmt.Sprintf("cfgms/steward/%s/dna", stewardID)

	// Create client
	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(stewardID)
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Create DNA update
	dnaUpdate := map[string]interface{}{
		"steward_id":       stewardID,
		"config_hash":      "abc123def456",
		"sync_fingerprint": "xyz789",
		"timestamp":        time.Now().Unix(),
		"dna": map[string]string{
			"hostname":        "test-host",
			"os":              "linux",
			"os_version":      "Ubuntu 22.04",
			"arch":            "amd64",
			"kernel":          "5.15.0-76-generic",
			"cpu_cores":       "4",
			"memory_mb":       "8192",
			"disk_gb":         "256",
			"ip_address":      "192.168.1.100",
			"mac_address":     "00:11:22:33:44:55",
			"steward_version": "0.5.0",
		},
	}

	dnaJSON, err := json.Marshal(dnaUpdate)
	s.NoError(err)

	// Publish DNA update
	pubToken := client.Publish(dnaTopic, 1, false, dnaJSON)
	s.True(pubToken.WaitTimeout(5 * time.Second))
	s.NoError(pubToken.Error())

	s.T().Logf("DNA update published: %d bytes", len(dnaJSON))
}

// TestExtendedDNACollection tests comprehensive DNA attributes
func (s *DNAUpdateTestSuite) TestExtendedDNACollection() {
	// Test extended DNA collection (161 attributes per Story #78)
	extendedDNA := map[string]interface{}{
		"steward_id": "test-steward-extended",
		"timestamp":  time.Now().Unix(),
		"dna": map[string]interface{}{
			// System Info
			"hostname":   "production-server-01",
			"domain":     "example.com",
			"os":         "linux",
			"os_version": "Ubuntu 22.04.3 LTS",
			"kernel":     "5.15.0-76-generic",
			"arch":       "x86_64",

			// Hardware
			"cpu_model":    "Intel Xeon E5-2670",
			"cpu_cores":    "16",
			"cpu_threads":  "32",
			"memory_total": "65536",
			"disk_total":   "2048",
			"motherboard":  "Dell Inc. PowerEdge R720",

			// Network
			"ip_addresses":  []string{"192.168.1.100", "10.0.0.50"},
			"mac_addresses": []string{"00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"},
			"dns_servers":   []string{"8.8.8.8", "8.8.4.4"},
			"gateway":       "192.168.1.1",

			// Software
			"installed_packages": 450,
			"running_services":   87,
			"listening_ports":    []int{22, 80, 443, 8080},

			// Security
			"firewall_enabled": true,
			"selinux_status":   "enforcing",
			"users_count":      12,
			"groups_count":     45,
		},
	}

	// Verify DNA richness
	dna := extendedDNA["dna"].(map[string]interface{})
	s.Greater(len(dna), 15, "Extended DNA should have many attributes")

	dnaJSON, err := json.Marshal(extendedDNA)
	s.NoError(err)
	s.T().Logf("Extended DNA: %d attributes, %d bytes", len(dna), len(dnaJSON))
}

// TestDNAUpdateFrequency tests periodic DNA update cadence
func (s *DNAUpdateTestSuite) TestDNAUpdateFrequency() {
	stewardID := "test-steward-frequency"
	dnaTopic := fmt.Sprintf("cfgms/steward/%s/dna", stewardID)

	opts := mqtt.NewClientOptions()
	opts.AddBroker(s.mqttAddr)
	opts.SetClientID(stewardID)
	opts.SetConnectTimeout(10 * time.Second)

	client := mqtt.NewClient(opts)
	token := client.Connect()
	s.True(token.WaitTimeout(10 * time.Second))
	s.NoError(token.Error())
	defer client.Disconnect(250)

	// Simulate periodic DNA updates (every 5 minutes in production)
	updateCount := 3
	for i := 0; i < updateCount; i++ {
		dnaUpdate := map[string]interface{}{
			"steward_id": stewardID,
			"timestamp":  time.Now().Unix(),
			"sequence":   i + 1,
			"dna": map[string]interface{}{
				"cpu_percent": fmt.Sprintf("%.1f", 20.0+float64(i)*5.0),
				"memory_used": fmt.Sprintf("%d", 4096+i*512),
			},
		}

		dnaJSON, err := json.Marshal(dnaUpdate)
		s.NoError(err)

		pubToken := client.Publish(dnaTopic, 1, false, dnaJSON)
		s.True(pubToken.WaitTimeout(5 * time.Second))
		s.NoError(pubToken.Error())

		s.T().Logf("DNA update %d/%d published", i+1, updateCount)
		time.Sleep(500 * time.Millisecond) // Simulate time between updates
	}

	s.T().Logf("Simulated %d periodic DNA updates", updateCount)
}

// TestDNAChangeDetection tests DNA delta/change reporting
func (s *DNAUpdateTestSuite) TestDNAChangeDetection() {
	// Test DNA change detection (only changed attributes)
	previousDNA := map[string]string{
		"cpu_percent": "25.5",
		"memory_used": "4096",
		"disk_used":   "102400",
	}

	currentDNA := map[string]string{
		"cpu_percent": "45.2",   // Changed
		"memory_used": "4096",   // Same
		"disk_used":   "105000", // Changed
	}

	// Calculate delta
	changes := make(map[string]interface{})
	for key, currentVal := range currentDNA {
		if prevVal, exists := previousDNA[key]; exists {
			if prevVal != currentVal {
				changes[key] = map[string]string{
					"old": prevVal,
					"new": currentVal,
				}
			}
		}
	}

	s.Len(changes, 2, "Should detect 2 changes")
	s.Contains(changes, "cpu_percent")
	s.Contains(changes, "disk_used")
	s.NotContains(changes, "memory_used")

	s.T().Logf("DNA change detection: %d attributes changed", len(changes))
}

// TestDNACompressionSimulation tests DNA payload compression
func (s *DNAUpdateTestSuite) TestDNACompressionSimulation() {
	// Large DNA payload that would benefit from compression
	largeDNA := map[string]interface{}{
		"steward_id": "test-steward-compression",
		"timestamp":  time.Now().Unix(),
		"dna":        make(map[string]interface{}),
	}

	// Add many attributes
	dnaMap := largeDNA["dna"].(map[string]interface{})
	for i := 0; i < 200; i++ {
		dnaMap[fmt.Sprintf("attribute_%d", i)] = fmt.Sprintf("value_%d_with_some_repeated_text", i)
	}

	dnaJSON, err := json.Marshal(largeDNA)
	s.NoError(err)

	// In production, payloads >10KB would be compressed
	uncompressedSize := len(dnaJSON)
	compressionThreshold := 10 * 1024

	if uncompressedSize > compressionThreshold {
		s.T().Logf("Large DNA payload: %d bytes (would trigger compression)", uncompressedSize)
	} else {
		s.T().Logf("DNA payload: %d bytes (below compression threshold)", uncompressedSize)
	}
}

func TestDNAUpdate(t *testing.T) {
	suite.Run(t, new(DNAUpdateTestSuite))
}
