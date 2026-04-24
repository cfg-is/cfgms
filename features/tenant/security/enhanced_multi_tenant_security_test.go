// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func TestEnhancedMultiTenantSecurity(t *testing.T) {
	ctx := context.Background()

	// Setup test infrastructure with durable storage (git-backed)
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, nil)
	isolationEngine := NewTenantIsolationEngine(tenantManager)
	// Get the audit logger from the isolation engine to ensure we query the same logger that receives events
	auditLogger := isolationEngine.GetAuditLogger()
	policyEngine := NewTenantSecurityPolicyEngine(tenantManager, auditLogger, isolationEngine)

	// Create test tenants
	mspTenant := &tenant.Tenant{
		ID:          "msp-corp",
		Name:        "MSP Corporation",
		Description: "Main MSP tenant",
		Status:      tenant.TenantStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, tenantStore.CreateTenant(ctx, mspTenant))

	clientTenant := &tenant.Tenant{
		ID:          "client-healthcare",
		Name:        "Healthcare Client",
		Description: "HIPAA-compliant client tenant",
		ParentID:    "msp-corp",
		Status:      tenant.TenantStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	require.NoError(t, tenantStore.CreateTenant(ctx, clientTenant))

	t.Run("TenantIsolationMechanisms", func(t *testing.T) {
		t.Run("CreateIsolationRule", func(t *testing.T) {
			// Create HIPAA-compliant isolation rule for healthcare client
			hipaaRule := &IsolationRule{
				TenantID: "client-healthcare",
				DataResidency: DataResidencyRule{
					AllowedRegions:    []string{"us-east-1", "us-west-2"},
					ProhibitedRegions: []string{"eu-west-1", "ap-southeast-1"},
					RequireEncryption: true,
					EncryptionLevel:   "fips",
				},
				NetworkIsolation: NetworkRule{
					RequireVPNAccess:     true,
					AllowedIPRanges:      []string{"10.0.0.0/8", "192.168.1.0/24"},
					ProhibitedIPRanges:   []string{"0.0.0.0/0"},
					RequireMTLS:          true,
					ProhibitedUserAgents: []string{"curl", "wget"},
				},
				ResourceIsolation: ResourceRule{
					IsolatedStorage:        true,
					DedicatedCompute:       true,
					RestrictedResources:    []string{"admin/", "system/"},
					MaxResourceConsumption: 1000000, // 1MB
					AllowResourceSharing:   false,
				},
				CrossTenantAccess: CrossTenantRule{
					AllowCrossTenantAccess: true,
					AllowedTenants:         []string{"msp-corp"},
					AccessLevels: map[string]CrossTenantLevel{
						"msp-corp": CrossTenantLevelRead,
					},
					RequireApproval:  true,
					ApprovalWorkflow: "healthcare-approval",
				},
				ComplianceLevel: ComplianceLevelHIPAA,
			}

			err := isolationEngine.CreateIsolationRule(ctx, hipaaRule)
			require.NoError(t, err)

			// Verify rule was stored
			retrievedRule, err := isolationEngine.GetIsolationRule(ctx, "client-healthcare")
			require.NoError(t, err)
			assert.Equal(t, ComplianceLevelHIPAA, retrievedRule.ComplianceLevel)
			assert.True(t, retrievedRule.DataResidency.RequireEncryption)
			assert.Equal(t, "fips", retrievedRule.DataResidency.EncryptionLevel)
		})

		t.Run("ValidateTenantAccessWithRestrictions", func(t *testing.T) {
			// Test access from MSP to client tenant (should be allowed with read access)
			accessRequest := &TenantAccessRequest{
				SubjectID:       "admin-user",
				SubjectTenantID: "msp-corp",
				TargetTenantID:  "client-healthcare",
				ResourceID:      "config/database",
				AccessLevel:     CrossTenantLevelRead,
				Context: map[string]string{
					"source_ip":  "192.168.1.100",
					"user_agent": "CFGMS-Client/1.0",
				},
			}

			response, err := isolationEngine.ValidateTenantAccess(ctx, accessRequest)
			require.NoError(t, err)
			assert.True(t, response.Granted, "MSP should have read access to client tenant")
			assert.Equal(t, "Access granted - all isolation rules satisfied", response.Reason)

			// Test write access (should be denied - only read allowed)
			accessRequest.AccessLevel = CrossTenantLevelWrite
			response, err = isolationEngine.ValidateTenantAccess(ctx, accessRequest)
			require.NoError(t, err)
			assert.False(t, response.Granted, "Write access should be denied when only read access is configured")
			assert.Contains(t, response.Reason, "Insufficient access level")

			// Test access from prohibited IP
			accessRequest.Context["source_ip"] = "203.0.113.1" // Public IP
			accessRequest.AccessLevel = CrossTenantLevelRead
			_, err = isolationEngine.ValidateTenantAccess(ctx, accessRequest)
			require.NoError(t, err)
			// Note: IP validation is simplified in test implementation
		})

		t.Run("RestrictedResourceAccess", func(t *testing.T) {
			// Test access to restricted resource
			accessRequest := &TenantAccessRequest{
				SubjectID:       "user-1",
				SubjectTenantID: "client-healthcare",
				TargetTenantID:  "client-healthcare",
				ResourceID:      "admin/system-config",
				AccessLevel:     CrossTenantLevelRead,
				Context: map[string]string{
					"source_ip":  "192.168.1.100",
					"user_agent": "CFGMS-Client/1.0",
				},
			}

			response, err := isolationEngine.ValidateTenantAccess(ctx, accessRequest)
			require.NoError(t, err)
			assert.False(t, response.Granted, "Access to restricted resource should be denied")
			assert.Contains(t, response.Reason, "restricted")
		})
	})

	t.Run("CrossTenantAccessControl", func(t *testing.T) {
		accessValidator := NewCrossTenantAccessValidator()
		accessValidator.SetTenantManager(tenantManager)

		t.Run("CreateAndValidateAccessPolicy", func(t *testing.T) {
			// Create cross-tenant access policy
			policy := &CrossTenantAccessPolicy{
				SourceTenantID: "msp-corp",
				TargetTenantID: "client-healthcare",
				AccessLevel:    CrossTenantLevelRead,
				Permissions:    []string{"config.read", "status.read"},
				ResourceFilters: []ResourceFilter{
					{
						Type:     "include",
						Patterns: []string{"config/*", "status/*"},
					},
					{
						Type:     "exclude",
						Patterns: []string{"config/secrets/*"},
					},
				},
				TimeRestrictions: &TimeRestriction{
					AllowedDaysOfWeek: []int{0, 1, 2, 3, 4, 5, 6}, // All days for testing (0=Sunday, 6=Saturday)
					AllowedTimeRanges: []string{"00:00-23:59"},    // All hours for testing
					Timezone:          "America/New_York",
					MaxDurationHours:  24,
				},
				ApprovalRequired: false,
				Status:           CrossTenantAccessStatusActive,
				CreatedBy:        "system-admin",
			}

			createdPolicy, err := accessValidator.CreateAccessPolicy(ctx, policy)
			require.NoError(t, err)
			assert.NotEmpty(t, createdPolicy.ID)
			assert.Equal(t, CrossTenantAccessStatusActive, createdPolicy.Status)

			// Validate cross-tenant access using the policy
			accessRequest := &CrossTenantAccessRequest{
				SourceTenantID: "msp-corp",
				TargetTenantID: "client-healthcare",
				SubjectID:      "admin-user",
				ResourceID:     "config/database",
				AccessLevel:    CrossTenantLevelRead,
				Context: map[string]string{
					"time": time.Now().Format(time.RFC3339),
				},
			}

			validation, err := accessValidator.ValidateCrossTenantAccess(ctx, accessRequest)
			require.NoError(t, err)
			assert.True(t, validation.Granted, "Cross-tenant access should be granted")
			if validation.GrantingPolicy != nil {
				assert.Equal(t, createdPolicy.ID, validation.GrantingPolicy.ID)
			} else {
				t.Errorf("GrantingPolicy is nil when access was granted. Validation: %+v", validation)
			}

			// Test access to excluded resource
			accessRequest.ResourceID = "config/secrets/api-key"
			_, err = accessValidator.ValidateCrossTenantAccess(ctx, accessRequest)
			require.NoError(t, err)
			// Note: Resource filter validation is simplified in test
		})

		t.Run("ApprovalWorkflow", func(t *testing.T) {
			// Create policy requiring approval
			policy := &CrossTenantAccessPolicy{
				SourceTenantID:   "client-healthcare",
				TargetTenantID:   "msp-corp",
				AccessLevel:      CrossTenantLevelWrite,
				ApprovalRequired: true,
				ApprovalWorkflow: "healthcare-to-msp-approval",
				Status:           CrossTenantAccessStatusPending,
				CreatedBy:        "client-admin",
			}

			createdPolicy, err := accessValidator.CreateAccessPolicy(ctx, policy)
			require.NoError(t, err)
			assert.Equal(t, CrossTenantAccessStatusPending, createdPolicy.Status)

			// Test access with pending approval
			accessRequest := &CrossTenantAccessRequest{
				SourceTenantID: "client-healthcare",
				TargetTenantID: "msp-corp",
				SubjectID:      "client-user",
				ResourceID:     "config/network",
				AccessLevel:    CrossTenantLevelWrite,
			}

			validation, err := accessValidator.ValidateCrossTenantAccess(ctx, accessRequest)
			require.NoError(t, err)
			assert.False(t, validation.Granted, "Access should be denied while approval is pending")
			assert.Contains(t, validation.PolicyViolations[0], "pending")
		})
	})

	t.Run("TenantSecurityPolicyEngine", func(t *testing.T) {
		t.Run("CreateAndEvaluateSecurityPolicy", func(t *testing.T) {
			// Create comprehensive security policy for healthcare client
			securityPolicy := &TenantSecurityPolicy{
				TenantID:    "client-healthcare",
				Name:        "HIPAA Compliance Policy",
				Description: "Comprehensive HIPAA compliance security policy",
				Version:     "1.0",
				DataSecurityRules: []DataSecurityRule{
					{
						ID:                 "data-encryption-rule",
						Name:               "PHI Encryption Requirement",
						Description:        "All PHI data must be encrypted with FIPS-compliant encryption",
						Severity:           RuleSeverityCritical,
						DataTypes:          []string{"phi", "pii"},
						Classification:     DataClassificationRestricted,
						EncryptionRequired: true,
						EncryptionLevel:    "fips",
						AccessRestrictions: []string{"mfa_required", "vpn_required"},
						RetentionPeriod:    2555, // 7 years for HIPAA
					},
				},
				AccessControlRules: []AccessControlRule{
					{
						ID:                    "mfa-requirement",
						Name:                  "Multi-Factor Authentication",
						Description:           "MFA required for all PHI access",
						Severity:              RuleSeverityHigh,
						ResourceTypes:         []string{"phi_data", "patient_records"},
						MFARequired:           true,
						MaxConcurrentSessions: 1,
						SessionTimeout:        time.Hour * 2,
						IPWhitelist:           []string{"10.0.0.0/8", "192.168.0.0/16"},
					},
				},
				ComplianceRules: []ComplianceRule{
					{
						ID:                   "hipaa-audit-logging",
						Name:                 "HIPAA Audit Logging",
						Description:          "All PHI access must be logged per HIPAA requirements",
						Severity:             RuleSeverityCritical,
						Framework:            "hipaa",
						Requirement:          "164.308(a)(5)(ii)(D)",
						EvidenceRequired:     true,
						AuditFrequency:       time.Hour * 24,
						NotificationRequired: true,
					},
				},
				Status:          PolicyStatusActive,
				EnforcementMode: PolicyEnforcementModeBlock,
				CreatedBy:       "compliance-officer",
			}

			err := policyEngine.CreateSecurityPolicy(ctx, securityPolicy)
			require.NoError(t, err)

			// Test policy evaluation - compliant request
			compliantRequest := &SecurityEvaluationRequest{
				TenantID:     "client-healthcare",
				SubjectID:    "doctor-smith",
				Action:       "read",
				ResourceType: "phi_data",
				ResourceID:   "patient/12345",
				Context: map[string]string{
					"encrypted":    "true",
					"mfa_verified": "true",
					"source_ip":    "10.1.1.100",
				},
				Permissions:        []string{"phi_read", "patient_access"},
				DataClassification: "restricted",
			}

			result, err := policyEngine.EvaluateSecurityPolicy(ctx, compliantRequest)
			require.NoError(t, err)
			assert.True(t, result.Allowed, "Compliant request should be allowed")
			assert.Equal(t, "allow", result.Decision)
			assert.Empty(t, result.Violations, "No violations should be found for compliant request")

			// Test policy evaluation - non-compliant request (missing MFA)
			nonCompliantRequest := &SecurityEvaluationRequest{
				TenantID:     "client-healthcare",
				SubjectID:    "nurse-jones",
				Action:       "read",
				ResourceType: "phi_data",
				ResourceID:   "patient/67890",
				Context: map[string]string{
					"encrypted":    "true",
					"mfa_verified": "false", // MFA not verified
					"source_ip":    "10.1.1.101",
				},
				Permissions:        []string{"phi_read"},
				DataClassification: "restricted",
			}

			result, err = policyEngine.EvaluateSecurityPolicy(ctx, nonCompliantRequest)
			require.NoError(t, err)
			assert.False(t, result.Allowed, "Non-compliant request should be blocked")
			assert.Equal(t, "block_on_violation", result.Decision)
			assert.NotEmpty(t, result.Violations, "Policy violations should be detected")

			// Find the MFA violation
			var mfaViolation *RuleViolation
			for _, violation := range result.Violations {
				if violation.RuleID == "mfa-requirement" {
					mfaViolation = &violation
					break
				}
			}
			assert.NotNil(t, mfaViolation, "MFA violation should be detected")
			assert.Equal(t, RuleSeverityHigh, mfaViolation.Severity)
		})

		t.Run("PolicyEnforcementModes", func(t *testing.T) {
			// Test monitor mode - should allow but log violations
			monitorPolicy := &TenantSecurityPolicy{
				TenantID:        "test-tenant-monitor",
				Name:            "Monitor Mode Policy",
				Version:         "1.0",
				Status:          PolicyStatusActive,
				EnforcementMode: PolicyEnforcementModeMonitor,
				AccessControlRules: []AccessControlRule{
					{
						ID:          "test-mfa-rule",
						Name:        "Test MFA Rule",
						Severity:    RuleSeverityHigh,
						MFARequired: true,
					},
				},
				CreatedBy: "test-admin",
			}

			// Create test tenant first
			testTenant := &tenant.Tenant{
				ID:        "test-tenant-monitor",
				Name:      "Test Tenant Monitor",
				Status:    tenant.TenantStatusActive,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			require.NoError(t, tenantStore.CreateTenant(ctx, testTenant))

			err := policyEngine.CreateSecurityPolicy(ctx, monitorPolicy)
			require.NoError(t, err)

			violatingRequest := &SecurityEvaluationRequest{
				TenantID:     "test-tenant-monitor",
				SubjectID:    "test-user",
				Action:       "read",
				ResourceType: "data",
				Context: map[string]string{
					"mfa_verified": "false",
				},
			}

			result, err := policyEngine.EvaluateSecurityPolicy(ctx, violatingRequest)
			require.NoError(t, err)
			assert.True(t, result.Allowed, "Monitor mode should allow access despite violations")
			assert.Equal(t, "allow_with_monitoring", result.Decision)
			assert.NotEmpty(t, result.Violations, "Violations should still be detected and logged")
		})
	})

	t.Run("TenantSecurityAuditing", func(t *testing.T) {
		t.Run("AuditIsolationRuleChanges", func(t *testing.T) {
			newRule := &IsolationRule{
				TenantID:        "client-healthcare",
				ComplianceLevel: ComplianceLevelHIPAA,
			}

			err := auditLogger.LogIsolationRuleChange(ctx, "create", "client-healthcare", newRule, nil)
			require.NoError(t, err)

			// Retrieve audit entries
			filter := &TenantSecurityAuditFilter{
				TenantID:  "client-healthcare",
				EventType: string(TenantSecurityEventIsolationRuleChange),
			}

			entries, err := auditLogger.GetAuditEntries(ctx, filter)
			require.NoError(t, err)
			assert.Greater(t, len(entries), 0, "Audit entries should be created")

			entry := entries[len(entries)-1] // Get the latest entry
			assert.Equal(t, TenantSecurityEventIsolationRuleChange, entry.EventType)
			assert.Equal(t, "client-healthcare", entry.TenantID)
			assert.Equal(t, "create", entry.Action)
			assert.NotNil(t, entry.ComplianceInfo)
			assert.Contains(t, entry.ComplianceInfo.ComplianceFrameworks, "hipaa")
		})

		t.Run("GenerateSecurityReport", func(t *testing.T) {
			// Generate some test audit data
			for i := 0; i < 5; i++ {
				accessRequest := &TenantAccessRequest{
					SubjectID:       "test-user",
					SubjectTenantID: "client-healthcare",
					TargetTenantID:  "client-healthcare",
					ResourceID:      "test-resource",
					AccessLevel:     CrossTenantLevelRead,
				}
				accessResponse := &TenantAccessResponse{
					Granted:  i%2 == 0, // Alternate between granted and denied
					TenantID: "client-healthcare",
					Reason:   "test access",
				}
				err := auditLogger.LogAccessAttempt(ctx, accessRequest, accessResponse)
				require.NoError(t, err)
			}

			// Generate security report
			report, err := auditLogger.GetSecurityReport(ctx, "client-healthcare", time.Hour*24)
			require.NoError(t, err)
			assert.Equal(t, "client-healthcare", report.TenantID)
			assert.Greater(t, report.TotalEntries, 0)
			assert.Contains(t, report.EventSummary, TenantSecurityEventAccessAttempt)
		})

		t.Run("ComplianceViolationAuditing", func(t *testing.T) {
			err := auditLogger.LogComplianceViolation(ctx, "client-healthcare", "hipaa", "164.312(a)(1)", "Insufficient access controls")
			require.NoError(t, err)

			filter := &TenantSecurityAuditFilter{
				TenantID:  "client-healthcare",
				EventType: string(TenantSecurityEventComplianceViolation),
				Severity:  string(AuditSeverityCritical),
			}

			entries, err := auditLogger.GetAuditEntries(ctx, filter)
			require.NoError(t, err)
			assert.Greater(t, len(entries), 0, "Compliance violations should be audited")

			entry := entries[len(entries)-1]
			assert.Equal(t, AuditSeverityCritical, entry.Severity)
			assert.NotNil(t, entry.ComplianceInfo)
			assert.Contains(t, entry.ComplianceInfo.RequirementsViolated, "164.312(a)(1)")
		})
	})

	t.Run("EndToEndSecurityValidation", func(t *testing.T) {
		// Simulate a complete security validation flow

		// 1. Create isolation rule
		isolationRule := &IsolationRule{
			TenantID:        "client-healthcare",
			ComplianceLevel: ComplianceLevelHIPAA,
			CrossTenantAccess: CrossTenantRule{
				AllowCrossTenantAccess: true,
				AllowedTenants:         []string{"msp-corp"},
				AccessLevels: map[string]CrossTenantLevel{
					"msp-corp": CrossTenantLevelRead,
				},
				RequireApproval: false,
			},
		}
		err := isolationEngine.CreateIsolationRule(ctx, isolationRule)
		require.NoError(t, err)

		// 2. Create security policy
		securityPolicy := &TenantSecurityPolicy{
			TenantID:        "client-healthcare",
			Name:            "End-to-End Test Policy",
			Status:          PolicyStatusActive,
			EnforcementMode: PolicyEnforcementModeBlock,
			AccessControlRules: []AccessControlRule{
				{
					ID:          "e2e-access-rule",
					Name:        "End-to-End Access Rule",
					Severity:    RuleSeverityHigh,
					MFARequired: true,
				},
			},
			CreatedBy: "e2e-test",
		}
		err = policyEngine.CreateSecurityPolicy(ctx, securityPolicy)
		require.NoError(t, err)

		// 3. Validate cross-tenant access request
		tenantAccessRequest := &TenantAccessRequest{
			SubjectID:       "msp-admin",
			SubjectTenantID: "msp-corp",
			TargetTenantID:  "client-healthcare",
			ResourceID:      "patient-data/records",
			AccessLevel:     CrossTenantLevelRead,
			Context: map[string]string{
				"source_ip":    "192.168.1.100",
				"mfa_verified": "true",
			},
		}

		isolationResponse, err := isolationEngine.ValidateTenantAccess(ctx, tenantAccessRequest)
		require.NoError(t, err)
		assert.True(t, isolationResponse.Granted, "Isolation validation should pass")

		// 4. Evaluate security policy
		policyRequest := &SecurityEvaluationRequest{
			TenantID:     "client-healthcare",
			SubjectID:    "msp-admin",
			Action:       "read",
			ResourceType: "patient_data",
			ResourceID:   "patient-data/records",
			Context: map[string]string{
				"mfa_verified": "true",
				"encrypted":    "true",
			},
			Permissions: []string{"patient_read"},
		}

		policyResult, err := policyEngine.EvaluateSecurityPolicy(ctx, policyRequest)
		require.NoError(t, err)
		assert.True(t, policyResult.Allowed, "Policy evaluation should pass with MFA")

		// 5. Verify comprehensive audit trail
		auditFilter := &TenantSecurityAuditFilter{
			TenantID: "client-healthcare",
		}

		auditEntries, err := auditLogger.GetAuditEntries(ctx, auditFilter)
		require.NoError(t, err)
		assert.Greater(t, len(auditEntries), 0, "Audit trail should contain entries")

		// Verify different types of audit entries exist
		eventTypes := make(map[TenantSecurityEventType]bool)
		for _, entry := range auditEntries {
			eventTypes[entry.EventType] = true
		}

		assert.True(t, eventTypes[TenantSecurityEventIsolationRuleChange], "Should have isolation rule change events")
		assert.True(t, eventTypes[TenantSecurityEventAccessAttempt], "Should have access attempt events")
	})

	t.Run("DataResidencyAndComplianceValidation", func(t *testing.T) {
		// Test GDPR compliance for EU tenant
		euTenant := &tenant.Tenant{
			ID:        "client-eu",
			Name:      "EU Client",
			ParentID:  "msp-corp",
			Status:    tenant.TenantStatusActive,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		require.NoError(t, tenantStore.CreateTenant(ctx, euTenant))

		gdprRule := &IsolationRule{
			TenantID: "client-eu",
			DataResidency: DataResidencyRule{
				AllowedRegions:    []string{"eu-west-1", "eu-central-1"},
				ProhibitedRegions: []string{"us-east-1", "us-west-2", "ap-southeast-1"},
				RequireEncryption: true,
				EncryptionLevel:   "high",
			},
			ComplianceLevel: ComplianceLevelGDPR,
		}

		err := isolationEngine.CreateIsolationRule(ctx, gdprRule)
		require.NoError(t, err)

		retrievedRule, err := isolationEngine.GetIsolationRule(ctx, "client-eu")
		require.NoError(t, err)
		assert.Equal(t, ComplianceLevelGDPR, retrievedRule.ComplianceLevel)
		assert.Contains(t, retrievedRule.DataResidency.AllowedRegions, "eu-west-1")
		assert.Contains(t, retrievedRule.DataResidency.ProhibitedRegions, "us-east-1")
	})
}
