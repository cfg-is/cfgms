package rollback

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// DefaultRollbackValidator implements the RollbackValidator interface
type DefaultRollbackValidator struct {
	// Dependencies for validation
	moduleRegistry ModuleRegistry
	configParser   ConfigurationParser
}

// ModuleRegistry provides module information for validation
type ModuleRegistry interface {
	GetModuleVersion(ctx context.Context, moduleName string) (string, error)
	GetModuleDependencies(ctx context.Context, moduleName string) ([]string, error)
	IsModuleCompatible(ctx context.Context, moduleName, version string) (bool, error)
}

// ConfigurationParser parses and validates configurations
type ConfigurationParser interface {
	ParseConfiguration(content []byte, format string) (map[string]interface{}, error)
	ValidateSchema(config map[string]interface{}, schema string) error
	GetRequiredFields(schema string) []string
}

// NewRollbackValidator creates a new rollback validator
func NewRollbackValidator(moduleRegistry ModuleRegistry, configParser ConfigurationParser) RollbackValidator {
	return &DefaultRollbackValidator{
		moduleRegistry: moduleRegistry,
		configParser:   configParser,
	}
}

// ValidateRollback checks if a rollback is safe to perform
func (v *DefaultRollbackValidator) ValidateRollback(ctx context.Context, request RollbackRequest, preview *RollbackPreview) (*ValidationResults, error) {
	results := &ValidationResults{
		Passed:   true,
		Warnings: []ValidationIssue{},
		Errors:   []ValidationIssue{},
		Metadata: make(map[string]interface{}),
	}
	
	// Validate target exists and is accessible
	if err := v.validateTarget(ctx, request.TargetType, request.TargetID); err != nil {
		results.Errors = append(results.Errors, ValidationIssue{
			Type:     "target_validation",
			Severity: "error",
			Message:  fmt.Sprintf("Invalid target: %v", err),
		})
		results.Passed = false
	}
	
	// Validate rollback type and options
	if err := v.validateRollbackType(request); err != nil {
		results.Errors = append(results.Errors, ValidationIssue{
			Type:     "rollback_type_validation",
			Severity: "error",
			Message:  err.Error(),
		})
		results.Passed = false
	}
	
	// If we have a preview, validate the changes
	if preview != nil {
		// Check for breaking changes
		breakingChanges := v.checkBreakingChanges(ctx, preview.Changes)
		if len(breakingChanges) > 0 {
			for _, bc := range breakingChanges {
				issue := ValidationIssue{
					Type:     "breaking_change",
					Severity: "warning",
					Message:  bc,
					Details: map[string]interface{}{
						"can_force": true,
					},
					Resolvable: true,
					Resolution: "Use --force flag to proceed with breaking changes",
				}
				
				// Breaking changes are errors unless force is set
				if !request.Options.Force {
					issue.Severity = "error"
					results.Errors = append(results.Errors, issue)
					results.Passed = false
				} else {
					results.Warnings = append(results.Warnings, issue)
				}
			}
		}
		
		// Validate module compatibility
		if err := v.ValidateModuleCompatibility(ctx, preview.AffectedModules, request.RollbackTo); err != nil {
			results.Errors = append(results.Errors, ValidationIssue{
				Type:     "module_compatibility",
				Severity: "error",
				Message:  fmt.Sprintf("Module compatibility check failed: %v", err),
			})
			results.Passed = false
		}
		
		// Check dependencies
		if err := v.CheckDependencies(ctx, request.TargetType, request.TargetID, preview.Changes); err != nil {
			results.Errors = append(results.Errors, ValidationIssue{
				Type:     "dependency_check",
				Severity: "error",
				Message:  fmt.Sprintf("Dependency check failed: %v", err),
			})
			results.Passed = false
		}
	}
	
	// Validate permissions
	if err := v.validatePermissions(ctx, request); err != nil {
		results.Errors = append(results.Errors, ValidationIssue{
			Type:     "permission_validation",
			Severity: "error",
			Message:  fmt.Sprintf("Permission denied: %v", err),
		})
		results.Passed = false
	}
	
	// Check system health
	healthIssues := v.checkSystemHealth(ctx, request.TargetType, request.TargetID)
	if len(healthIssues) > 0 {
		results.Warnings = append(results.Warnings, healthIssues...)
	}
	
	// Add validation metadata
	results.Metadata["validation_time"] = time.Now()
	results.Metadata["validator_version"] = "1.0.0"
	
	return results, nil
}

// AssessRisk evaluates the risk level of a rollback
func (v *DefaultRollbackValidator) AssessRisk(ctx context.Context, request RollbackRequest, changes []ConfigurationChange) (*RiskAssessment, error) {
	assessment := &RiskAssessment{
		OverallRisk:      RiskLevelLow,
		ServiceImpact:    "minimal",
		DataLossRisk:     false,
		DowntimeEstimate: 0,
		AffectedUsers:    0,
		RiskFactors:      []RiskFactor{},
	}
	
	// Assess risk based on number of changes
	if len(changes) > 10 {
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "large_change_set",
			Description: fmt.Sprintf("%d configuration changes", len(changes)),
			Impact:      RiskLevelMedium,
			Mitigation:  "Consider progressive rollback",
		})
		assessment.OverallRisk = RiskLevelMedium
	}
	
	// Check for critical module changes
	criticalModules := []string{"authentication", "security", "network", "database"}
	for _, change := range changes {
		for _, critical := range criticalModules {
			if strings.Contains(change.Path, critical) {
				assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
					Factor:      "critical_module_change",
					Description: fmt.Sprintf("Changes to %s module", critical),
					Impact:      RiskLevelHigh,
					Mitigation:  "Ensure backup authentication method available",
				})
				assessment.OverallRisk = RiskLevelHigh
				assessment.ServiceImpact = "significant"
				break
			}
		}
	}
	
	// Assess data loss risk
	for _, change := range changes {
		if strings.Contains(change.Path, "schema") || strings.Contains(change.Path, "migration") {
			assessment.DataLossRisk = true
			assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
				Factor:      "schema_change",
				Description: "Database schema changes detected",
				Impact:      RiskLevelCritical,
				Mitigation:  "Ensure database backup before proceeding",
			})
			assessment.OverallRisk = RiskLevelCritical
		}
	}
	
	// Estimate downtime
	assessment.DowntimeEstimate = v.estimateDowntime(changes)
	if assessment.DowntimeEstimate > 5*time.Minute {
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "extended_downtime",
			Description: fmt.Sprintf("Expected downtime: %v", assessment.DowntimeEstimate),
			Impact:      RiskLevelMedium,
			Mitigation:  "Schedule during maintenance window",
		})
	}
	
	// Estimate affected users based on target type
	assessment.AffectedUsers = v.estimateAffectedUsers(request.TargetType, request.TargetID)
	if assessment.AffectedUsers > 1000 {
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "large_user_impact",
			Description: fmt.Sprintf("%d users affected", assessment.AffectedUsers),
			Impact:      RiskLevelHigh,
			Mitigation:  "Use progressive rollback strategy",
		})
		if assessment.OverallRisk < RiskLevelHigh {
			assessment.OverallRisk = RiskLevelHigh
		}
	}
	
	// Emergency rollbacks are always high risk
	if request.Emergency {
		assessment.RiskFactors = append(assessment.RiskFactors, RiskFactor{
			Factor:      "emergency_rollback",
			Description: "Emergency rollback bypasses normal safety checks",
			Impact:      RiskLevelHigh,
			Mitigation:  "Ensure post-rollback validation",
		})
		if assessment.OverallRisk < RiskLevelHigh {
			assessment.OverallRisk = RiskLevelHigh
		}
	}
	
	return assessment, nil
}

// CheckDependencies validates that all dependencies are satisfied
func (v *DefaultRollbackValidator) CheckDependencies(ctx context.Context, targetType TargetType, targetID string, changes []ConfigurationChange) error {
	// Extract modules from changes
	modules := make(map[string]bool)
	for _, change := range changes {
		if change.Module != "" {
			modules[change.Module] = true
		}
	}
	
	// Check each module's dependencies
	for module := range modules {
		deps, err := v.moduleRegistry.GetModuleDependencies(ctx, module)
		if err != nil {
			return fmt.Errorf("failed to get dependencies for module %s: %w", module, err)
		}
		
		// Verify each dependency
		for _, dep := range deps {
			// Check if dependency is also being rolled back
			if modules[dep] {
				continue // OK - both module and dependency are being rolled back
			}
			
			// Check if dependency will remain compatible
			currentVersion, err := v.moduleRegistry.GetModuleVersion(ctx, dep)
			if err != nil {
				return fmt.Errorf("failed to get version for dependency %s: %w", dep, err)
			}
			
			// This is simplified - in reality would check actual compatibility
			compatible, err := v.moduleRegistry.IsModuleCompatible(ctx, dep, currentVersion)
			if err != nil {
				return fmt.Errorf("failed to check compatibility for %s: %w", dep, err)
			}
			
			if !compatible {
				return fmt.Errorf("module %s depends on %s which would be incompatible after rollback", module, dep)
			}
		}
	}
	
	return nil
}

// ValidateModuleCompatibility checks if modules are compatible with the target version
func (v *DefaultRollbackValidator) ValidateModuleCompatibility(ctx context.Context, modules []string, targetVersion string) error {
	for _, module := range modules {
		compatible, err := v.moduleRegistry.IsModuleCompatible(ctx, module, targetVersion)
		if err != nil {
			return fmt.Errorf("failed to check compatibility for module %s: %w", module, err)
		}
		
		if !compatible {
			return fmt.Errorf("module %s is not compatible with target version %s", module, targetVersion)
		}
	}
	
	return nil
}

// Helper methods

func (v *DefaultRollbackValidator) validateTarget(ctx context.Context, targetType TargetType, targetID string) error {
	// In a real implementation, this would verify the target exists
	// and the user has access to it
	if targetID == "" {
		return fmt.Errorf("target ID cannot be empty")
	}
	
	// Validate target type
	switch targetType {
	case TargetTypeDevice, TargetTypeGroup, TargetTypeClient, TargetTypeMSP:
		// Valid
	default:
		return fmt.Errorf("invalid target type: %s", targetType)
	}
	
	return nil
}

func (v *DefaultRollbackValidator) validateRollbackType(request RollbackRequest) error {
	switch request.RollbackType {
	case RollbackTypeFull:
		// No additional validation needed
		
	case RollbackTypePartial:
		if len(request.Configurations) == 0 {
			return fmt.Errorf("partial rollback requires at least one configuration")
		}
		
	case RollbackTypeModule:
		if len(request.Modules) == 0 {
			return fmt.Errorf("module rollback requires at least one module")
		}
		
	case RollbackTypeEmergency:
		if request.Reason == "" {
			return fmt.Errorf("emergency rollback requires a reason")
		}
		
	default:
		return fmt.Errorf("invalid rollback type: %s", request.RollbackType)
	}
	
	return nil
}

func (v *DefaultRollbackValidator) checkBreakingChanges(ctx context.Context, changes []ConfigurationChange) []string {
	breakingChanges := []string{}
	
	for _, change := range changes {
		// Check for schema changes
		if strings.Contains(change.Path, "schema") {
			breakingChanges = append(breakingChanges, 
				fmt.Sprintf("Schema change detected in %s", change.Path))
		}
		
		// Check for API version changes
		if strings.Contains(change.Diff, "apiVersion") {
			breakingChanges = append(breakingChanges,
				fmt.Sprintf("API version change detected in %s", change.Path))
		}
		
		// Check for removed required fields
		if strings.Contains(change.Diff, "required:") && strings.Contains(change.Diff, "-") {
			breakingChanges = append(breakingChanges,
				fmt.Sprintf("Required field removal detected in %s", change.Path))
		}
	}
	
	return breakingChanges
}

func (v *DefaultRollbackValidator) validatePermissions(ctx context.Context, request RollbackRequest) error {
	// In a real implementation, this would check actual permissions
	// For now, we'll simulate some basic checks
	
	// Emergency rollbacks require special permission
	if request.Emergency {
		// Check for emergency rollback permission
		// return error if not authorized
	}
	
	// MSP-level rollbacks require admin permission
	if request.TargetType == TargetTypeMSP {
		// Check for MSP admin permission
		// return error if not authorized
	}
	
	return nil
}

func (v *DefaultRollbackValidator) checkSystemHealth(ctx context.Context, targetType TargetType, targetID string) []ValidationIssue {
	issues := []ValidationIssue{}
	
	// In a real implementation, this would check actual system health
	// For now, we'll simulate some checks
	
	// Check CPU usage
	cpuUsage := 75 // Simulated
	if cpuUsage > 80 {
		issues = append(issues, ValidationIssue{
			Type:       "system_health",
			Severity:   "warning",
			Message:    fmt.Sprintf("High CPU usage detected: %d%%", cpuUsage),
			Resolvable: true,
			Resolution: "Wait for CPU usage to decrease or proceed with caution",
		})
	}
	
	// Check available disk space
	diskFree := 15 // Simulated percentage
	if diskFree < 20 {
		issues = append(issues, ValidationIssue{
			Type:       "system_health",
			Severity:   "warning",
			Message:    fmt.Sprintf("Low disk space: %d%% free", diskFree),
			Resolvable: true,
			Resolution: "Free up disk space before proceeding",
		})
	}
	
	return issues
}

func (v *DefaultRollbackValidator) estimateDowntime(changes []ConfigurationChange) time.Duration {
	// Base downtime for rollback operation
	downtime := 30 * time.Second
	
	// Add time for each change
	downtime += time.Duration(len(changes)) * 5 * time.Second
	
	// Add extra time for critical changes
	for _, change := range changes {
		if strings.Contains(change.Path, "network") || strings.Contains(change.Path, "database") {
			downtime += 30 * time.Second
		}
	}
	
	return downtime
}

func (v *DefaultRollbackValidator) estimateAffectedUsers(targetType TargetType, targetID string) int {
	// In a real implementation, this would query actual user counts
	// For now, we'll use estimates based on target type
	
	switch targetType {
	case TargetTypeDevice:
		return 1
	case TargetTypeGroup:
		return 50
	case TargetTypeClient:
		return 500
	case TargetTypeMSP:
		return 5000
	default:
		return 0
	}
}