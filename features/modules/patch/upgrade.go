package patch

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// Windows11Requirements defines minimum hardware requirements for Windows 11
type Windows11Requirements struct {
	// TPMVersion is the minimum TPM version required (2.0 for Windows 11)
	TPMVersion string

	// RequiresUEFI indicates if UEFI firmware is required (true for Windows 11)
	RequiresUEFI bool

	// MinCPUCores is the minimum number of CPU cores required
	MinCPUCores int

	// MinCPUSpeedGHz is the minimum CPU speed in GHz
	MinCPUSpeedGHz float64

	// MinRAMGB is the minimum RAM in gigabytes
	MinRAMGB int

	// MinStorageGB is the minimum storage space in gigabytes
	MinStorageGB int

	// RequiresSecureBoot indicates if Secure Boot is required
	RequiresSecureBoot bool

	// MinDirectXVersion is the minimum DirectX version required
	MinDirectXVersion string
}

// DefaultWindows11Requirements returns the standard Windows 11 requirements
func DefaultWindows11Requirements() Windows11Requirements {
	return Windows11Requirements{
		TPMVersion:         "2.0",
		RequiresUEFI:       true,
		MinCPUCores:        2,
		MinCPUSpeedGHz:     1.0,
		MinRAMGB:           4,
		MinStorageGB:       64,
		RequiresSecureBoot: true,
		MinDirectXVersion:  "12",
	}
}

// CompatibilityResult represents the result of a compatibility check
type CompatibilityResult struct {
	// Compatible indicates if the device meets all requirements
	Compatible bool

	// MissingRequirements lists requirements that are not met
	MissingRequirements []string

	// Warnings lists non-blocking compatibility warnings
	Warnings []string

	// DeviceDNA is the DNA data used for the check
	DeviceDNA *commonpb.DNA

	// CheckedAt is when the compatibility check was performed
	CheckedAt time.Time

	// TargetVersion is the Windows version being checked for
	TargetVersion string
}

// UpgradePolicy defines policy for major version upgrades
type UpgradePolicy struct {
	// Enabled indicates if major version upgrades are allowed
	Enabled bool `yaml:"enabled" json:"enabled"`

	// AutoUpgrade indicates if upgrades should be automatic
	AutoUpgrade bool `yaml:"auto_upgrade" json:"auto_upgrade"`

	// TargetVersion is the target Windows version (e.g., "11", "11 23H2")
	TargetVersion string `yaml:"target_version" json:"target_version"`

	// RequireCompatibilityCheck indicates if compatibility must be validated
	RequireCompatibilityCheck bool `yaml:"require_compatibility_check" json:"require_compatibility_check"`

	// BlockIncompatible prevents upgrades on incompatible hardware
	BlockIncompatible bool `yaml:"block_incompatible" json:"block_incompatible"`

	// DeferDays is the number of days to defer the upgrade after release
	DeferDays int `yaml:"defer_days" json:"defer_days"`

	// TestMode enables test mode (no actual upgrade)
	TestMode bool `yaml:"test_mode" json:"test_mode"`

	// RollbackOnFailure enables automatic rollback on upgrade failure
	RollbackOnFailure bool `yaml:"rollback_on_failure" json:"rollback_on_failure"`

	// UpgradeWindow defines when upgrades can occur
	UpgradeWindow *TimeWindow `yaml:"upgrade_window,omitempty" json:"upgrade_window,omitempty"`
}

// TimeWindow defines a time period for operations
type TimeWindow struct {
	// StartHour is the start hour (0-23)
	StartHour int `yaml:"start_hour" json:"start_hour"`

	// EndHour is the end hour (0-23)
	EndHour int `yaml:"end_hour" json:"end_hour"`

	// DaysOfWeek lists allowed days (0=Sunday, 6=Saturday)
	DaysOfWeek []int `yaml:"days_of_week" json:"days_of_week"`
}

// DefaultUpgradePolicy returns default upgrade policy
func DefaultUpgradePolicy() UpgradePolicy {
	return UpgradePolicy{
		Enabled:                   false, // Disabled by default for safety
		AutoUpgrade:               false,
		TargetVersion:             "11",
		RequireCompatibilityCheck: true,
		BlockIncompatible:         true,
		DeferDays:                 30, // Wait 30 days after release
		TestMode:                  false,
		RollbackOnFailure:         true,
		UpgradeWindow:             nil, // No restrictions by default
	}
}

// CompatibilityChecker validates hardware compatibility for upgrades
type CompatibilityChecker struct {
	requirements Windows11Requirements
}

// NewCompatibilityChecker creates a new compatibility checker
func NewCompatibilityChecker(requirements Windows11Requirements) *CompatibilityChecker {
	return &CompatibilityChecker{
		requirements: requirements,
	}
}

// CheckCompatibility validates if device DNA meets upgrade requirements
func (cc *CompatibilityChecker) CheckCompatibility(dna *commonpb.DNA, targetVersion string) (*CompatibilityResult, error) {
	if dna == nil {
		return nil, fmt.Errorf("DNA data is required for compatibility check")
	}

	result := &CompatibilityResult{
		Compatible:          true,
		MissingRequirements: make([]string, 0),
		Warnings:            make([]string, 0),
		DeviceDNA:           dna,
		CheckedAt:           time.Now(),
		TargetVersion:       targetVersion,
	}

	// Check TPM version
	if err := cc.checkTPM(dna, result); err != nil {
		return nil, err
	}

	// Check UEFI/BIOS mode
	if err := cc.checkUEFI(dna, result); err != nil {
		return nil, err
	}

	// Check CPU requirements
	if err := cc.checkCPU(dna, result); err != nil {
		return nil, err
	}

	// Check RAM
	if err := cc.checkRAM(dna, result); err != nil {
		return nil, err
	}

	// Check storage
	if err := cc.checkStorage(dna, result); err != nil {
		return nil, err
	}

	// Check Secure Boot
	if err := cc.checkSecureBoot(dna, result); err != nil {
		return nil, err
	}

	// If any requirements are missing, mark as incompatible
	if len(result.MissingRequirements) > 0 {
		result.Compatible = false
	}

	return result, nil
}

// checkTPM validates TPM version
func (cc *CompatibilityChecker) checkTPM(dna *commonpb.DNA, result *CompatibilityResult) error {
	tpmVersion, exists := dna.Attributes["tpm_version"]
	if !exists || tpmVersion == "" {
		result.MissingRequirements = append(result.MissingRequirements,
			fmt.Sprintf("TPM %s not found (no TPM detected)", cc.requirements.TPMVersion))
		return nil
	}

	// Parse TPM version (e.g., "2.0" or "1.2")
	if !strings.HasPrefix(tpmVersion, cc.requirements.TPMVersion) {
		result.MissingRequirements = append(result.MissingRequirements,
			fmt.Sprintf("TPM %s required (found %s)", cc.requirements.TPMVersion, tpmVersion))
	}

	return nil
}

// checkUEFI validates UEFI firmware
func (cc *CompatibilityChecker) checkUEFI(dna *commonpb.DNA, result *CompatibilityResult) error {
	if !cc.requirements.RequiresUEFI {
		return nil
	}

	biosMode, exists := dna.Attributes["bios_mode"]
	if !exists {
		result.Warnings = append(result.Warnings, "BIOS mode could not be determined")
		return nil
	}

	if strings.ToLower(biosMode) != "uefi" {
		result.MissingRequirements = append(result.MissingRequirements,
			fmt.Sprintf("UEFI firmware required (found %s)", biosMode))
	}

	return nil
}

// checkCPU validates CPU requirements
func (cc *CompatibilityChecker) checkCPU(dna *commonpb.DNA, result *CompatibilityResult) error {
	// Check CPU cores
	coresStr, exists := dna.Attributes["cpu_cores"]
	if exists && coresStr != "" {
		cores, err := strconv.Atoi(coresStr)
		if err == nil && cores < cc.requirements.MinCPUCores {
			result.MissingRequirements = append(result.MissingRequirements,
				fmt.Sprintf("CPU with %d+ cores required (found %d)", cc.requirements.MinCPUCores, cores))
		}
	} else {
		result.Warnings = append(result.Warnings, "CPU core count could not be determined")
	}

	// Check CPU speed
	speedStr, exists := dna.Attributes["cpu_speed_ghz"]
	if exists && speedStr != "" {
		speed, err := strconv.ParseFloat(speedStr, 64)
		if err == nil && speed < cc.requirements.MinCPUSpeedGHz {
			result.MissingRequirements = append(result.MissingRequirements,
				fmt.Sprintf("CPU with %.1f+ GHz required (found %.1f GHz)", cc.requirements.MinCPUSpeedGHz, speed))
		}
	}

	return nil
}

// checkRAM validates memory requirements
func (cc *CompatibilityChecker) checkRAM(dna *commonpb.DNA, result *CompatibilityResult) error {
	ramStr, exists := dna.Attributes["ram_gb"]
	if !exists || ramStr == "" {
		result.Warnings = append(result.Warnings, "RAM capacity could not be determined")
		return nil
	}

	ram, err := strconv.Atoi(ramStr)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Invalid RAM value: %s", ramStr))
		return nil
	}

	if ram < cc.requirements.MinRAMGB {
		result.MissingRequirements = append(result.MissingRequirements,
			fmt.Sprintf("%d+ GB RAM required (found %d GB)", cc.requirements.MinRAMGB, ram))
	}

	return nil
}

// checkStorage validates storage requirements
func (cc *CompatibilityChecker) checkStorage(dna *commonpb.DNA, result *CompatibilityResult) error {
	storageStr, exists := dna.Attributes["storage_gb"]
	if !exists || storageStr == "" {
		result.Warnings = append(result.Warnings, "Storage capacity could not be determined")
		return nil
	}

	storage, err := strconv.Atoi(storageStr)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Invalid storage value: %s", storageStr))
		return nil
	}

	if storage < cc.requirements.MinStorageGB {
		result.MissingRequirements = append(result.MissingRequirements,
			fmt.Sprintf("%d+ GB storage required (found %d GB)", cc.requirements.MinStorageGB, storage))
	}

	return nil
}

// checkSecureBoot validates Secure Boot status
func (cc *CompatibilityChecker) checkSecureBoot(dna *commonpb.DNA, result *CompatibilityResult) error {
	if !cc.requirements.RequiresSecureBoot {
		return nil
	}

	secureBoot, exists := dna.Attributes["secure_boot"]
	if !exists {
		result.Warnings = append(result.Warnings, "Secure Boot status could not be determined")
		return nil
	}

	if strings.ToLower(secureBoot) != "enabled" {
		result.MissingRequirements = append(result.MissingRequirements,
			"Secure Boot must be enabled")
	}

	return nil
}

// UpgradeManager manages major version upgrades
type UpgradeManager struct {
	patchModule          *PatchModule
	compatibilityChecker *CompatibilityChecker
	policy               UpgradePolicy
	windowManager        WindowManager
	deviceID             string
}

// NewUpgradeManager creates a new upgrade manager
func NewUpgradeManager(
	patchModule *PatchModule,
	compatibilityChecker *CompatibilityChecker,
	policy UpgradePolicy,
	windowManager WindowManager,
	deviceID string,
) *UpgradeManager {
	return &UpgradeManager{
		patchModule:          patchModule,
		compatibilityChecker: compatibilityChecker,
		policy:               policy,
		windowManager:        windowManager,
		deviceID:             deviceID,
	}
}

// CheckUpgradeEligibility checks if device is eligible for upgrade
func (um *UpgradeManager) CheckUpgradeEligibility(ctx context.Context, dna *commonpb.DNA) (*CompatibilityResult, error) {
	if !um.policy.Enabled {
		return nil, fmt.Errorf("major version upgrades are disabled by policy")
	}

	if !um.policy.RequireCompatibilityCheck {
		// Skip compatibility check if not required
		return &CompatibilityResult{
			Compatible:          true,
			MissingRequirements: []string{},
			Warnings:            []string{"Compatibility check skipped by policy"},
			CheckedAt:           time.Now(),
			TargetVersion:       um.policy.TargetVersion,
		}, nil
	}

	// Run compatibility check
	result, err := um.compatibilityChecker.CheckCompatibility(dna, um.policy.TargetVersion)
	if err != nil {
		return nil, fmt.Errorf("compatibility check failed: %w", err)
	}

	return result, nil
}

// CanUpgradeNow checks if upgrade can proceed now based on windows and policy
func (um *UpgradeManager) CanUpgradeNow(ctx context.Context) (bool, string, error) {
	if !um.policy.Enabled {
		return false, "major version upgrades disabled by policy", nil
	}

	// Check upgrade window if configured
	if um.policy.UpgradeWindow != nil {
		inWindow := um.isInUpgradeWindow(time.Now())
		if !inWindow {
			return false, "outside of upgrade window", nil
		}
	}

	// Check maintenance window if available
	if um.windowManager != nil {
		canPerform, err := um.windowManager.CanPerformMaintenance(ctx, um.deviceID)
		if err != nil {
			return false, "", fmt.Errorf("failed to check maintenance window: %w", err)
		}
		if !canPerform {
			return false, "outside of maintenance window", nil
		}
	}

	return true, "", nil
}

// isInUpgradeWindow checks if current time is within upgrade window
func (um *UpgradeManager) isInUpgradeWindow(now time.Time) bool {
	if um.policy.UpgradeWindow == nil {
		return true
	}

	window := um.policy.UpgradeWindow

	// Check day of week
	if len(window.DaysOfWeek) > 0 {
		dayAllowed := false
		currentDay := int(now.Weekday())
		for _, allowedDay := range window.DaysOfWeek {
			if currentDay == allowedDay {
				dayAllowed = true
				break
			}
		}
		if !dayAllowed {
			return false
		}
	}

	// Check time of day
	currentHour := now.Hour()
	if window.StartHour <= window.EndHour {
		// Normal window (e.g., 9:00 - 17:00)
		return currentHour >= window.StartHour && currentHour < window.EndHour
	} else {
		// Overnight window (e.g., 22:00 - 6:00)
		return currentHour >= window.StartHour || currentHour < window.EndHour
	}
}

// PerformUpgrade executes a major version upgrade
func (um *UpgradeManager) PerformUpgrade(ctx context.Context, dna *commonpb.DNA) error {
	if um.policy.TestMode {
		// In test mode, just validate and return
		_, err := um.CheckUpgradeEligibility(ctx, dna)
		return err
	}

	// Check eligibility
	result, err := um.CheckUpgradeEligibility(ctx, dna)
	if err != nil {
		return fmt.Errorf("upgrade eligibility check failed: %w", err)
	}

	// Block if incompatible and policy requires it
	if !result.Compatible && um.policy.BlockIncompatible {
		return fmt.Errorf("device is not compatible with Windows %s: %v",
			um.policy.TargetVersion, result.MissingRequirements)
	}

	// Check if upgrade can proceed now
	canUpgrade, reason, err := um.CanUpgradeNow(ctx)
	if err != nil {
		return fmt.Errorf("failed to check upgrade timing: %w", err)
	}
	if !canUpgrade {
		return fmt.Errorf("cannot upgrade now: %s", reason)
	}

	// Create upgrade configuration
	config := &Config{
		PatchType:  "feature-update", // Windows feature update = major version
		AutoReboot: true,
		TestMode:   false,
	}

	// Execute upgrade through patch module
	if err := um.patchModule.Set(ctx, "upgrade", config); err != nil {
		if um.policy.RollbackOnFailure {
			// Windows will automatically rollback on failure
			return fmt.Errorf("upgrade failed (automatic rollback initiated): %w", err)
		}
		return fmt.Errorf("upgrade failed: %w", err)
	}

	return nil
}

// GetUpgradeStatus returns the current upgrade status
func (um *UpgradeManager) GetUpgradeStatus(ctx context.Context) (string, error) {
	// This would query Windows Update API for upgrade status
	// For now, return basic status based on policy
	if !um.policy.Enabled {
		return "disabled", nil
	}

	if um.policy.AutoUpgrade {
		return "auto-upgrade-enabled", nil
	}

	return "manual-upgrade-only", nil
}

// SetPolicy updates the upgrade policy
func (um *UpgradeManager) SetPolicy(policy UpgradePolicy) {
	um.policy = policy
}

// GetPolicy returns the current upgrade policy
func (um *UpgradeManager) GetPolicy() UpgradePolicy {
	return um.policy
}
