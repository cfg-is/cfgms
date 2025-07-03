package patch

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/modules"
)

// New creates a new instance of the Patch module
func New() modules.Module {
	return &PatchModule{
		patchManager: NewMockPatchManager(),
	}
}

// NewPatchModule creates a new patch module instance with the specified patch manager
func NewPatchModule(patchManager PatchManager) (*PatchModule, error) {
	if patchManager == nil {
		return nil, ErrInvalidConfig
	}

	return &PatchModule{
		patchManager: patchManager,
	}, nil
}

// Get returns the current patch status of the system
func (m *PatchModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	if resourceID == "" {
		return nil, ErrInvalidResourceID
	}

	// Check if we need to refresh the cached status (check outside of lock)
	m.mu.RLock()
	needsRefresh := time.Since(m.lastCheck) > 5*time.Minute || m.cachedStatus == nil
	m.mu.RUnlock()

	if needsRefresh {
		if err := m.refreshStatus(ctx); err != nil {
			return nil, fmt.Errorf("failed to refresh patch status: %w", err)
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Build current configuration based on system state
	config := &Config{
		PatchType:  "security", // Default to security patches
		AutoReboot: false,      // Default to manual reboot
		TestMode:   false,      // Default to actual patching
	}

	// Add information about available patches in a comment-like field
	// This isn't a real config field but provides status information
	if len(m.cachedStatus.AvailablePatches) > 0 {
		var patchIDs []string
		for _, patch := range m.cachedStatus.AvailablePatches {
			patchIDs = append(patchIDs, patch.ID)
		}
		// We'll add this as metadata rather than direct config
	}

	return config, nil
}

// Set applies patch configuration to the system
func (m *PatchModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	if resourceID == "" {
		return ErrInvalidResourceID
	}

	if config == nil || reflect.ValueOf(config).IsNil() {
		return ErrInvalidConfig
	}

	// Convert ConfigState to Config
	configMap := config.AsMap()

	m.mu.Lock()
	// Note: We manually unlock before refreshStatus call at the end
	cfg := &Config{}

	if patchType, ok := configMap["patch_type"].(string); ok {
		cfg.PatchType = patchType
	} else {
		cfg.PatchType = "security" // Default
	}

	if autoReboot, ok := configMap["auto_reboot"].(bool); ok {
		cfg.AutoReboot = autoReboot
	}

	if testMode, ok := configMap["test_mode"].(bool); ok {
		cfg.TestMode = testMode
	}

	if maxDowntime, ok := configMap["max_downtime"].(string); ok {
		cfg.MaxDowntime = maxDowntime
	}

	if prePatchScript, ok := configMap["pre_patch_script"].(string); ok {
		cfg.PrePatchScript = prePatchScript
	}

	if postPatchScript, ok := configMap["post_patch_script"].(string); ok {
		cfg.PostPatchScript = postPatchScript
	}

	// Handle include/exclude patches
	if includePatches, ok := configMap["include_patches"].([]string); ok {
		cfg.IncludePatches = includePatches
	} else if includePatchesInterface, ok := configMap["include_patches"].([]interface{}); ok {
		for _, p := range includePatchesInterface {
			if patchStr, ok := p.(string); ok {
				cfg.IncludePatches = append(cfg.IncludePatches, patchStr)
			}
		}
	}

	if excludePatches, ok := configMap["exclude_patches"].([]string); ok {
		cfg.ExcludePatches = excludePatches
	} else if excludePatchesInterface, ok := configMap["exclude_patches"].([]interface{}); ok {
		for _, p := range excludePatchesInterface {
			if patchStr, ok := p.(string); ok {
				cfg.ExcludePatches = append(cfg.ExcludePatches, patchStr)
			}
		}
	}

	// Handle maintenance window
	if maintenanceData, ok := configMap["maintenance"].(map[string]interface{}); ok {
		if window, ok := maintenanceData["window"].(string); ok {
			cfg.Maintenance.Window = window
		}
		if schedule, ok := maintenanceData["schedule"].(string); ok {
			cfg.Maintenance.Schedule = schedule
		}
		if duration, ok := maintenanceData["duration"].(time.Duration); ok {
			cfg.Maintenance.Duration = duration
		}
		if timezone, ok := maintenanceData["timezone"].(string); ok {
			cfg.Maintenance.Timezone = timezone
		}
	}

	// Handle platform-specific options
	if platformData, ok := configMap["platform"].(map[string]interface{}); ok {
		if useYum, ok := platformData["use_yum"].(bool); ok {
			cfg.Platform.UseYum = useYum
		}
		if useApt, ok := platformData["use_apt"].(bool); ok {
			cfg.Platform.UseApt = useApt
		}
		if updateKernel, ok := platformData["update_kernel"].(bool); ok {
			cfg.Platform.UpdateKernel = updateKernel
		}
		if useWSUS, ok := platformData["use_wsus"].(bool); ok {
			cfg.Platform.UseWSUS = useWSUS
		}
		if wsusServer, ok := platformData["wsus_server"].(string); ok {
			cfg.Platform.WSUSServer = wsusServer
		}
		if includeAppStore, ok := platformData["include_app_store"].(bool); ok {
			cfg.Platform.IncludeAppStore = includeAppStore
		}
	}

	// Validate the configuration
	if err := cfg.validate(); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("invalid patch configuration: %w", err)
	}

	// Execute pre-patch script if specified
	if cfg.PrePatchScript != "" {
		if err := m.executeScript(ctx, cfg.PrePatchScript); err != nil {
			m.mu.Unlock()
			return fmt.Errorf("pre-patch script failed: %w", err)
		}
	}

	// Check if we're in a maintenance window (if specified)
	if cfg.Maintenance.Window != "" || cfg.Maintenance.Schedule != "" {
		if !m.isInMaintenanceWindow(cfg) {
			m.mu.Unlock()
			return ErrMaintenanceWindowNotActive
		}
	}

	// Install patches
	if err := m.patchManager.InstallPatches(ctx, cfg); err != nil {
		m.mu.Unlock()
		return fmt.Errorf("patch installation failed: %w", err)
	}

	// Execute post-patch script if specified
	if cfg.PostPatchScript != "" {
		if err := m.executeScript(ctx, cfg.PostPatchScript); err != nil {
			// Log warning but don't fail the operation
			// In a real implementation, this would use proper logging
			fmt.Printf("Warning: post-patch script failed: %v\n", err)
		}
	}

	// Check if reboot is required
	rebootRequired, err := m.patchManager.CheckRebootRequired(ctx)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("failed to check reboot status: %w", err)
	}

	if rebootRequired {
		if cfg.AutoReboot {
			// In a real implementation, this would trigger a system reboot
			// For now, we'll just log it
			fmt.Println("Auto-reboot would be triggered here")
		} else {
			m.mu.Unlock()
			return ErrRebootRequired
		}
	}

	// Release the lock before refreshing status
	m.mu.Unlock()
	
	// Refresh cached status after successful patching
	err = m.refreshStatus(ctx)
	if err != nil {
		// Don't fail the operation if status refresh fails
		fmt.Printf("Warning: failed to refresh patch status: %v\n", err)
	}

	return nil
}

// refreshStatus updates the cached patch status
func (m *PatchModule) refreshStatus(ctx context.Context) error {
	// Get available patches
	availablePatches, err := m.patchManager.ListAvailablePatches(ctx, "all")
	if err != nil {
		return fmt.Errorf("failed to list available patches: %w", err)
	}

	// Get installed patches
	installedPatches, err := m.patchManager.ListInstalledPatches(ctx)
	if err != nil {
		return fmt.Errorf("failed to list installed patches: %w", err)
	}

	// Get last patch date
	lastPatchDate, err := m.patchManager.GetLastPatchDate(ctx)
	if err != nil {
		return fmt.Errorf("failed to get last patch date: %w", err)
	}

	// Check reboot status
	rebootRequired, err := m.patchManager.CheckRebootRequired(ctx)
	if err != nil {
		return fmt.Errorf("failed to check reboot status: %w", err)
	}

	// Calculate statistics
	var totalSize int64
	var securityPatches, criticalPatches int
	var pendingPatches []PatchInfo

	for _, patch := range availablePatches {
		if !patch.Installed {
			pendingPatches = append(pendingPatches, patch)
			totalSize += patch.Size
			
			if patch.Category == "security" {
				securityPatches++
			}
			if patch.Severity == "critical" {
				criticalPatches++
			}
		}
	}

	// Update cached status
	m.cachedStatus = &PatchStatus{
		LastPatchDate:    lastPatchDate,
		RebootRequired:   rebootRequired,
		AvailablePatches: availablePatches,
		InstalledPatches: installedPatches,
		PendingPatches:   pendingPatches,
		TotalSize:        totalSize,
		SecurityPatches:  securityPatches,
		CriticalPatches:  criticalPatches,
	}

	m.lastCheck = time.Now()
	return nil
}

// executeScript executes a shell script (placeholder implementation)
func (m *PatchModule) executeScript(ctx context.Context, script string) error {
	// In a real implementation, this would execute the script
	// For now, we'll just validate that it's not empty
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("empty script")
	}
	
	// Simulate script execution
	fmt.Printf("Executing script: %s\n", script)
	return nil
}

// isInMaintenanceWindow checks if the current time is within the maintenance window
func (m *PatchModule) isInMaintenanceWindow(config *Config) bool {
	// In a real implementation, this would parse the maintenance window
	// and check if the current time falls within it
	// For now, we'll just return true as a placeholder
	return true
}

// GetPatchStatus returns the current patch status
func (m *PatchModule) GetPatchStatus(ctx context.Context) (*PatchStatus, error) {
	// Check if we need to refresh the cached status (check outside of lock)
	m.mu.RLock()
	needsRefresh := time.Since(m.lastCheck) > 5*time.Minute || m.cachedStatus == nil
	m.mu.RUnlock()

	if needsRefresh {
		if err := m.refreshStatus(ctx); err != nil {
			return nil, err
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cachedStatus, nil
}