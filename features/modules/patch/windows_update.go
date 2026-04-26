//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// +build windows

package patch

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// WindowsUpdateManager implements PatchManager for Windows systems using COM API
type WindowsUpdateManager struct {
	session *ole.IDispatch
}

// NewWindowsUpdateManager creates a new Windows Update manager using COM API
func NewWindowsUpdateManager() (*WindowsUpdateManager, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("Windows Update manager only available on Windows")
	}

	// Initialize COM
	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize COM: %w", err)
	}

	// Create IUpdateSession
	unknown, err := oleutil.CreateObject("Microsoft.Update.Session")
	if err != nil {
		ole.CoUninitialize()
		return nil, fmt.Errorf("failed to create update session: %w", err)
	}

	session, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		ole.CoUninitialize()
		return nil, fmt.Errorf("failed to query dispatch interface: %w", err)
	}

	return &WindowsUpdateManager{
		session: session,
	}, nil
}

// Close releases COM resources
func (w *WindowsUpdateManager) Close() error {
	if w.session != nil {
		w.session.Release()
	}
	ole.CoUninitialize()
	return nil
}

// ListAvailablePatches returns available patches using Windows Update COM API
func (w *WindowsUpdateManager) ListAvailablePatches(ctx context.Context, patchType string) ([]PatchInfo, error) {
	// Create IUpdateSearcher
	searcher, err := oleutil.CallMethod(w.session, "CreateUpdateSearcher")
	if err != nil {
		return nil, fmt.Errorf("failed to create update searcher: %w", err)
	}
	defer searcher.Clear()

	// Build search criteria based on patch type
	criteria, err := w.buildSearchCriteria(patchType)
	if err != nil {
		return nil, fmt.Errorf("unsupported patch type %q: %w", patchType, err)
	}

	// Search for updates
	searchResult, err := oleutil.CallMethod(searcher.ToIDispatch(), "Search", criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for updates: %w", err)
	}
	defer searchResult.Clear()

	// Get Updates collection
	updatesCollection, err := oleutil.GetProperty(searchResult.ToIDispatch(), "Updates")
	if err != nil {
		return nil, fmt.Errorf("failed to get updates collection: %w", err)
	}
	defer updatesCollection.Clear()

	// Get update count
	countVariant, err := oleutil.GetProperty(updatesCollection.ToIDispatch(), "Count")
	if err != nil {
		return nil, fmt.Errorf("failed to get update count: %w", err)
	}
	count := int(countVariant.Val)

	patches := make([]PatchInfo, 0, count)

	// Iterate through updates
	for i := 0; i < count; i++ {
		updateVariant, err := oleutil.GetProperty(updatesCollection.ToIDispatch(), "Item", i)
		if err != nil {
			continue
		}
		update := updateVariant.ToIDispatch()

		patchInfo := w.extractPatchInfo(update)
		patches = append(patches, patchInfo)

		update.Release()
	}

	return patches, nil
}

// ListInstalledPatches returns currently installed patches
func (w *WindowsUpdateManager) ListInstalledPatches(ctx context.Context) ([]PatchInfo, error) {
	// Create IUpdateSearcher
	searcher, err := oleutil.CallMethod(w.session, "CreateUpdateSearcher")
	if err != nil {
		return nil, fmt.Errorf("failed to create update searcher: %w", err)
	}
	defer searcher.Clear()

	// Search for installed updates
	criteria := "IsInstalled=1"
	searchResult, err := oleutil.CallMethod(searcher.ToIDispatch(), "Search", criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for installed updates: %w", err)
	}
	defer searchResult.Clear()

	// Get Updates collection
	updatesCollection, err := oleutil.GetProperty(searchResult.ToIDispatch(), "Updates")
	if err != nil {
		return nil, fmt.Errorf("failed to get updates collection: %w", err)
	}
	defer updatesCollection.Clear()

	// Get update count
	countVariant, err := oleutil.GetProperty(updatesCollection.ToIDispatch(), "Count")
	if err != nil {
		return nil, fmt.Errorf("failed to get update count: %w", err)
	}
	count := int(countVariant.Val)

	patches := make([]PatchInfo, 0, count)

	// Iterate through updates
	for i := 0; i < count; i++ {
		updateVariant, err := oleutil.GetProperty(updatesCollection.ToIDispatch(), "Item", i)
		if err != nil {
			continue
		}
		update := updateVariant.ToIDispatch()

		patchInfo := w.extractPatchInfo(update)
		patchInfo.Installed = true
		patches = append(patches, patchInfo)

		update.Release()
	}

	return patches, nil
}

// InstallPatches installs patches based on the configuration
func (w *WindowsUpdateManager) InstallPatches(ctx context.Context, config *Config) error {
	// Create IUpdateSearcher
	searcher, err := oleutil.CallMethod(w.session, "CreateUpdateSearcher")
	if err != nil {
		return fmt.Errorf("failed to create update searcher: %w", err)
	}
	defer searcher.Clear()

	// Build search criteria
	criteria, err := w.buildSearchCriteria(config.PatchType)
	if err != nil {
		return fmt.Errorf("unsupported patch type %q: %w", config.PatchType, err)
	}

	// Search for updates
	searchResult, err := oleutil.CallMethod(searcher.ToIDispatch(), "Search", criteria)
	if err != nil {
		return fmt.Errorf("failed to search for updates: %w", err)
	}
	defer searchResult.Clear()

	// Get Updates collection
	updatesCollection, err := oleutil.GetProperty(searchResult.ToIDispatch(), "Updates")
	if err != nil {
		return fmt.Errorf("failed to get updates collection: %w", err)
	}
	defer updatesCollection.Clear()

	// Filter updates based on include/exclude lists
	updatesToInstall, err := w.filterUpdates(updatesCollection.ToIDispatch(), config)
	if err != nil {
		return fmt.Errorf("failed to filter updates: %w", err)
	}
	defer updatesToInstall.Release()

	// Check if there are updates to install
	countVariant, err := oleutil.GetProperty(updatesToInstall, "Count")
	if err != nil {
		return fmt.Errorf("failed to get update count: %w", err)
	}
	count := int(countVariant.Val)

	if count == 0 {
		return nil // No updates to install
	}

	// Create IUpdateDownloader
	downloader, err := oleutil.CallMethod(w.session, "CreateUpdateDownloader")
	if err != nil {
		return fmt.Errorf("failed to create downloader: %w", err)
	}
	defer downloader.Clear()

	// Set updates to download
	_, err = oleutil.PutProperty(downloader.ToIDispatch(), "Updates", updatesToInstall)
	if err != nil {
		return fmt.Errorf("failed to set updates for download: %w", err)
	}

	// Download updates
	if !config.TestMode {
		downloadResult, err := oleutil.CallMethod(downloader.ToIDispatch(), "Download")
		if err != nil {
			return fmt.Errorf("failed to download updates: %w", err)
		}
		downloadResult.Clear()
	}

	// Create IUpdateInstaller
	installer, err := oleutil.CallMethod(w.session, "CreateUpdateInstaller")
	if err != nil {
		return fmt.Errorf("failed to create installer: %w", err)
	}
	defer installer.Clear()

	// Set updates to install
	_, err = oleutil.PutProperty(installer.ToIDispatch(), "Updates", updatesToInstall)
	if err != nil {
		return fmt.Errorf("failed to set updates for installation: %w", err)
	}

	// Install updates
	if !config.TestMode {
		installResult, err := oleutil.CallMethod(installer.ToIDispatch(), "Install")
		if err != nil {
			return fmt.Errorf("failed to install updates: %w", err)
		}
		installResult.Clear()
	}

	return nil
}

// CheckRebootRequired checks if a reboot is required after patching
func (w *WindowsUpdateManager) CheckRebootRequired(ctx context.Context) (bool, error) {
	// Create ISystemInformation
	sysInfo, err := oleutil.CreateObject("Microsoft.Update.SystemInfo")
	if err != nil {
		return false, fmt.Errorf("failed to create system info: %w", err)
	}
	defer sysInfo.Release()

	dispatch, err := sysInfo.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return false, fmt.Errorf("failed to query dispatch interface: %w", err)
	}
	defer dispatch.Release()

	// Get RebootRequired property
	rebootVariant, err := oleutil.GetProperty(dispatch, "RebootRequired")
	if err != nil {
		return false, fmt.Errorf("failed to get reboot required status: %w", err)
	}

	return rebootVariant.Value().(bool), nil
}

// GetLastPatchDate returns the date of the last successful patch operation
func (w *WindowsUpdateManager) GetLastPatchDate(ctx context.Context) (time.Time, error) {
	// Get update history
	historyCount := 1 // Get just the most recent update

	searcher, err := oleutil.CallMethod(w.session, "CreateUpdateSearcher")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create update searcher: %w", err)
	}
	defer searcher.Clear()

	// Query update history
	historyVariant, err := oleutil.CallMethod(searcher.ToIDispatch(), "QueryHistory", 0, historyCount)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query update history: %w", err)
	}
	defer historyVariant.Clear()

	history := historyVariant.ToIDispatch()

	// Get count
	countVariant, err := oleutil.GetProperty(history, "Count")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get history count: %w", err)
	}
	count := int(countVariant.Val)

	if count == 0 {
		return time.Time{}, nil // No update history
	}

	// Get first (most recent) entry
	entryVariant, err := oleutil.GetProperty(history, "Item", 0)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get history entry: %w", err)
	}
	defer entryVariant.Clear()

	entry := entryVariant.ToIDispatch()

	// Get Date property
	dateVariant, err := oleutil.GetProperty(entry, "Date")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get update date: %w", err)
	}

	// Convert OLE date to Go time
	oleDate := dateVariant.Val
	goTime, err := ole.GetVariantDate(uint64(oleDate))
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to convert OLE date: %w", err)
	}

	return goTime, nil
}

// Name returns the name of the patch manager
func (w *WindowsUpdateManager) Name() string {
	return "Windows Update"
}

// IsValidPatchType checks if the given patch type is valid for Windows.
// "feature-update" is registered as a recognized type so module-level validation
// accepts it; however, buildSearchCriteria returns an explicit error for it until
// windowsUpgradeCategoryGUID is confirmed from Microsoft documentation. Callers
// that proceed to InstallPatches or ListAvailablePatches will receive that error.
func (w *WindowsUpdateManager) IsValidPatchType(patchType string) bool {
	validTypes := map[string]bool{
		"security":       true,
		"critical":       true,
		"all":            true,
		"feature-update": true,
	}
	return validTypes[patchType]
}

// windowsUpgradeCategoryGUID is the Windows Update category GUID for the "Windows Upgrades" category.
// This value must be confirmed from Microsoft WUA SDK documentation before use.
// Left empty to trigger the explicit-error fallback until an authoritative source is cited in the PR.
const windowsUpgradeCategoryGUID = ""

// buildSearchCriteria builds Windows Update search criteria based on patch type.
// Returns an error for patch types that require an unconfirmed category GUID.
func (w *WindowsUpdateManager) buildSearchCriteria(patchType string) (string, error) {
	switch patchType {
	case "security":
		return "IsInstalled=0 AND Type='Software' AND CategoryIDs contains '0FA1201D-4330-4FA8-8AE9-B877473B6441'", nil
	case "critical":
		return "IsInstalled=0 AND Type='Software' AND MsrcSeverity='Critical'", nil
	case "all":
		return "IsInstalled=0 AND Type='Software'", nil
	case "feature-update":
		if windowsUpgradeCategoryGUID == "" {
			return "", fmt.Errorf("feature updates require Windows Update for Business or the Media Creation Tool — not supported by this implementation")
		}
		return fmt.Sprintf("IsInstalled=0 AND Type='Software' AND CategoryIDs contains '%s'", windowsUpgradeCategoryGUID), nil
	default:
		return "IsInstalled=0 AND Type='Software'", nil
	}
}

// filterUpdates filters updates based on include/exclude lists
func (w *WindowsUpdateManager) filterUpdates(updatesCollection *ole.IDispatch, config *Config) (*ole.IDispatch, error) {
	// Create UpdateCollection for filtered results
	updateColl, err := oleutil.CreateObject("Microsoft.Update.UpdateColl")
	if err != nil {
		return nil, fmt.Errorf("failed to create update collection: %w", err)
	}

	filteredColl, err := updateColl.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		updateColl.Release()
		return nil, fmt.Errorf("failed to query dispatch interface: %w", err)
	}
	updateColl.Release()

	// Get count of available updates
	countVariant, err := oleutil.GetProperty(updatesCollection, "Count")
	if err != nil {
		filteredColl.Release()
		return nil, fmt.Errorf("failed to get update count: %w", err)
	}
	count := int(countVariant.Val)

	// Filter updates
	for i := 0; i < count; i++ {
		updateVariant, err := oleutil.GetProperty(updatesCollection, "Item", i)
		if err != nil {
			continue
		}
		update := updateVariant.ToIDispatch()

		// Get update ID
		kbArticleIDsVariant, err := oleutil.GetProperty(update, "KBArticleIDs")
		if err != nil {
			update.Release()
			continue
		}
		kbArticleIDs := kbArticleIDsVariant.ToIDispatch()

		// Check if update should be included
		shouldInclude := w.shouldIncludeUpdate(kbArticleIDs, config)
		kbArticleIDs.Release()

		if shouldInclude {
			_, err = oleutil.CallMethod(filteredColl, "Add", update)
			if err != nil {
				update.Release()
				continue
			}
		}

		update.Release()
	}

	return filteredColl, nil
}

// shouldIncludeUpdate checks if an update should be included based on include/exclude lists
func (w *WindowsUpdateManager) shouldIncludeUpdate(kbArticleIDs *ole.IDispatch, config *Config) bool {
	countVariant, err := oleutil.GetProperty(kbArticleIDs, "Count")
	if err != nil {
		return true // Include by default if we can't check
	}
	count := int(countVariant.Val)

	if count == 0 {
		return true
	}

	// Get first KB article ID
	kbVariant, err := oleutil.GetProperty(kbArticleIDs, "Item", 0)
	if err != nil {
		return true
	}
	kbID := fmt.Sprintf("KB%v", kbVariant.Val)

	// Check exclude list first
	for _, excludeID := range config.ExcludePatches {
		if excludeID == kbID {
			return false
		}
	}

	// If include list is specified, only include if in list
	if len(config.IncludePatches) > 0 {
		for _, includeID := range config.IncludePatches {
			if includeID == kbID {
				return true
			}
		}
		return false
	}

	return true
}

// extractPatchInfo extracts patch information from an IUpdate COM object
func (w *WindowsUpdateManager) extractPatchInfo(update *ole.IDispatch) PatchInfo {
	patchInfo := PatchInfo{}

	// Get Title
	if titleVariant, err := oleutil.GetProperty(update, "Title"); err == nil {
		patchInfo.Title = titleVariant.Value().(string)
	}

	// Get Description
	if descVariant, err := oleutil.GetProperty(update, "Description"); err == nil {
		patchInfo.Description = descVariant.Value().(string)
	}

	// Get KB Article IDs
	if kbVariant, err := oleutil.GetProperty(update, "KBArticleIDs"); err == nil {
		kbArticleIDs := kbVariant.ToIDispatch()
		if countVariant, err := oleutil.GetProperty(kbArticleIDs, "Count"); err == nil {
			count := int(countVariant.Val)
			if count > 0 {
				if idVariant, err := oleutil.GetProperty(kbArticleIDs, "Item", 0); err == nil {
					patchInfo.ID = fmt.Sprintf("KB%v", idVariant.Val)
				}
			}
		}
		kbArticleIDs.Release()
	}

	// If no KB ID found, try to use UpdateID as fallback
	if patchInfo.ID == "" {
		if updateIDVariant, err := oleutil.GetProperty(update, "UpdateID"); err == nil {
			if updateID, ok := updateIDVariant.Value().(string); ok && updateID != "" {
				patchInfo.ID = updateID
			}
		}
	}

	// If still no ID, use Title as last resort (truncated to 50 chars)
	if patchInfo.ID == "" && patchInfo.Title != "" {
		title := patchInfo.Title
		if len(title) > 50 {
			title = title[:50]
		}
		// Replace spaces and special chars with underscores for ID safety
		title = strings.Map(func(r rune) rune {
			if r == ' ' || r == '(' || r == ')' || r == '[' || r == ']' {
				return '_'
			}
			return r
		}, title)
		patchInfo.ID = "TITLE_" + title
	}

	// Get MsrcSeverity
	if severityVariant, err := oleutil.GetProperty(update, "MsrcSeverity"); err == nil {
		if severity, ok := severityVariant.Value().(string); ok && severity != "" {
			patchInfo.Severity = strings.ToLower(severity)
		}
	}
	// Ensure we always have a severity value
	if patchInfo.Severity == "" {
		patchInfo.Severity = "unspecified"
	}

	// Get MaxDownloadSize
	if sizeVariant, err := oleutil.GetProperty(update, "MaxDownloadSize"); err == nil {
		if size, ok := sizeVariant.Value().(int64); ok {
			patchInfo.Size = size
		}
	}

	// Get LastDeploymentChangeTime
	if dateVariant, err := oleutil.GetProperty(update, "LastDeploymentChangeTime"); err == nil {
		oleDate := dateVariant.Val
		if releaseDate, dateErr := ole.GetVariantDate(uint64(oleDate)); dateErr == nil {
			patchInfo.ReleaseDate = releaseDate
		}
	}

	// Get RebootRequired
	if rebootVariant, err := oleutil.GetProperty(update, "RebootRequired"); err == nil {
		if reboot, ok := rebootVariant.Value().(bool); ok {
			patchInfo.RebootRequired = reboot
		}
	}

	// Determine category based on update properties
	if categoriesVariant, err := oleutil.GetProperty(update, "Categories"); err == nil {
		categories := categoriesVariant.ToIDispatch()
		if countVariant, err := oleutil.GetProperty(categories, "Count"); err == nil {
			count := int(countVariant.Val)
			if count > 0 {
				if catVariant, err := oleutil.GetProperty(categories, "Item", 0); err == nil {
					category := catVariant.ToIDispatch()
					if nameVariant, err := oleutil.GetProperty(category, "Name"); err == nil {
						categoryName := nameVariant.Value().(string)
						if categoryName == "Security Updates" {
							patchInfo.Category = "security"
						} else {
							patchInfo.Category = "bugfix"
						}
					}
					category.Release()
				}
			}
		}
		categories.Release()
	}

	return patchInfo
}
