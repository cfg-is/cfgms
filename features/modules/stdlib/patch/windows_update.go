//go:build windows
// +build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package patch

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"github.com/cfgis/cfgms/pkg/logging"
)

// COM IDispatch.Clear() and VARIANT.Clear() calls throughout this file drop
// their error return via an explicit _ = (or a deferred closure). Every such
// release runs after the operation's outcome is already decided, and the COM
// runtime offers no remedy for a failed VARIANT release beyond an internal leak
// — the error is deliberately dropped rather than handled or logged.

// WindowsUpdateManager implements PatchManager for Windows systems using COM API
type WindowsUpdateManager struct {
	session  *ole.IDispatch
	comOwner bool // true only when this instance called CoInitializeEx and got S_OK
	logger   logging.Logger
}

// NewWindowsUpdateManager creates a new Windows Update manager using COM API
func NewWindowsUpdateManager() (*WindowsUpdateManager, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("not supported on %q: requires windows", runtime.GOOS)
	}

	// CoInitializeEx returns S_OK (0) on success and S_FALSE (1) when COM is already
	// initialized on the calling thread. go-ole v1.3.0 converts any non-zero HRESULT to
	// an error, so S_FALSE surfaces as *ole.OleError with Code()==1 and message
	// "Incorrect function." — this is a library quirk, not a real failure. Track COM
	// ownership to avoid calling CoUninitialize() on a thread we did not initialize.
	comOwner := false
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		if oleErr, ok := err.(*ole.OleError); !ok || oleErr.Code() != 1 {
			return nil, fmt.Errorf("failed to initialize COM: %w", err)
		}
		// Code()==1 is S_FALSE: COM already initialized on this thread, not an error.
	} else {
		comOwner = true
	}

	// Create IUpdateSession
	unknown, err := oleutil.CreateObject("Microsoft.Update.Session")
	if err != nil {
		if comOwner {
			ole.CoUninitialize()
		}
		return nil, fmt.Errorf("failed to create update session: %w", err)
	}

	session, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		if comOwner {
			ole.CoUninitialize()
		}
		return nil, fmt.Errorf("failed to query dispatch interface: %w", err)
	}

	return &WindowsUpdateManager{
		session:  session,
		comOwner: comOwner,
		logger:   logging.NewNoopLogger(),
	}, nil
}

// Close releases COM resources
func (w *WindowsUpdateManager) Close() error {
	if w.session != nil {
		w.session.Release()
	}
	if w.comOwner {
		ole.CoUninitialize()
	}
	return nil
}

// searchPollInterval is how often searchWithContext re-checks a running search
// job. The completion callback normally wakes the wait sooner; the poll is the
// safety net if a callback is never delivered.
const searchPollInterval = 100 * time.Millisecond

// iidSearchCompletedCallback is IID_ISearchCompletedCallback from wuapi.h.
var iidSearchCompletedCallback = ole.NewGUID("{88AEE058-D4B0-4725-A2F1-814A67AE964C}")

// searchCallback is a minimal in-process COM object implementing
// ISearchCompletedCallback (IUnknown plus Invoke). IUpdateSearcher.BeginSearch
// rejects a null onCompleted argument (VT_NULL fails with DISP_E_TYPEMISMATCH,
// a null IDispatch with DISP_E_EXCEPTION), so a real object is passed. Its
// Invoke only signals done; all COM calls stay on the polling goroutine.
//
// The vtable pointer must be the first field: COM reads it from the object's
// address.
type searchCallback struct {
	vtbl *searchCallbackVtbl
	refs int32
	done chan struct{} // capacity 1; Invoke never blocks on it
}

type searchCallbackVtbl struct {
	queryInterface uintptr
	addRef         uintptr
	release        uintptr
	invoke         uintptr
}

var (
	searchCallbackVtblOnce sync.Once
	searchCallbackVtblPtr  *searchCallbackVtbl

	// liveSearchCallbacks keeps every callback object reachable while COM may
	// still hold a reference: the Go collector cannot see pointers held by
	// Windows Update. An entry is removed when its reference count reaches zero.
	liveSearchCallbacksMu sync.Mutex
	liveSearchCallbacks   = map[*searchCallback]struct{}{}
)

// newSearchCallback returns a callback object holding one reference, owned by
// the caller, who must Release it.
func newSearchCallback() *searchCallback {
	// syscall.NewCallback slots are never freed, so the vtable is built once.
	searchCallbackVtblOnce.Do(func() {
		searchCallbackVtblPtr = &searchCallbackVtbl{
			queryInterface: syscall.NewCallback(searchCallbackQueryInterface),
			addRef:         syscall.NewCallback(searchCallbackAddRef),
			release:        syscall.NewCallback(searchCallbackRelease),
			invoke:         syscall.NewCallback(searchCallbackInvoke),
		}
	})
	cb := &searchCallback{vtbl: searchCallbackVtblPtr, refs: 1, done: make(chan struct{}, 1)}
	liveSearchCallbacksMu.Lock()
	liveSearchCallbacks[cb] = struct{}{}
	liveSearchCallbacksMu.Unlock()
	return cb
}

// Release drops the caller's reference.
func (cb *searchCallback) Release() {
	searchCallbackRelease(cb)
}

// asDispatch returns the object as the *ole.IDispatch go-ole needs to marshal it
// as an object argument (VT_DISPATCH). Only its address is used: it is never
// called through IDispatch, and Windows Update queries the interfaces it needs.
func (cb *searchCallback) asDispatch() *ole.IDispatch {
	return (*ole.IDispatch)(unsafe.Pointer(cb))
}

func searchCallbackQueryInterface(cb *searchCallback, riid *ole.GUID, ppv **searchCallback) uintptr {
	if ppv == nil {
		return ole.E_POINTER
	}
	if riid != nil && (ole.IsEqualGUID(riid, ole.IID_IUnknown) || ole.IsEqualGUID(riid, iidSearchCompletedCallback)) {
		atomic.AddInt32(&cb.refs, 1)
		*ppv = cb
		return ole.S_OK
	}
	*ppv = nil
	return ole.E_NOINTERFACE
}

func searchCallbackAddRef(cb *searchCallback) uintptr {
	return uintptr(atomic.AddInt32(&cb.refs, 1))
}

func searchCallbackRelease(cb *searchCallback) uintptr {
	n := atomic.AddInt32(&cb.refs, -1)
	if n == 0 {
		liveSearchCallbacksMu.Lock()
		delete(liveSearchCallbacks, cb)
		liveSearchCallbacksMu.Unlock()
	}
	return uintptr(n)
}

// searchCallbackInvoke is ISearchCompletedCallback::Invoke. It runs on a thread
// owned by Windows Update, so it only does a non-blocking send.
func searchCallbackInvoke(cb *searchCallback, _, _ uintptr) uintptr {
	select {
	case cb.done <- struct{}{}:
	default:
	}
	return ole.S_OK
}

// comErrorDetail renders the HRESULT and EXCEPINFO behind a go-ole error. go-ole
// reports only the generic HRESULT text (for example "Exception occurred"),
// which hides the Windows Update status code that explains it.
func comErrorDetail(err error) string {
	var oleErr *ole.OleError
	if !errors.As(err, &oleErr) {
		return "no COM error detail"
	}
	detail := fmt.Sprintf("hresult=%#x", uint32(oleErr.Code()))
	if excep, ok := oleErr.SubError().(ole.EXCEPINFO); ok {
		detail += ", excepinfo={" + excep.String() + "}"
	}
	return detail
}

// searchWithContext runs an IUpdateSearcher search bounded by ctx. It uses the
// asynchronous BeginSearch/EndSearch pair and waits for the completion callback,
// a poll tick or ctx, whichever comes first, so a cancelled context or elapsed
// deadline is observed promptly. On cancellation the job is aborted and cleaned
// up, and the returned error wraps ctx.Err(). The caller owns the returned
// ISearchResult variant and must Clear it.
func searchWithContext(ctx context.Context, searcher *ole.IDispatch, criteria string) (*ole.VARIANT, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("search not started: %w", err)
	}

	// onCompleted is a real ISearchCompletedCallback object (see searchCallback).
	// state is opaque caller data handed back to the callback; it is unused, and
	// an empty string is a non-null VARIANT that WUA accepts.
	cb := newSearchCallback()
	defer cb.Release()

	jobVariant, err := oleutil.CallMethod(searcher, "BeginSearch", criteria, cb.asDispatch(), "")
	if err != nil {
		return nil, fmt.Errorf("failed to begin search: %w (%s)", err, comErrorDetail(err))
	}
	defer func() { _ = jobVariant.Clear() }()
	job := jobVariant.ToIDispatch()

	ticker := time.NewTicker(searchPollInterval)
	defer ticker.Stop()

	for {
		completedVariant, err := oleutil.GetProperty(job, "IsCompleted")
		if err != nil {
			abortSearchJob(job)
			return nil, fmt.Errorf("failed to poll search job: %w (%s)", err, comErrorDetail(err))
		}
		completed, _ := completedVariant.Value().(bool)
		_ = completedVariant.Clear()
		if completed {
			break
		}

		select {
		case <-ctx.Done():
			abortSearchJob(job)
			return nil, fmt.Errorf("search aborted: %w", ctx.Err())
		case <-cb.done:
		case <-ticker.C:
		}
	}

	searchResult, err := oleutil.CallMethod(searcher, "EndSearch", job)
	if err != nil {
		abortSearchJob(job)
		return nil, fmt.Errorf("failed to end search: %w (%s)", err, comErrorDetail(err))
	}
	// The job is finished; release its resources.
	_, _ = oleutil.CallMethod(job, "CleanUp")
	return searchResult, nil
}

// abortSearchJob asks a running ISearchJob to stop and releases its resources.
// Failures are ignored: the job is being abandoned and the caller already holds
// the error that matters.
func abortSearchJob(job *ole.IDispatch) {
	_, _ = oleutil.CallMethod(job, "RequestAbort")
	_, _ = oleutil.CallMethod(job, "CleanUp")
}

// ListAvailablePatches returns available patches using Windows Update COM API
func (w *WindowsUpdateManager) ListAvailablePatches(ctx context.Context, patchType string) ([]PatchInfo, error) {
	// Create IUpdateSearcher
	searcher, err := oleutil.CallMethod(w.session, "CreateUpdateSearcher")
	if err != nil {
		return nil, fmt.Errorf("failed to create update searcher: %w", err)
	}
	defer func() { _ = searcher.Clear() }()

	// Build search criteria based on patch type
	criteria, err := w.buildSearchCriteria(patchType)
	if err != nil {
		return nil, fmt.Errorf("unsupported patch type %q: %w", patchType, err)
	}

	// Search for updates (online, bounded by ctx)
	searchResult, err := searchWithContext(ctx, searcher.ToIDispatch(), criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for updates: %w", err)
	}
	defer func() { _ = searchResult.Clear() }()

	// Get Updates collection
	updatesCollection, err := oleutil.GetProperty(searchResult.ToIDispatch(), "Updates")
	if err != nil {
		return nil, fmt.Errorf("failed to get updates collection: %w", err)
	}
	defer func() { _ = updatesCollection.Clear() }()

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
	defer func() { _ = searcher.Clear() }()

	// Installed updates are answered from the local update store: keep the
	// searcher offline so the query never waits on the Windows Update service
	// or network.
	if _, err := oleutil.PutProperty(searcher.ToIDispatch(), "Online", false); err != nil {
		return nil, fmt.Errorf("failed to set searcher offline: %w", err)
	}

	// Search for installed updates (bounded by ctx)
	criteria := "IsInstalled=1"
	searchResult, err := searchWithContext(ctx, searcher.ToIDispatch(), criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to search for installed updates: %w", err)
	}
	defer func() { _ = searchResult.Clear() }()

	// Get Updates collection
	updatesCollection, err := oleutil.GetProperty(searchResult.ToIDispatch(), "Updates")
	if err != nil {
		return nil, fmt.Errorf("failed to get updates collection: %w", err)
	}
	defer func() { _ = updatesCollection.Clear() }()

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
	defer func() { _ = searcher.Clear() }()

	// Build search criteria
	criteria, err := w.buildSearchCriteria(config.PatchType)
	if err != nil {
		return fmt.Errorf("unsupported patch type %q: %w", config.PatchType, err)
	}

	// Search for updates (online, bounded by ctx)
	searchResult, err := searchWithContext(ctx, searcher.ToIDispatch(), criteria)
	if err != nil {
		return fmt.Errorf("failed to search for updates: %w", err)
	}
	defer func() { _ = searchResult.Clear() }()

	// Get Updates collection
	updatesCollection, err := oleutil.GetProperty(searchResult.ToIDispatch(), "Updates")
	if err != nil {
		return fmt.Errorf("failed to get updates collection: %w", err)
	}
	defer func() { _ = updatesCollection.Clear() }()

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

	return w.downloadAndInstall(updatesToInstall, config)
}

// downloadAndInstall downloads and installs the already-filtered updates. In
// TestMode the downloader and installer are configured but not executed.
func (w *WindowsUpdateManager) downloadAndInstall(updatesToInstall *ole.IDispatch, config *Config) error {
	// Create IUpdateDownloader
	downloader, err := oleutil.CallMethod(w.session, "CreateUpdateDownloader")
	if err != nil {
		return fmt.Errorf("failed to create downloader: %w", err)
	}
	defer func() { _ = downloader.Clear() }()

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
		_ = downloadResult.Clear()
	}

	// Create IUpdateInstaller
	installer, err := oleutil.CallMethod(w.session, "CreateUpdateInstaller")
	if err != nil {
		return fmt.Errorf("failed to create installer: %w", err)
	}
	defer func() { _ = installer.Clear() }()

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
		_ = installResult.Clear()
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
	// The history query reads local state, but never start it for a caller that
	// has already given up.
	if err := ctx.Err(); err != nil {
		return time.Time{}, fmt.Errorf("update history query not started: %w", err)
	}

	// Get update history
	historyCount := 1 // Get just the most recent update

	searcher, err := oleutil.CallMethod(w.session, "CreateUpdateSearcher")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create update searcher: %w", err)
	}
	defer func() { _ = searcher.Clear() }()

	// Query update history
	historyVariant, err := oleutil.CallMethod(searcher.ToIDispatch(), "QueryHistory", 0, historyCount)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query update history: %w", err)
	}
	defer func() { _ = historyVariant.Clear() }()

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
	defer func() { _ = entryVariant.Clear() }()

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
			// Fails closed: an update whose KB IDs cannot be read is skipped.
			_, reason := decideKBInclusion(nil, err, config.IncludePatches, config.ExcludePatches)
			w.log().Warn("windows update excluded by patch filter", "reason", logging.SanitizeLogValue(reason))
			update.Release()
			continue
		}
		kbArticleIDs := kbArticleIDsVariant.ToIDispatch()
		if kbArticleIDs == nil {
			_, reason := decideKBInclusion(nil, fmt.Errorf("KBArticleIDs is not a collection"), config.IncludePatches, config.ExcludePatches)
			w.log().Warn("windows update excluded by patch filter", "reason", logging.SanitizeLogValue(reason))
			update.Release()
			continue
		}

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

// shouldIncludeUpdate reads every KB article ID of an update and decides
// against the include and exclude lists with decideKBInclusion, which fails
// closed. An exclusion is logged with its reason.
func (w *WindowsUpdateManager) shouldIncludeUpdate(kbArticleIDs *ole.IDispatch, config *Config) bool {
	kbIDs, readErr := readKBArticleIDs(kbArticleIDs)
	include, reason := decideKBInclusion(kbIDs, readErr, config.IncludePatches, config.ExcludePatches)
	if reason != "" {
		w.log().Warn("windows update excluded by patch filter", "reason", logging.SanitizeLogValue(reason))
	}
	return include
}

// readKBArticleIDs reads every entry of an update's KBArticleIDs string
// collection, formatted as "KB<number>". Any failed read is an error.
func readKBArticleIDs(kbArticleIDs *ole.IDispatch) ([]string, error) {
	countVariant, err := oleutil.GetProperty(kbArticleIDs, "Count")
	if err != nil {
		return nil, fmt.Errorf("read KB article ID count: %w", err)
	}
	count := int(countVariant.Val)
	_ = countVariant.Clear()

	ids := make([]string, 0, count)
	for i := 0; i < count; i++ {
		kbVariant, err := oleutil.GetProperty(kbArticleIDs, "Item", i)
		if err != nil {
			return nil, fmt.Errorf("read KB article ID %d: %w", i, err)
		}
		// The collection holds strings; Val would be the BSTR pointer.
		raw, ok := kbVariant.Value().(string)
		_ = kbVariant.Clear()
		if !ok {
			return nil, fmt.Errorf("KB article ID %d is not a string", i)
		}
		ids = append(ids, kbArticleID(raw))
	}
	return ids, nil
}

// PatchModule.Set hands its logger to a manager with this method.
var _ interface{ SetLogger(logging.Logger) } = (*WindowsUpdateManager)(nil)

// SetLogger sets the logger that patch filter decisions are reported to.
func (w *WindowsUpdateManager) SetLogger(logger logging.Logger) {
	w.logger = logger
}

// log returns the configured logger, or a no-op logger when none is set.
func (w *WindowsUpdateManager) log() logging.Logger {
	if w.logger == nil {
		return logging.NewNoopLogger()
	}
	return w.logger
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
