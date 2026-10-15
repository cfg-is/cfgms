// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fleetstorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestDirectoryDNAIntegration tests the complete DirectoryDNA system integration
func TestDirectoryDNAIntegration(t *testing.T) {
	// Set up real components (following CFGMS testing patterns)
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()

	// Create collector
	collector := NewDirectoryDNACollector(provider, logger)

	// Create drift detector
	driftDetector := NewDirectoryDriftDetector(logger)

	// Create storage using real backend, compressor and indexer implementations
	storage := newDirectoryStorageAdapter(t)

	// Create monitoring system
	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	t.Run("complete collection and storage workflow", func(t *testing.T) {
		// Step 1: Set up directory objects
		user := createTestUser("user1", "TestUser")
		group := createTestGroup("group1", "TestGroup")
		ou := createTestOU("ou1", "TestOU", "")

		provider.AddUser(user)
		provider.AddGroup(group)
		provider.AddOU(ou)

		// Step 2: Collect DNA for all objects
		userDNA, err := collector.CollectUserDNA(ctx, "user1")
		require.NoError(t, err)
		assert.NotNil(t, userDNA)

		groupDNA, err := collector.CollectGroupDNA(ctx, "group1")
		require.NoError(t, err)
		assert.NotNil(t, groupDNA)

		ouDNA, err := collector.CollectOUDNA(ctx, "ou1")
		require.NoError(t, err)
		assert.NotNil(t, ouDNA)

		// Step 3: Store DNA records
		err = storage.StoreDirectoryDNA(ctx, userDNA)
		require.NoError(t, err)

		err = storage.StoreDirectoryDNA(ctx, groupDNA)
		require.NoError(t, err)

		err = storage.StoreDirectoryDNA(ctx, ouDNA)
		require.NoError(t, err)

		// Step 4: Retrieve stored DNA
		retrievedUserDNA, err := storage.GetDirectoryDNA(ctx, "user1", interfaces.DirectoryObjectTypeUser)
		require.NoError(t, err)
		assert.Equal(t, "user1", retrievedUserDNA.ObjectID)

		retrievedGroupDNA, err := storage.GetDirectoryDNA(ctx, "group1", interfaces.DirectoryObjectTypeGroup)
		require.NoError(t, err)
		assert.Equal(t, "group1", retrievedGroupDNA.ObjectID)

		retrievedOUDNA, err := storage.GetDirectoryDNA(ctx, "ou1", interfaces.DirectoryObjectTypeOU)
		require.NoError(t, err)
		assert.Equal(t, "ou1", retrievedOUDNA.ObjectID)

		// Step 5: Verify statistics
		stats, err := storage.GetDirectoryStats(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, stats.TotalObjects, int64(3))
	})

	t.Run("drift detection workflow", func(t *testing.T) {
		// Step 1: Create baseline DNA
		baseline := &DirectoryDNA{
			ObjectID:   "user2",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user2_baseline",
			Attributes: map[string]string{
				"username":   "user2",
				"email":      "user2@test.com",
				"department": "IT",
				"is_active":  "true",
			},
			Provider:       "TestProvider",
			LastUpdated:    timePtr(time.Now().Add(-1 * time.Hour)),
			AttributeCount: 4,
		}

		// Step 2: Store baseline
		err := storage.StoreDirectoryDNA(ctx, baseline)
		require.NoError(t, err)

		// Step 3: Create current state with changes
		current := &DirectoryDNA{
			ObjectID:   "user2",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user2_current",
			Attributes: map[string]string{
				"username":   "user2",
				"email":      "newemail@test.com", // Changed
				"department": "Engineering",       // Changed
				"is_active":  "true",
			},
			Provider:       "TestProvider",
			LastUpdated:    timePtr(time.Now()),
			AttributeCount: 4,
		}

		// Step 4: Detect drift
		drift, err := driftDetector.DetectDrift(ctx, current, baseline)
		require.NoError(t, err)
		assert.NotNil(t, drift)

		// Step 5: Verify drift details
		assert.Equal(t, "user2", drift.ObjectID)
		assert.Len(t, drift.Changes, 2) // email and department changed
		assert.Greater(t, drift.RiskScore, float64(0))

		// Step 6: Store current state
		err = storage.StoreDirectoryDNA(ctx, current)
		require.NoError(t, err)

		// Step 7: Verify history
		history, err := storage.GetDirectoryHistory(ctx, "user2", nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(history), 2) // Should have baseline and current
	})

	t.Run("relationship collection and storage", func(t *testing.T) {
		// Step 1: Set up complex relationships
		manager := createTestUser("manager1", "Manager")
		employee := createTestUser("employee1", "Employee")
		employee.Manager = "manager1"
		employee.OU = "ou1"

		group := createTestGroup("team1", "TeamGroup")
		group.OU = "ou1"

		ou := createTestOU("ou1", "TeamOU", "")

		provider.AddUser(manager)
		provider.AddUser(employee)
		provider.AddGroup(group)
		provider.AddOU(ou)

		// Step 2: Collect relationships
		relationships, err := collector.CollectRelationships(ctx, "employee1")
		require.NoError(t, err)
		assert.NotNil(t, relationships)

		// Step 3: Store relationships
		err = storage.StoreRelationships(ctx, relationships)
		require.NoError(t, err)

		// Step 4: Retrieve relationships
		retrieved, err := storage.GetRelationships(ctx, "employee1")
		require.NoError(t, err)
		assert.Equal(t, "manager1", retrieved.Manager)
		assert.Equal(t, "ou1", retrieved.ParentOU)

		// Step 5: Collect hierarchy
		hierarchy, err := collector.CollectOUHierarchy(ctx)
		require.NoError(t, err)
		assert.NotNil(t, hierarchy)
		assert.Greater(t, hierarchy.TotalOUs, 0)
	})

	t.Run("monitoring system integration", func(t *testing.T) {
		// Use shorter intervals for testing
		config := &MonitoringConfig{
			CollectionInterval:  100 * time.Millisecond,
			DriftCheckInterval:  100 * time.Millisecond,
			HealthCheckInterval: 50 * time.Millisecond,
			MonitoredObjectTypes: []interfaces.DirectoryObjectType{
				interfaces.DirectoryObjectTypeUser,
				interfaces.DirectoryObjectTypeGroup,
			},
			AlertOnDriftSeverity:     DriftSeverityMedium,
			AlertOnHealthIssues:      true,
			MaxConcurrentCollections: 5,
			MaxConcurrentDriftChecks: 10,
			CollectionTimeout:        30 * time.Second,
			MetricsRetention:         time.Hour,
			HealthDataRetention:      time.Hour,
		}

		err := monitoring.UpdateConfig(config)
		require.NoError(t, err)

		// Start monitoring system
		err = monitoring.Start(ctx)
		require.NoError(t, err)

		// Allow monitoring to perform several cycles
		time.Sleep(300 * time.Millisecond)

		// Verify monitoring is working
		assert.True(t, monitoring.IsRunning())

		metrics := monitoring.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.TotalCollections, int64(0))

		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)
		assert.NotEmpty(t, status.ComponentStatuses)

		// Stop monitoring
		err = monitoring.Stop()
		require.NoError(t, err)
		assert.False(t, monitoring.IsRunning())
	})
}

func TestEndToEndDriftScenario(t *testing.T) {
	// Set up complete system
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)

	storage := newDirectoryStorageAdapter(t)

	_ = NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	// Scenario: User account compromise detection
	t.Run("user account compromise detection", func(t *testing.T) {
		// Step 1: Establish baseline
		user := createTestUser("critical_user", "CriticalUser")
		user.ProviderAttributes["security_clearance"] = "high"
		user.ProviderAttributes["privileged_access"] = "true"
		provider.AddUser(user)

		baselineDNA, err := collector.CollectUserDNA(ctx, "critical_user")
		require.NoError(t, err)

		err = storage.StoreDirectoryDNA(ctx, baselineDNA)
		require.NoError(t, err)

		// Step 2: Simulate compromise (account disabled, email changed)
		compromisedUser := *user
		compromisedUser.AccountEnabled = false
		compromisedUser.EmailAddress = "hacker@malicious.com"

		// Deep copy the ProviderAttributes map to avoid race conditions
		compromisedUser.ProviderAttributes = make(map[string]interface{})
		for k, v := range user.ProviderAttributes {
			compromisedUser.ProviderAttributes[k] = v
		}
		compromisedUser.ProviderAttributes["last_login"] = "suspicious_location"

		// Update the user data in a thread-safe way
		provider.mutex.Lock()
		provider.users["critical_user"] = &compromisedUser
		provider.mutex.Unlock()

		currentDNA, err := collector.CollectUserDNA(ctx, "critical_user")
		require.NoError(t, err)

		// Step 3: Detect drift
		drift, err := driftDetector.DetectDrift(ctx, currentDNA, baselineDNA)
		require.NoError(t, err)
		assert.NotNil(t, drift)

		// Step 4: Verify security assessment
		assert.Greater(t, drift.RiskScore, float64(70)) // High risk for account compromise
		assert.Contains(t, []DriftSeverity{DriftSeverityHigh, DriftSeverityCritical}, drift.Severity)

		// Verify critical changes are detected
		changeFields := make(map[string]bool)
		for _, change := range drift.Changes {
			changeFields[change.Field] = true
		}
		assert.True(t, changeFields["account_enabled"])
		assert.True(t, changeFields["email_address"])

		// Step 5: Verify suggested actions for security incident
		assert.NotEmpty(t, drift.SuggestedActions)
		assert.False(t, drift.AutoRemediable) // High-risk security changes should not be auto-remediable

		// Step 6: Store compromised state for audit trail
		err = storage.StoreDirectoryDNA(ctx, currentDNA)
		require.NoError(t, err)

		// Step 7: Verify audit trail
		history, err := storage.GetDirectoryHistory(ctx, "critical_user", nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(history), 2)
	})
}

// durationPercentile returns the p-th percentile (0..1) of durations. The
// scalability check logs the median (p=0.5) of each half's batch costs.
func durationPercentile(durations []time.Duration, p float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

// writeBatchSize is the number of writes timed as one sample. Timing a batch
// instead of a single write keeps each sample far above the clock tick: CI's
// Windows runners have been observed with ~15.6ms timer granularity, where a
// single fast write reads exactly 0s (Issue #4931).
const writeBatchSize = 50

// maxWriteGrowth bounds how much more a write may cost late in a run than its
// control (see measureWriteGrowth). Without growth the measured ratio is
// 1.1-1.25 under -race and 1.3-1.8 without it on a Windows host.
const maxWriteGrowth = 8

// writeGrowth holds per-batch write costs from measureWriteGrowth.
type writeGrowth struct {
	storedCount int
	// main[k] and control[k] are the per-write cost of the k-th main batch and
	// of the control batch timed right after it.
	main    []time.Duration
	control []time.Duration
}

// measureWriteGrowth writes items through store in batches of writeBatchSize.
// Right after each batch it writes a control batch of the same size into a
// fresh store from newControl, so the control always runs at the same small
// dataset size while the main store grows.
//
// The property under test is that the cost of a single write does not grow as
// the dataset grows: a per-write cost that climbs with table size (an
// unindexed version lookup, a full-table dedup scan) is the scalability
// regression this test exists to catch. Wall-clock time cannot show it on its
// own. This package runs inside `go test -race ./...`, where package binaries
// compete for the machine, and a shared CI runner can slow down for a whole
// phase of a run. On 2026-10-14 a native Windows runner wrote the first half of
// the dataset at a median of 3.3ms per write and the second half at 26.8ms. The
// same test on a quiet Windows host measures 3.1ms and 3.3ms, and doubling the
// dataset leaves the per-write cost unchanged, so that whole second half ran
// slower, not each write growing with n (Issue #5001). The control batch is
// timed in the same phase as the main batch next to it, so a slowdown inflates
// both and cancels out of their ratio, while growth with n raises only the main
// store's cost.
func measureWriteGrowth(t *testing.T, store *DirectoryDNAStorageAdapter, newControl func() *DirectoryDNAStorageAdapter, items []*DirectoryDNA) writeGrowth {
	t.Helper()
	ctx := context.Background()
	controlItems := items[:min(writeBatchSize, len(items))]

	// timeBatch returns the per-write cost of the successful writes, or 0 when
	// none succeeded.
	timeBatch := func(s *DirectoryDNAStorageAdapter, batch []*DirectoryDNA) (time.Duration, int) {
		ok := 0
		start := time.Now()
		for _, dna := range batch {
			if err := s.StoreDirectoryDNA(ctx, dna); err == nil {
				ok++
			}
		}
		elapsed := time.Since(start)
		if ok == 0 {
			return 0, 0
		}
		return elapsed / time.Duration(ok), ok
	}

	var g writeGrowth
	for i := 0; i < len(items); i += writeBatchSize {
		mainCost, ok := timeBatch(store, items[i:min(i+writeBatchSize, len(items))])
		g.storedCount += ok
		control := newControl()
		controlCost, _ := timeBatch(control, controlItems)
		if mainCost > 0 && controlCost > 0 {
			g.main = append(g.main, mainCost)
			g.control = append(g.control, controlCost)
		}
	}
	return g
}

// ratios returns main/control for each batch.
func (g writeGrowth) ratios() []float64 {
	r := make([]float64, len(g.main))
	for k := range g.main {
		r[k] = float64(g.main[k]) / float64(g.control[k])
	}
	return r
}

func medianFloat(v []float64) float64 {
	sorted := append([]float64(nil), v...)
	sort.Float64s(sorted)
	return sorted[(len(sorted)-1)/2]
}

// check fails when writes late in the run cost more than maxWriteGrowth times
// their control, or grew more than maxWriteGrowth times relative to the early
// half of the run. Medians are used, so a few outlier batches (a disk stall, a
// GC pause, a slowdown that starts between a batch and its control) cannot trip
// it; a per-write cost that depends on n shifts every late batch.
func (g writeGrowth) check() error {
	if len(g.main) < 4 {
		return fmt.Errorf("only %d timed batches; need at least 4", len(g.main))
	}
	r := g.ratios()
	half := len(r) / 2
	early, late := medianFloat(r[:half]), medianFloat(r[half:])
	if late >= maxWriteGrowth {
		return fmt.Errorf("late writes cost %.1fx a write at fixed dataset size (bound %dx)", late, maxWriteGrowth)
	}
	if late >= maxWriteGrowth*early {
		return fmt.Errorf("late/control ratio %.2f is %.1fx the early ratio %.2f (bound %dx)", late, late/early, early, maxWriteGrowth)
	}
	return nil
}

func (g writeGrowth) log(t *testing.T, label string) {
	t.Helper()
	if len(g.main) < 2 {
		return
	}
	r := g.ratios()
	half := len(r) / 2
	t.Logf("[%s] early: main median=%v control median=%v ratio median=%.2f (batches=%d)",
		label, durationPercentile(g.main[:half], 0.5), durationPercentile(g.control[:half], 0.5), medianFloat(r[:half]), half)
	t.Logf("[%s] late:  main median=%v control median=%v ratio median=%.2f (batches=%d)",
		label, durationPercentile(g.main[half:], 0.5), durationPercentile(g.control[half:], 0.5), medianFloat(r[half:]), len(r)-half)
}

// runLargeOrganizationSimulation exercises the scalability scenario at a given
// multiple of the baseline organization size (scale=1 is the original
// 1000 users / 100 groups / 50 OUs; scale=2 doubles every count). Running it
// at two sizes lets the per-write timings reported via t.Logf show whether
// the per-write cost bound is a property of the write path (stays flat as
// scale changes) or an artifact of one specific dataset size.
func runLargeOrganizationSimulation(t *testing.T, scale int) {
	t.Helper()

	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	storage := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	// Create a simulated large organization
	numUsers := 1000 * scale
	numGroups := 100 * scale
	numOUs := 50 * scale

	// Add users
	for i := 0; i < numUsers; i++ {
		userID := fmt.Sprintf("user%04d", i)
		user := createTestUser(userID, "User"+userID)
		user.OU = fmt.Sprintf("ou%02d", i%numOUs)
		provider.AddUser(user)
	}

	// Add groups
	for i := 0; i < numGroups; i++ {
		groupID := fmt.Sprintf("group%03d", i)
		group := createTestGroup(groupID, "Group"+groupID)
		group.OU = fmt.Sprintf("ou%02d", i%numOUs)
		provider.AddGroup(group)
	}

	// Add OUs
	for i := 0; i < numOUs; i++ {
		ouID := fmt.Sprintf("ou%02d", i)
		ou := createTestOU(ouID, "OU"+ouID, "")
		provider.AddOU(ou)
	}

	// Test bulk collection performance
	start := time.Now()
	allDNA, err := collector.CollectAll(ctx)
	collectionDuration := time.Since(start)

	require.NoError(t, err)
	assert.Len(t, allDNA, numUsers+numGroups+numOUs)

	// Should complete within reasonable time
	assert.Less(t, collectionDuration, 30*time.Second, "Collection took too long for large dataset")

	// Test storage scaling: the cost of a single write must not grow with the
	// number of objects already stored (see measureWriteGrowth).
	growth := measureWriteGrowth(t, storage, func() *DirectoryDNAStorageAdapter { return newDirectoryStorageAdapter(t) }, allDNA)

	assert.Greater(t, growth.storedCount, numUsers+numGroups+numOUs-10) // Allow for some errors
	growth.log(t, fmt.Sprintf("scale=%dx, n=%d", scale, len(allDNA)))
	assert.NoError(t, growth.check(), "per-write cost grew with dataset size")

	// Test query performance
	start = time.Now()
	query := &DirectoryDNAQuery{
		ObjectTypes: []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
		Limit:       100,
	}
	results, err := storage.QueryDirectoryDNA(ctx, query)
	queryDuration := time.Since(start)

	require.NoError(t, err)
	assert.LessOrEqual(t, len(results), 100)
	assert.Less(t, queryDuration, 5*time.Second, "Query took too long")
}

func TestScalabilityScenario(t *testing.T) {
	// Test system behavior with larger datasets
	t.Run("large organization simulation", func(t *testing.T) {
		runLargeOrganizationSimulation(t, 1)
	})

	// Issue #4239 AC1: the same scenario at 2x the dataset size, to confirm
	// the per-write cost bound holds independent of dataset size rather than
	// being tuned to one specific n.
	t.Run("large organization simulation 2x", func(t *testing.T) {
		runLargeOrganizationSimulation(t, 2)
	})
}

// scanningBackend reads back every record stored so far before each write: a
// real O(n) scan on the real SQLite backend, the shape of a dedup-by-scan
// regression in the write path.
type scanningBackend struct {
	fleetstorage.Backend
	stored []fleetstorage.DNARecord
}

func (b *scanningBackend) scan(ctx context.Context) error {
	for _, r := range b.stored {
		if _, err := b.GetRecord(ctx, r.ContentHash, r.ShardID); err != nil {
			return err
		}
	}
	return nil
}

func (b *scanningBackend) StoreRecord(ctx context.Context, record *fleetstorage.DNARecord, data []byte) error {
	if err := b.scan(ctx); err != nil {
		return err
	}
	if err := b.Backend.StoreRecord(ctx, record, data); err != nil {
		return err
	}
	b.stored = append(b.stored, fleetstorage.DNARecord{ContentHash: record.ContentHash, ShardID: record.ShardID})
	return nil
}

func (b *scanningBackend) StoreReference(ctx context.Context, record *fleetstorage.DNARecord) error {
	if err := b.scan(ctx); err != nil {
		return err
	}
	return b.Backend.StoreReference(ctx, record)
}

// organizationDNA collects DNA for a synthetic organization of n users.
func organizationDNA(t *testing.T, n int) []*DirectoryDNA {
	t.Helper()
	provider := NewMockDirectoryProvider()
	for i := 0; i < n; i++ {
		userID := fmt.Sprintf("user%04d", i)
		provider.AddUser(createTestUser(userID, "User"+userID))
	}
	allDNA, err := NewDirectoryDNACollector(provider, logging.NewNoopLogger()).CollectAll(context.Background())
	require.NoError(t, err)
	require.Len(t, allDNA, n)
	return allDNA
}

// TestWriteGrowthCheck_DetectsPerWriteScan proves the scalability check fails a
// write path that does O(n) work per write, on whatever machine runs it.
func TestWriteGrowthCheck_DetectsPerWriteScan(t *testing.T) {
	st := newDirectoryStorage(t)
	store := NewDirectoryDNAStorageAdapter(&scanningBackend{Backend: st.backend}, st.compressor, st.indexer, st.logger)
	g := measureWriteGrowth(t, store, func() *DirectoryDNAStorageAdapter { return newDirectoryStorageAdapter(t) }, organizationDNA(t, 400))
	g.log(t, "O(n) scan per write")
	assert.Error(t, g.check(), "a write path that scans every stored record must fail the growth check")
}

// TestWriteGrowthCheck_IgnoresUniformSlowdown feeds the check timings in which
// the whole second half of the run is 8x slower, as observed on a CI runner on
// 2026-10-14, and timings in which per-write cost grows with n.
func TestWriteGrowthCheck_IgnoresUniformSlowdown(t *testing.T) {
	const batches = 24
	ms := func(f float64) time.Duration { return time.Duration(f * float64(time.Millisecond)) }

	var slow writeGrowth
	for k := 0; k < batches; k++ {
		factor := 1.0
		if k >= batches/2 {
			factor = 8
		}
		slow.main = append(slow.main, ms(3.3*factor))
		slow.control = append(slow.control, ms(3.1*factor))
	}
	assert.NoError(t, slow.check(), "a uniformly slower phase is not growth with n")

	var linear writeGrowth
	for k := 0; k < batches; k++ {
		n := float64((k + 1) * writeBatchSize)
		linear.main = append(linear.main, ms(3+0.03*n)) // 30us of work per stored object
		linear.control = append(linear.control, ms(3))
	}
	assert.Error(t, linear.check(), "per-write cost proportional to n must fail")

	var flat writeGrowth
	for k := 0; k < batches; k++ {
		flat.main = append(flat.main, ms(3.3))
		flat.control = append(flat.control, ms(3.1))
	}
	assert.NoError(t, flat.check())

	assert.Error(t, writeGrowth{main: flat.main[:3], control: flat.control[:3]}.check(), "too few batches to judge")
}

func TestMultiTenantScenario(t *testing.T) {
	// Test multi-tenant directory DNA collection
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()

	ctx := context.Background()

	t.Run("multi-tenant collection", func(t *testing.T) {
		// Create collectors for different tenants
		tenant1Config := &CollectorConfig{
			TenantID:          "tenant1",
			BatchSize:         100,
			CollectionTimeout: 30 * time.Second,
			MaxConcurrency:    5,
		}

		tenant2Config := &CollectorConfig{
			TenantID:          "tenant2",
			BatchSize:         100,
			CollectionTimeout: 30 * time.Second,
			MaxConcurrency:    5,
		}

		collector1 := NewDirectoryDNACollectorWithConfig(provider, logger, tenant1Config)
		collector2 := NewDirectoryDNACollectorWithConfig(provider, logger, tenant2Config)

		// Add tenant-specific users
		user1 := createTestUser("tenant1_user", "Tenant1User")
		user2 := createTestUser("tenant2_user", "Tenant2User")
		provider.AddUser(user1)
		provider.AddUser(user2)

		// Collect DNA for each tenant
		dna1, err := collector1.CollectUserDNA(ctx, "tenant1_user")
		require.NoError(t, err)
		assert.Equal(t, "tenant1", dna1.TenantID)

		dna2, err := collector2.CollectUserDNA(ctx, "tenant2_user")
		require.NoError(t, err)
		assert.Equal(t, "tenant2", dna2.TenantID)

		// Verify tenant isolation
		assert.NotEqual(t, dna1.TenantID, dna2.TenantID)
	})
}

func TestErrorRecoveryScenario(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("recovery from storage errors", func(t *testing.T) {
		// Add test data
		provider.AddUser(createTestUser("user1", "User1"))

		// Configure for fast testing
		config := &MonitoringConfig{
			CollectionInterval:       50 * time.Millisecond,
			DriftCheckInterval:       50 * time.Millisecond,
			HealthCheckInterval:      25 * time.Millisecond,
			MonitoredObjectTypes:     []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
			AlertOnDriftSeverity:     DriftSeverityMedium,
			AlertOnHealthIssues:      true,
			MaxConcurrentCollections: 5,
			MaxConcurrentDriftChecks: 10,
			CollectionTimeout:        30 * time.Second,
			MetricsRetention:         time.Hour,
			HealthDataRetention:      time.Hour,
		}

		err := monitoring.UpdateConfig(config)
		require.NoError(t, err)

		// Start monitoring
		err = monitoring.Start(ctx)
		require.NoError(t, err)

		// Allow initial successful operations
		time.Sleep(100 * time.Millisecond)

		// Introduce storage errors
		storage.SetShouldError(true)

		// Allow system to experience errors
		time.Sleep(150 * time.Millisecond)

		// Verify system continues running despite errors
		assert.True(t, monitoring.IsRunning())

		// Check health status reflects errors
		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)

		// Recovery: fix storage errors
		storage.SetShouldError(false)

		// Allow system to recover
		time.Sleep(150 * time.Millisecond)

		// Verify recovery
		finalStatus := monitoring.GetHealthStatus()
		assert.NotNil(t, finalStatus)

		err = monitoring.Stop()
		require.NoError(t, err)
	})
}

func TestRealWorldDriftPatterns(t *testing.T) {
	// Test realistic drift detection scenarios
	logger := logging.NewNoopLogger()
	driftDetector := NewDirectoryDriftDetector(logger)

	ctx := context.Background()

	testCases := []struct {
		name               string
		baselineAttributes map[string]string
		currentAttributes  map[string]string
		expectedSeverity   DriftSeverity
		expectedMinRisk    float64
		expectedDriftType  DirectoryDriftType
	}{
		{
			name: "user promotion",
			baselineAttributes: map[string]string{
				"title":      "Developer",
				"department": "Engineering",
				"level":      "L3",
			},
			currentAttributes: map[string]string{
				"title":      "Senior Developer",
				"department": "Engineering",
				"level":      "L4",
			},
			expectedSeverity:  DriftSeverityLow,
			expectedMinRisk:   0.0,
			expectedDriftType: DirectoryDriftTypeAttributeChange,
		},
		{
			name: "security group addition",
			baselineAttributes: map[string]string{
				"groups": "users,developers",
				"access": "standard",
			},
			currentAttributes: map[string]string{
				"groups": "users,developers,admins",
				"access": "elevated",
			},
			expectedSeverity:  DriftSeverityHigh,
			expectedMinRisk:   60.0,
			expectedDriftType: DirectoryDriftTypePermissionEscalation,
		},
		{
			name: "account compromise indicators",
			baselineAttributes: map[string]string{
				"is_active":     "true",
				"email":         "user@company.com",
				"last_login":    "internal_network",
				"failed_logins": "0",
			},
			currentAttributes: map[string]string{
				"is_active":     "true",
				"email":         "user@suspicious.com",
				"last_login":    "unknown_location",
				"failed_logins": "15",
			},
			expectedSeverity:  DriftSeverityCritical,
			expectedMinRisk:   80.0,
			expectedDriftType: DirectoryDriftTypeUnauthorizedChange,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := &DirectoryDNA{
				ObjectID:       "test_user",
				ObjectType:     interfaces.DirectoryObjectTypeUser,
				ID:             "baseline",
				Attributes:     tc.baselineAttributes,
				Provider:       "TestProvider",
				LastUpdated:    timePtr(time.Now().Add(-1 * time.Hour)),
				AttributeCount: int32(len(tc.baselineAttributes)),
			}

			current := &DirectoryDNA{
				ObjectID:       "test_user",
				ObjectType:     interfaces.DirectoryObjectTypeUser,
				ID:             "current",
				Attributes:     tc.currentAttributes,
				Provider:       "TestProvider",
				LastUpdated:    timePtr(time.Now()),
				AttributeCount: int32(len(tc.currentAttributes)),
			}

			drift, err := driftDetector.DetectDrift(ctx, current, baseline)

			require.NoError(t, err)
			assert.NotNil(t, drift)
			assert.Equal(t, tc.expectedSeverity, drift.Severity)
			assert.GreaterOrEqual(t, drift.RiskScore, tc.expectedMinRisk)
			assert.Equal(t, tc.expectedDriftType, drift.DriftType)

			// Verify drift has actionable information
			assert.NotEmpty(t, drift.Description)
			assert.NotEmpty(t, drift.SuggestedActions)
			assert.Greater(t, len(drift.Changes), 0)
		})
	}
}

func TestSystemResourceUsage(t *testing.T) {
	// Test that the system doesn't consume excessive resources
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	// Add moderate dataset
	for i := 0; i < 100; i++ {
		userID := "user" + string(rune('0'+(i%10))) + string(rune('0'+(i/10)))
		provider.AddUser(createTestUser(userID, "User"+userID))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use reasonable intervals
	config := &MonitoringConfig{
		CollectionInterval:       1 * time.Second,
		DriftCheckInterval:       1 * time.Second,
		HealthCheckInterval:      500 * time.Millisecond,
		MonitoredObjectTypes:     []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
		AlertOnDriftSeverity:     DriftSeverityMedium,
		AlertOnHealthIssues:      true,
		MaxConcurrentCollections: 10,
		MaxConcurrentDriftChecks: 20,
		CollectionTimeout:        30 * time.Second,
		MetricsRetention:         time.Hour,
		HealthDataRetention:      time.Hour,
	}

	err := monitoring.UpdateConfig(config)
	require.NoError(t, err)

	// Start monitoring and let it run
	err = monitoring.Start(ctx)
	require.NoError(t, err)

	// Monitor for a reasonable time
	time.Sleep(3 * time.Second)

	// Check that system is performing well
	metrics := monitoring.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Greater(t, metrics.TotalCollections, int64(0))

	status := monitoring.GetHealthStatus()
	assert.NotNil(t, status)

	// Verify system health under load
	if status.CollectorHealth != nil {
		assert.LessOrEqual(t, status.CollectorHealth.ErrorRate, 0.1) // Less than 10% error rate
	}

	err = monitoring.Stop()
	require.NoError(t, err)
}

func TestComprehensiveWorkflow(t *testing.T) {
	// Test a complete workflow from setup to drift detection
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)

	storage := newDirectoryStorageAdapter(t)

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	// Phase 1: Initial setup and baseline collection
	user := createTestUser("workflow_user", "WorkflowUser")
	group := createTestGroup("workflow_group", "WorkflowGroup")
	ou := createTestOU("workflow_ou", "WorkflowOU", "")

	provider.AddUser(user)
	provider.AddGroup(group)
	provider.AddOU(ou)

	// Collect initial DNA
	userDNA, err := collector.CollectUserDNA(ctx, "workflow_user")
	require.NoError(t, err)

	relationships, err := collector.CollectRelationships(ctx, "workflow_user")
	require.NoError(t, err)

	// Store baseline
	err = storage.StoreDirectoryDNA(ctx, userDNA)
	require.NoError(t, err)

	err = storage.StoreRelationships(ctx, relationships)
	require.NoError(t, err)

	// Phase 2: Start monitoring
	config := &MonitoringConfig{
		CollectionInterval:       200 * time.Millisecond,
		DriftCheckInterval:       200 * time.Millisecond,
		HealthCheckInterval:      100 * time.Millisecond,
		MonitoredObjectTypes:     []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
		AlertOnDriftSeverity:     DriftSeverityMedium,
		AlertOnHealthIssues:      true,
		MaxConcurrentCollections: 5,
		MaxConcurrentDriftChecks: 10,
		CollectionTimeout:        30 * time.Second,
		MetricsRetention:         time.Hour,
		HealthDataRetention:      time.Hour,
	}

	err = monitoring.UpdateConfig(config)
	require.NoError(t, err)

	err = monitoring.Start(ctx)
	require.NoError(t, err)

	// Phase 3: Wait for the monitoring loop to complete its first collection
	// cycle. The counters are driven by background tickers, so wait on the
	// observable state rather than a fixed sleep that races scheduler load.
	require.Eventually(t, func() bool {
		return monitoring.GetMetrics().TotalCollections > 0
	}, 10*time.Second, 10*time.Millisecond, "monitoring loop never completed a DNA collection cycle")

	// Phase 4: Introduce changes
	modifiedUser := *user
	modifiedUser.EmailAddress = "modified@test.com"

	// Deep copy the ProviderAttributes map to avoid race conditions
	modifiedUser.ProviderAttributes = make(map[string]interface{})
	for k, v := range user.ProviderAttributes {
		modifiedUser.ProviderAttributes[k] = v
	}
	modifiedUser.ProviderAttributes["title"] = "Senior Developer"

	// Update the user data in a thread-safe way
	provider.mutex.Lock()
	provider.users["workflow_user"] = &modifiedUser
	provider.mutex.Unlock()

	// Wait for the monitoring loop to run a drift check cycle after the change.
	driftChecksBefore := monitoring.GetMetrics().TotalDriftChecks
	require.Eventually(t, func() bool {
		return monitoring.GetMetrics().TotalDriftChecks > driftChecksBefore
	}, 10*time.Second, 10*time.Millisecond, "monitoring loop never ran a drift check cycle")

	// Phase 5: Verify system detected changes
	currentDNA, err := collector.CollectUserDNA(ctx, "workflow_user")
	require.NoError(t, err)

	drift, err := driftDetector.DetectDrift(ctx, currentDNA, userDNA)
	require.NoError(t, err)
	assert.Greater(t, len(drift.Changes), 0)

	// Phase 6: Verify monitoring metrics
	metrics := monitoring.GetMetrics()
	assert.Greater(t, metrics.TotalCollections, int64(0))
	assert.Greater(t, metrics.TotalDriftChecks, int64(0))

	status := monitoring.GetHealthStatus()
	assert.NotNil(t, status)

	// Phase 7: Clean shutdown
	err = monitoring.Stop()
	require.NoError(t, err)
	assert.False(t, monitoring.IsRunning())

	// Verify final statistics
	finalStats := collector.GetCollectionStats()
	assert.Greater(t, finalStats.TotalCollections, int64(0))

	driftStats := driftDetector.GetDriftDetectionStats()
	assert.Greater(t, driftStats.TotalComparisons, int64(0))
}
