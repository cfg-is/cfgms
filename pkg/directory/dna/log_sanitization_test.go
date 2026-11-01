// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Log-injection regression tests for storage.go, relationships.go and
// monitoring.go (Issue #4341). Each test forces an error containing CR/LF
// through a real code path that logs it, and asserts the field reaching the
// captured log record carries no raw \r or \n — proving the call site wraps
// the value with logging.SanitizeLogValue instead of passing it through
// verbatim.
//
// logging.CapturingLogger (pkg/logging/capturing.go) is used rather than a
// mock: it is a real, shipped implementation of the logging.Logger interface
// that records exactly what a call site passes, without performing any
// sanitization of its own — the DefaultLogger/ModuleLogger sinks used in
// production already scrub control characters from every field, so testing
// through them would pass regardless of whether the call site sanitizes.
// CapturingLogger isolates the call-site behavior under test.
package dna

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	fleetstorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// crlfError is a real error type (not a mock) carrying attacker-controlled
// CR/LF content, simulating a message that a backend/provider error might
// carry back from tainted input (e.g. an entity ID or directory attribute).
const crlfPayload = "injected\r\nWARN forged log line"

// --- storage.go ---

// fakeIndexingFailureBackend is a minimal real implementation of
// fleetstorage.Backend that succeeds through StoreRecord/HasContent so
// StoreDirectoryDNA reaches the indexing step.
type fakeIndexingFailureBackend struct {
	fleetstorage.Backend // nil embedded interface: unused methods are not called by this test
}

func (f *fakeIndexingFailureBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	return false, nil
}

func (f *fakeIndexingFailureBackend) StoreRecord(ctx context.Context, record *fleetstorage.DNARecord, compressedData []byte) error {
	return nil
}

type fakePassthroughCompressor struct {
	fleetstorage.Compressor
}

func (f *fakePassthroughCompressor) Compress(dna *commonpb.DNA) ([]byte, int64, error) {
	return []byte("compressed"), 100, nil
}

// fakeFailingIndexer returns a next version successfully but fails
// IndexRecord with a CRLF-laced error, exercising storage.go's
// "Failed to index directory DNA record" Warn call.
type fakeFailingIndexer struct {
	fleetstorage.Indexer
}

func (f *fakeFailingIndexer) GetNextVersion(ctx context.Context, deviceID string) (int64, error) {
	return 1, nil
}

func (f *fakeFailingIndexer) IndexRecord(ctx context.Context, record *fleetstorage.DNARecord) error {
	return errors.New("index write failed: " + crlfPayload)
}

func TestStoreDirectoryDNA_LogsSanitizedErrorOnIndexFailure(t *testing.T) {
	logger := logging.NewCapturingLogger()
	adapter := NewDirectoryDNAStorageAdapter(
		&fakeIndexingFailureBackend{},
		&fakePassthroughCompressor{},
		&fakeFailingIndexer{},
		logger,
	)

	dna := &DirectoryDNA{
		ID:         "dna-1",
		ObjectID:   "user-1" + crlfPayload,
		ObjectType: interfaces.DirectoryObjectTypeUser,
	}

	// StoreDirectoryDNA tolerates indexing failures (storage already
	// succeeded), so it must return nil while still logging the failure.
	err := adapter.StoreDirectoryDNA(context.Background(), dna)
	require.NoError(t, err)

	entry, found := logger.FindWarn("Failed to index directory DNA record")
	require.True(t, found, "expected a Warn call for the indexing failure")

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r")
	assert.NotContains(t, errVal, "\n")

	objectIDVal, ok := entry["object_id"].(string)
	require.True(t, ok, "object_id field must be a sanitized string")
	assert.NotContains(t, objectIDVal, "\r")
	assert.NotContains(t, objectIDVal, "\n")
}

// --- relationships.go ---

// crlfProvider is a minimal real implementation of interfaces.DirectoryProvider
// (embedding the nil interface for unused methods) that fails GetGroupMembers
// with a CRLF-laced error and otherwise returns a valid group, exercising
// collectGroupRelationships' "Failed to get group members" Warn call.
type crlfProvider struct {
	interfaces.DirectoryProvider
}

func (p *crlfProvider) GetGroupMembers(ctx context.Context, groupID string) ([]interfaces.DirectoryUser, error) {
	return nil, errors.New("member lookup failed: " + crlfPayload)
}

func (p *crlfProvider) GetGroup(ctx context.Context, groupID string) (*interfaces.DirectoryGroup, error) {
	return &interfaces.DirectoryGroup{ID: groupID}, nil
}

func TestCollectGroupRelationships_LogsSanitizedErrorOnMemberFailure(t *testing.T) {
	logger := logging.NewCapturingLogger()
	collector := NewDirectoryDNACollector(&crlfProvider{}, logger)

	relationships := &DirectoryRelationships{ObjectID: "group-1"}
	err := collector.collectGroupRelationships(context.Background(), "group-1"+crlfPayload, relationships)
	require.NoError(t, err)

	entry, found := logger.FindWarn("Failed to get group members")
	require.True(t, found, "expected a Warn call for the member lookup failure")

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r")
	assert.NotContains(t, errVal, "\n")

	groupIDVal, ok := entry["group_id"].(string)
	require.True(t, ok, "group_id field must be a sanitized string")
	assert.NotContains(t, groupIDVal, "\r")
	assert.NotContains(t, groupIDVal, "\n")
}

// --- monitoring.go ---

// crlfCollector is a minimal real implementation of DirectoryDNACollector
// (embedding the nil interface for unused methods) whose bulk collection
// methods fail with a CRLF-laced error, exercising performDNACollection's
// "DNA collection failed for object type" Warn call for every monitored
// object type.
type crlfCollector struct {
	DirectoryDNACollector
}

func (c *crlfCollector) CollectAllUsers(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	return nil, errors.New("collection failed: " + crlfPayload)
}

func (c *crlfCollector) CollectAllGroups(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	return nil, errors.New("collection failed: " + crlfPayload)
}

func (c *crlfCollector) CollectAllOUs(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	return nil, errors.New("collection failed: " + crlfPayload)
}

// collectingCollector is a minimal real implementation of
// DirectoryDNACollector that succeeds, returning one DNA record per object
// type whose ObjectID carries tainted CR/LF content — so the storage loops in
// collectDNAForObjectType are reached and their store-failure Warn calls fire.
type collectingCollector struct {
	DirectoryDNACollector
}

func (c *collectingCollector) dnaFor(objectType interfaces.DirectoryObjectType) []*DirectoryDNA {
	return []*DirectoryDNA{{
		ID:         "dna-1",
		ObjectID:   "object-1" + crlfPayload,
		ObjectType: objectType,
	}}
}

func (c *collectingCollector) CollectAllUsers(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	return c.dnaFor(interfaces.DirectoryObjectTypeUser), nil
}

func (c *collectingCollector) CollectAllGroups(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	return c.dnaFor(interfaces.DirectoryObjectTypeGroup), nil
}

func (c *collectingCollector) CollectAllOUs(ctx context.Context, filters *interfaces.SearchFilters) ([]*DirectoryDNA, error) {
	return c.dnaFor(interfaces.DirectoryObjectTypeOU), nil
}

// crlfStorage is a minimal real implementation of DirectoryDNAStorage whose
// StoreDirectoryDNA fails with a CRLF-laced error, exercising the
// "Failed to store user/group/OU DNA" Warn calls in collectDNAForObjectType.
type crlfStorage struct {
	DirectoryDNAStorage
}

func (s *crlfStorage) StoreDirectoryDNA(ctx context.Context, dna *DirectoryDNA) error {
	return errors.New("store failed: " + crlfPayload)
}

// assertSanitizedWarn asserts that the named Warn call was made and that each
// of the listed fields reached the logger as a string free of raw CR/LF.
func assertSanitizedWarn(t *testing.T, logger *logging.CapturingLogger, msg string, fields ...string) {
	t.Helper()

	entry, found := logger.FindWarn(msg)
	require.True(t, found, "expected a Warn call with message %q", msg)

	for _, field := range fields {
		value, ok := entry[field].(string)
		require.True(t, ok, "%s field must be a sanitized string, not a raw value", field)
		assert.NotContains(t, value, "\r", "%s field must not carry a raw CR", field)
		assert.NotContains(t, value, "\n", "%s field must not carry a raw LF", field)
	}
}

func TestPerformDNACollection_LogsSanitizedErrorOnCollectionFailure(t *testing.T) {
	logger := logging.NewCapturingLogger()
	driftDetector := NewDirectoryDriftDetector(logger)
	monitoring := NewDirectoryDNAMonitoringSystem(&crlfCollector{}, driftDetector, &crlfStorage{}, logger)

	// performDNACollection is the sole caller of the "DNA collection failed
	// for object type" Warn; it iterates every monitored object type, each of
	// which fails here with a CRLF-laced error.
	monitoring.performDNACollection(context.Background())

	assertSanitizedWarn(t, logger, "DNA collection failed for object type", "error")

	// Every monitored object type failed, so the failure was logged once per
	// type — confirming the loop, not just the first iteration, sanitizes.
	var warnCount int
	for _, msg := range logger.WarnMessages {
		if msg == "DNA collection failed for object type" {
			warnCount++
		}
	}
	assert.Equal(t, len(monitoring.GetConfig().MonitoredObjectTypes), warnCount,
		"expected one collection-failure Warn per monitored object type")
}

func TestCollectDNAForObjectType_LogsSanitizedErrorOnStoreFailure(t *testing.T) {
	testCases := []struct {
		name       string
		objectType interfaces.DirectoryObjectType
		warnMsg    string
		idField    string
	}{
		{"user", interfaces.DirectoryObjectTypeUser, "Failed to store user DNA", "user_id"},
		{"group", interfaces.DirectoryObjectTypeGroup, "Failed to store group DNA", "group_id"},
		{"ou", interfaces.DirectoryObjectTypeOU, "Failed to store OU DNA", "ou_id"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := logging.NewCapturingLogger()
			driftDetector := NewDirectoryDriftDetector(logger)
			monitoring := NewDirectoryDNAMonitoringSystem(
				&collectingCollector{}, driftDetector, &crlfStorage{}, logger)

			// Collection succeeds, so the storage loop runs; the store then
			// fails with a CRLF-laced error against a CRLF-laced ObjectID,
			// exercising both sanitized fields of the Warn call.
			collected, err := monitoring.collectDNAForObjectType(context.Background(), tc.objectType)
			require.NoError(t, err)
			assert.Equal(t, int64(1), collected)

			assertSanitizedWarn(t, logger, tc.warnMsg, tc.idField, "error")
		})
	}
}
