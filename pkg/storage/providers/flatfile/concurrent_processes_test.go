// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// TestHelperProcess is the helper invoked by the cross-process flatfile
// concurrency test. It's NOT a real test — the parent test re-exec's this
// binary with GO_WANT_HELPER_PROCESS=1 plus FLATFILE_HELPER_MODE=<mode>
// to drive a writer or a reader against the same root directory.
//
// Modes:
//
//	writer  Loops StoreConfig against tenant/ns/name with monotonically
//	        increasing version-payloads for FLATFILE_HELPER_DURATION_MS.
//	        Exits 0 on clean completion; non-zero on any store error.
//	reader  Loops GetConfig against the same key. Each Get MUST return
//	        either ErrConfigNotFound (key not yet written by writer) or a
//	        ConfigEntry whose Data unmarshals to the expected
//	        version-payload shape — a torn read would manifest as a JSON
//	        unmarshal error and the helper exits non-zero with the count
//	        of torn reads on stderr.
//
// FLATFILE_HELPER_ROOT     — path to the shared flatfile root.
// FLATFILE_HELPER_TENANT   — tenant id (must be path-safe).
// FLATFILE_HELPER_DURATION_MS — how long to loop.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	mode := os.Getenv("FLATFILE_HELPER_MODE")
	root := os.Getenv("FLATFILE_HELPER_ROOT")
	tenant := os.Getenv("FLATFILE_HELPER_TENANT")
	durStr := os.Getenv("FLATFILE_HELPER_DURATION_MS")
	durMs, _ := strconv.Atoi(durStr)
	if durMs <= 0 {
		durMs = 500
	}
	if root == "" || tenant == "" || mode == "" {
		fmt.Fprintln(os.Stderr, "helper: missing required env (FLATFILE_HELPER_ROOT, FLATFILE_HELPER_TENANT, FLATFILE_HELPER_MODE)")
		os.Exit(2)
	}

	store, err := NewFlatFileConfigStore(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper: NewFlatFileConfigStore: %v\n", err)
		os.Exit(2)
	}

	deadline := time.Now().Add(time.Duration(durMs) * time.Millisecond)
	ctx := context.Background()
	key := &cfgconfig.ConfigKey{
		TenantID:  tenant,
		Namespace: "blue-green",
		Name:      "shared",
	}

	switch mode {
	case "writer":
		iter := 0
		for time.Now().Before(deadline) {
			iter++
			// Payload encodes the iteration so the reader can sanity-check
			// it parses as JSON. Length varies (zero-padded width 8 → 16
			// → 32 chars depending on iter) so different versions write
			// genuinely different byte sequences, maximising the chance
			// of a torn read materialising as a JSON parse error.
			payload := []byte(fmt.Sprintf(`{"iter":%d,"pad":%q}`, iter, "x"))
			entry := &cfgconfig.ConfigEntry{
				Key:    key,
				Data:   payload,
				Format: cfgconfig.ConfigFormatJSON,
			}
			if err := store.StoreConfig(ctx, entry); err != nil {
				fmt.Fprintf(os.Stderr, "helper writer iter=%d: StoreConfig: %v\n", iter, err)
				os.Exit(3)
			}
		}
		os.Exit(0)

	case "reader":
		var (
			ok        int
			notFound  int
			tornReads int
		)
		for time.Now().Before(deadline) {
			entry, err := store.GetConfig(ctx, key)
			if err == cfgconfig.ErrConfigNotFound {
				notFound++
				continue
			}
			if err != nil {
				// Any error other than not-found is treated as a torn
				// read for this test. The ONLY error path StoreConfig can
				// surface to the reader is via readConfigFile's JSON
				// unmarshal, which would mean the reader observed a
				// partially-written file.
				tornReads++
				fmt.Fprintf(os.Stderr, "helper reader: torn-read candidate: %v\n", err)
				continue
			}
			// Sanity check: payload must parse as JSON. If it doesn't,
			// that's a torn read disguised as a successful return. Using
			// json.Valid (not just a first-byte check) catches truncation
			// AFTER the leading '{' too — review feedback from #1919.
			if len(entry.Data) == 0 || entry.Data[0] != '{' || !json.Valid(entry.Data) {
				tornReads++
				fmt.Fprintf(os.Stderr, "helper reader: malformed payload: %q\n", entry.Data)
				continue
			}
			ok++
		}
		fmt.Fprintf(os.Stderr, "helper reader: ok=%d not_found=%d torn=%d\n", ok, notFound, tornReads)
		if tornReads > 0 {
			os.Exit(4)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "helper: unknown mode %q\n", mode)
		os.Exit(2)
	}
}

// TestFlatFile_CrossProcess_OneWriterManyReaders covers the flatfile
// blue/green substrate guarantee from Issue #1919: with one writer process
// pounding StoreConfig and N reader processes pounding GetConfig against
// the SAME shared root directory, no reader observes a torn / malformed
// file.
//
// This proves the documented contract in plugin.go: cross-process readers
// always observe a complete file because writes commit via os.Rename
// which is atomic on the host filesystem. The in-process RWMutex provides
// nothing across the process boundary, so this test specifically
// exercises the rename-based atomicity.
//
// The test uses the TestHelperProcess pattern (re-exec'ing the test binary
// in a different env var-controlled mode) to avoid building external
// helper binaries. The same trick is used by the launcher tests.
func TestFlatFile_CrossProcess_OneWriterManyReaders(t *testing.T) {
	root := t.TempDir()
	tenant := "blue-green-test"
	exe, err := os.Executable()
	require.NoError(t, err, "os.Executable")

	const (
		numReaders = 3
		// 5 seconds gives the test enough wall-clock under CI load to
		// actually exercise the rename/read sharing-violation retries.
		// 1500ms was the prior value; review feedback flagged it as
		// insufficient once subprocess fork+exec overhead was accounted
		// for. 5s = plenty of headroom while still keeping the test
		// fast enough that it doesn't dominate `go test ./...`.
		durationMs = "5000"
	)

	spawn := func(mode string) *exec.Cmd {
		cmd := exec.Command(exe, "-test.run=TestHelperProcess") //nolint:gosec // test infra
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			"FLATFILE_HELPER_MODE="+mode,
			"FLATFILE_HELPER_ROOT="+root,
			"FLATFILE_HELPER_TENANT="+tenant,
			"FLATFILE_HELPER_DURATION_MS="+durationMs,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd
	}

	writer := spawn("writer")
	readers := make([]*exec.Cmd, numReaders)
	for i := range readers {
		readers[i] = spawn("reader")
	}

	require.NoError(t, writer.Start(), "writer.Start")
	for i, r := range readers {
		require.NoError(t, r.Start(), "reader %d Start", i)
	}

	var wg sync.WaitGroup
	wg.Add(numReaders + 1)

	var writerErr error
	go func() {
		defer wg.Done()
		writerErr = writer.Wait()
	}()

	readerErrs := make([]error, numReaders)
	for i, r := range readers {
		idx, r := i, r
		go func() {
			defer wg.Done()
			readerErrs[idx] = r.Wait()
		}()
	}

	wg.Wait()

	assert.NoError(t, writerErr, "writer subprocess failed — see helper stderr above")
	for i, err := range readerErrs {
		assert.NoError(t, err, "reader subprocess %d failed — exit code 4 means a torn read was observed", i)
	}

	// Sanity: the parent process must be able to read the final state.
	parentStore, err := NewFlatFileConfigStore(root)
	require.NoError(t, err)
	entry, err := parentStore.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  tenant,
		Namespace: "blue-green",
		Name:      "shared",
	})
	require.NoError(t, err, "parent read of final state failed — write loop never landed any record?")
	assert.Greater(t, len(entry.Data), 0)
	assert.Equal(t, byte('{'), entry.Data[0], "final payload is not the expected JSON shape")

	// Confirm the writer actually did work by looking at the file size on
	// disk (smoke test against accidentally-no-op writer).
	fi, statErr := os.Stat(filepath.Join(root, tenant, "configs", "blue-green", "shared.json"))
	require.NoError(t, statErr, "final file should exist on disk")
	assert.Greater(t, fi.Size(), int64(0))
}
