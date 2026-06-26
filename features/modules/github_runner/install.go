// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package github_runner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxArchiveBytes bounds the agent archive download and each extracted entry to
// guard against a decompression bomb. The GitHub runner agent is ~200 MiB; 1 GiB
// is a generous ceiling.
const maxArchiveBytes = 1 << 30 // 1 GiB

// installSource fully describes one agent install: where to fetch it, the
// expected hash, the version label, the destination work dir, and the archive
// format ("tar.gz" or "zip").
type installSource struct {
	URL     string
	SHA256  string
	Version string
	WorkDir string
	Format  string
}

// httpInstaller is the production agentInstaller: it downloads the archive over
// net/http, verifies its SHA-256 against the pinned value, and unpacks it with
// the Go standard library. It never shells out.
type httpInstaller struct {
	client *http.Client
}

// newHTTPInstaller returns an installer using the default HTTP client.
func newHTTPInstaller() agentInstaller {
	return &httpInstaller{client: http.DefaultClient}
}

// newHTTPInstallerWithClient returns an installer using the supplied HTTP client.
// It is a test seam so a test can drive the real install path against a local
// TLS httptest server (whose self-signed cert the default client would reject).
func newHTTPInstallerWithClient(c *http.Client) agentInstaller {
	if c == nil {
		c = http.DefaultClient
	}
	return &httpInstaller{client: c}
}

// install downloads, verifies, and unpacks the agent archive into src.WorkDir.
func (h *httpInstaller) install(ctx context.Context, src installSource) error {
	data, err := h.download(ctx, src.URL)
	if err != nil {
		return err
	}
	if err := verifyChecksum(data, src.SHA256); err != nil {
		return err
	}
	if err := extractArchive(data, src.WorkDir, src.Format); err != nil {
		return err
	}
	return nil
}

// download fetches url into memory, bounded by maxArchiveBytes.
func (h *httpInstaller) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download agent: unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxArchiveBytes {
		return nil, fmt.Errorf("download agent: archive exceeds %d bytes", maxArchiveBytes)
	}
	return data, nil
}

// verifyChecksum computes the SHA-256 of data and compares it (constant-pattern,
// case-insensitive hex) to expectedHex. A mismatch rejects a tampered archive.
func verifyChecksum(data []byte, expectedHex string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, expectedHex) {
		return fmt.Errorf("agent archive sha256 mismatch: expected %s, got %s", strings.ToLower(expectedHex), got)
	}
	return nil
}

// archiveFormatForOS returns the agent archive format for the current OS: the
// GitHub runner ships as a .tar.gz on Linux and a .zip on Windows.
func archiveFormatForOS() string {
	if runtime.GOOS == "windows" {
		return "zip"
	}
	return "tar.gz"
}

// extractArchive unpacks data into dest using the named format. Both formats are
// implemented with the Go standard library — no shelling out to tar or
// Expand-Archive — and both reject path-traversal ("zip slip") entries.
func extractArchive(data []byte, dest, format string) error {
	switch format {
	case "tar.gz", "targz", "tgz":
		return unpackTarGz(data, dest)
	case "zip":
		return unpackZip(data, dest)
	default:
		return fmt.Errorf("unsupported archive format %q", format)
	}
}

// safeJoin joins dest and a (possibly hostile) archive entry name, REJECTING any
// entry that would escape dest. It normalises separators (so a Windows-built zip
// entry is handled on Linux and vice-versa), rejects any ".." path segment
// outright (zip-slip guard), and then verifies containment via filepath.Rel as
// defense in depth. Returns the cleaned absolute target.
func safeJoin(dest, name string) (string, error) {
	n := strings.TrimPrefix(strings.ReplaceAll(name, `\`, "/"), "/")
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return "", fmt.Errorf("archive entry %q escapes destination", name)
		}
	}
	target := filepath.Join(dest, filepath.FromSlash(n))
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry %q escapes destination", name)
	}
	return target, nil
}

// unpackTarGz extracts a gzip-compressed tar into dest.
func unpackTarGz(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeFileFromReader(target, tr, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		default:
			// Skip symlinks, devices, fifos — the runner archive contains none,
			// and extracting them would be an attack surface.
			continue
		}
	}
	return nil
}

// unpackZip extracts a zip archive into dest.
func unpackZip(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	for _, f := range zr.File {
		target, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}
		err = writeFileFromReader(target, rc, f.Mode())
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// writeFileFromReader creates target (with parent dirs) and copies up to
// maxArchiveBytes from r into it. The copy is bounded to guard against a
// decompression bomb in a single entry. The deferred Close error is propagated
// (when no earlier error occurred) because Close is where buffered writes flush —
// swallowing it could yield a silently truncated agent binary.
func writeFileFromReader(target string, r io.Reader, mode os.FileMode) (err error) {
	if err = os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	// Constrain file permissions to owner/group; never world-writable.
	perm := mode.Perm() & 0o770
	if perm == 0 {
		perm = 0o640
	}
	out, oerr := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm) // #nosec G304 - target validated by safeJoin
	if oerr != nil {
		return oerr
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, io.LimitReader(r, maxArchiveBytes+1)); err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}
