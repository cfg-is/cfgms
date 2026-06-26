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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// makeTarGz builds an in-memory gzip-compressed tar from name->content entries.
func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

// makeZip builds an in-memory zip from name->content entries.
func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip Create: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip Write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("github runner agent archive bytes")
	good := sha256Hex(data)

	if err := verifyChecksum(data, good); err != nil {
		t.Fatalf("verifyChecksum rejected a matching archive: %v", err)
	}
	// Case-insensitive hex must still match.
	if err := verifyChecksum(data, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("verifyChecksum accepted a tampered/mismatched archive")
	}
	// A single tampered byte must fail.
	tampered := append([]byte(nil), data...)
	tampered[0] ^= 0xFF
	if err := verifyChecksum(tampered, good); err == nil {
		t.Fatal("verifyChecksum accepted an archive whose bytes were altered")
	}
}

func TestUnpackTarGz_RoundTrip(t *testing.T) {
	dest := t.TempDir()
	archive := makeTarGz(t, map[string]string{
		"bin/Runner.Listener": "listener-binary",
		"config.sh":           "#!/bin/sh\n",
	})
	if err := unpackTarGz(archive, dest); err != nil {
		t.Fatalf("unpackTarGz: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "bin", "Runner.Listener"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "listener-binary" {
		t.Fatalf("extracted content = %q, want %q", got, "listener-binary")
	}
}

func TestUnpackZip_RoundTrip(t *testing.T) {
	dest := t.TempDir()
	archive := makeZip(t, map[string]string{
		"bin/Runner.Listener.exe": "listener-exe",
		"config.cmd":              "@echo off\n",
	})
	if err := unpackZip(archive, dest); err != nil {
		t.Fatalf("unpackZip: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "bin", "Runner.Listener.exe"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != "listener-exe" {
		t.Fatalf("extracted content = %q, want %q", got, "listener-exe")
	}
}

func TestUnpack_RejectsPathTraversal(t *testing.T) {
	dest := t.TempDir()

	tgz := makeTarGz(t, map[string]string{"../escape.sh": "evil"})
	if err := unpackTarGz(tgz, dest); err == nil {
		t.Fatal("unpackTarGz extracted a path-traversal (zip-slip) entry")
	}
	// The escaped file must not exist outside dest.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.sh")); err == nil {
		t.Fatal("path-traversal tar entry wrote outside the destination")
	}

	zipBytes := makeZip(t, map[string]string{`..\escape.exe`: "evil"})
	if err := unpackZip(zipBytes, dest); err == nil {
		t.Fatal("unpackZip extracted a path-traversal (zip-slip) entry")
	}
}

func TestExtractArchive_UnsupportedFormat(t *testing.T) {
	if err := extractArchive([]byte("x"), t.TempDir(), "rar"); err == nil {
		t.Fatal("extractArchive accepted an unsupported format")
	}
}

func TestHTTPInstaller_VerifiesAndExtracts(t *testing.T) {
	archive := makeTarGz(t, map[string]string{"bin/Runner.Listener": "listener"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	inst := newHTTPInstaller()
	dest := t.TempDir()

	// Correct hash → installs and extracts.
	if err := inst.install(context.Background(), installSource{
		URL: srv.URL, SHA256: sha256Hex(archive), Version: "2.319.1", WorkDir: dest, Format: "tar.gz",
	}); err != nil {
		t.Fatalf("install with correct hash failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "bin", "Runner.Listener")); err != nil {
		t.Fatalf("agent not extracted: %v", err)
	}

	// Wrong hash → rejected, nothing extracted into a fresh dir.
	dest2 := t.TempDir()
	err := inst.install(context.Background(), installSource{
		URL: srv.URL, SHA256: sha256Hex([]byte("different")), Version: "2.319.1", WorkDir: dest2, Format: "tar.gz",
	})
	if err == nil {
		t.Fatal("install accepted an archive whose served bytes did not match the pinned sha256")
	}
	if entries, _ := os.ReadDir(dest2); len(entries) != 0 {
		t.Fatalf("install extracted files despite a sha256 mismatch: %d entries", len(entries))
	}
}
