// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

const prepareImageTestToken = "tok_prepare_image_secret_123"

// serviceStandIn is a service-manager stand-in for the image under preparation.
// Its "service definition" is a real file on disk; Stop records the call and
// the image is considered stopped from then on.
type serviceStandIn struct {
	definitionPath string
	elevated       bool
	stopErr        error
	stopped        int
}

func (s *serviceStandIn) IsElevated() bool { return s.elevated }

func (s *serviceStandIn) Stop() error {
	s.stopped++
	return s.stopErr
}

func (s *serviceStandIn) RegistrationTokenConfigured() (bool, error) {
	data, err := os.ReadFile(s.definitionPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.Contains(string(data), "--regtoken "+prepareImageTestToken), nil
}

// enrolledImage is an image built from a machine that already enrolled: a real
// device key, identity file, pending/re-admission state and issued certificate
// in a cert store directory, plus a trust-anchor file and a service definition
// carrying the registration token outside that directory.
type enrolledImage struct {
	certStoreDir string
	caFile       string
	serviceDef   string
	svc          *serviceStandIn
	deviceID     string
}

func newEnrolledImage(t *testing.T) *enrolledImage {
	t.Helper()
	fx := newStoredIdentityFixture(t, "127.0.0.1:1")
	dir := fx.certStoreDir

	ks, err := identity.NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	require.NoError(t, savePendingState(dir, PendingState{PendingID: "pending-1", ClientKeyPEM: "k"}))
	require.NoError(t, writePendingStateFile(dir, refreshPendingStateFileName, PendingState{PendingID: "refresh-1"}))
	require.NoError(t, os.WriteFile(filepath.Join(dir, readmitPaceFileName), []byte("{}"), 0600))

	machine := t.TempDir()
	img := &enrolledImage{
		certStoreDir: dir,
		caFile:       filepath.Join(machine, "controller-ca.crt"),
		serviceDef:   filepath.Join(machine, "cfgms-steward.service"),
		deviceID:     ks.DeviceID(),
	}
	require.NoError(t, os.WriteFile(img.caFile, []byte(fx.caPEM), 0644))
	require.NoError(t, os.WriteFile(img.serviceDef,
		[]byte(`ExecStart=launcher run --child-args "--regtoken `+prepareImageTestToken+`"`), 0600))
	img.svc = &serviceStandIn{definitionPath: img.serviceDef, elevated: true}
	if runtime.GOOS == "windows" && !service.New("").IsElevated() {
		// The machine key store refuses an unelevated process (NTE_PERM), and
		// prepare-image requires elevation, so this run can only reach the file key.
		saved := removeDeviceKeys
		removeDeviceKeys = identity.RemoveStoredKey
		t.Cleanup(func() { removeDeviceKeys = saved })
	}
	return img
}

func (img *enrolledImage) run(t *testing.T, opts prepareImageOptions) (string, error) {
	t.Helper()
	opts.CertStoreDir = img.certStoreDir
	var out bytes.Buffer
	err := prepareImage(opts, img.svc, strings.NewReader(""), &out)
	return out.String(), err
}

// listFiles returns every file path under dir relative to dir.
func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	require.NoError(t, filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			files = append(files, rel)
		}
		return nil
	}))
	return files
}

func TestPrepareImage_RemovesIdentityKeepsTrustAnchorAndToken(t *testing.T) {
	img := newEnrolledImage(t)
	before := listFiles(t, img.certStoreDir)
	for _, want := range []string{
		"device_identity.enc", identityFileName, pendingStateFileName,
		refreshPendingStateFileName, readmitPaceFileName,
	} {
		require.Contains(t, before, want)
	}
	caBefore, err := os.ReadFile(img.caFile)
	require.NoError(t, err)
	defBefore, err := os.ReadFile(img.serviceDef)
	require.NoError(t, err)

	out, err := img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)

	// Every identity file is gone; only machine-generic files may remain.
	for _, f := range listFiles(t, img.certStoreDir) {
		base := filepath.Base(f)
		assert.Contains(t, []string{"salt", "machine-id"}, base, "unexpected file left behind: %s", f)
	}
	_, statErr := os.Stat(filepath.Join(img.certStoreDir, "ca"))
	assert.True(t, os.IsNotExist(statErr), "local cert-store CA directory must be removed")

	caAfter, err := os.ReadFile(img.caFile)
	require.NoError(t, err)
	assert.Equal(t, caBefore, caAfter, "trust anchor must be untouched")
	defAfter, err := os.ReadFile(img.serviceDef)
	require.NoError(t, err)
	assert.Equal(t, defBefore, defAfter, "service definition with token must be untouched")

	assert.Equal(t, 1, img.svc.stopped, "service must be stopped before removal")
	assert.NotContains(t, out, prepareImageTestToken, "output must never print the registration token")
	assert.Contains(t, out, "stopped")
}

func TestPrepareImage_NextStartGeneratesDifferentDeviceID(t *testing.T) {
	img := newEnrolledImage(t)
	require.NotEmpty(t, img.deviceID)

	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)

	ks, err := identity.NewFileKeyStoreForTesting(img.certStoreDir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, img.deviceID, ks.DeviceID(), "a clone must enroll as a different device")

	id, err := loadIdentity(img.certStoreDir)
	require.NoError(t, err)
	assert.Nil(t, id, "no stored identity may survive, so the first start takes the enrollment path")
}

// recordKeyRemoval wraps the real key removal and records each directory it ran on.
func recordKeyRemoval(t *testing.T) *[]string {
	t.Helper()
	var dirs []string
	saved := removeDeviceKeys
	removeDeviceKeys = func(dir string) error {
		dirs = append(dirs, dir)
		return saved(dir)
	}
	t.Cleanup(func() { removeDeviceKeys = saved })
	return &dirs
}

// TestPrepareImage_RemovesHardwareHeldKey covers a steward whose device key is
// held in a TPM or Secure Enclave: there is no device_identity.enc, yet the key
// backends must still be told to remove the key, or the next start reloads it.
func TestPrepareImage_RemovesHardwareHeldKey(t *testing.T) {
	img := newEnrolledImage(t)
	require.NoError(t, identity.RemoveStoredKey(img.certStoreDir))
	calls := recordKeyRemoval(t)

	out, err := img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)
	assert.Equal(t, []string{img.certStoreDir}, *calls)
	assert.Contains(t, out, "TPM or Secure Enclave")
	id, err := loadIdentity(img.certStoreDir)
	require.NoError(t, err)
	assert.Nil(t, id)
}

func TestPrepareImage_DryRunRemovesNoKey(t *testing.T) {
	img := newEnrolledImage(t)
	calls := recordKeyRemoval(t)
	_, err := img.run(t, prepareImageOptions{DryRun: true})
	require.NoError(t, err)
	assert.Empty(t, *calls)
}

func TestPrepareImage_KeyRemovalFailureRemovesNothingElse(t *testing.T) {
	img := newEnrolledImage(t)
	before := listFiles(t, img.certStoreDir)
	saved := removeDeviceKeys
	removeDeviceKeys = func(string) error { return errors.New("key store unavailable") }
	t.Cleanup(func() { removeDeviceKeys = saved })

	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "removed 0 of")
	assert.ElementsMatch(t, before, listFiles(t, img.certStoreDir))
}

func TestPrepareImage_DryRunRemovesNothing(t *testing.T) {
	img := newEnrolledImage(t)
	before := listFiles(t, img.certStoreDir)

	out, err := img.run(t, prepareImageOptions{DryRun: true})
	require.NoError(t, err)

	assert.ElementsMatch(t, before, listFiles(t, img.certStoreDir))
	assert.Equal(t, 0, img.svc.stopped, "dry run must not stop the service")
	for _, name := range []string{"device_identity.enc", identityFileName, pendingStateFileName} {
		assert.Contains(t, out, name)
	}
	assert.NotContains(t, out, prepareImageTestToken)
}

func TestPrepareImage_Idempotent(t *testing.T) {
	img := newEnrolledImage(t)
	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)
	stops := img.svc.stopped

	out, err := img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)
	assert.Contains(t, out, "nothing to remove")
	assert.Equal(t, stops, img.svc.stopped, "nothing to remove means the service is not touched")

	// A machine that never enrolled has no cert store at all.
	img.certStoreDir = filepath.Join(t.TempDir(), "never-enrolled")
	out, err = img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)
	assert.Contains(t, out, "nothing to remove")
}

func TestPrepareImage_RefusesSymlinkedCertStoreDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege the Windows CI user does not hold")
	}
	img := newEnrolledImage(t)
	link := filepath.Join(t.TempDir(), "certs-link")
	require.NoError(t, os.Symlink(img.certStoreDir, link))
	before := listFiles(t, img.certStoreDir)

	img.certStoreDir = link
	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")

	assert.ElementsMatch(t, before, listFiles(t, resolved(t, link)))
	assert.Equal(t, 0, img.svc.stopped)
}

func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	require.NoError(t, err)
	return r
}

func TestPrepareImage_DoesNotFollowSymlinkedEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege the Windows CI user does not hold")
	}
	img := newEnrolledImage(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("keep me"), 0600))
	require.NoError(t, os.Remove(filepath.Join(img.certStoreDir, readmitPaceFileName)))
	require.NoError(t, os.Symlink(outside, filepath.Join(img.certStoreDir, readmitPaceFileName)))

	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)

	data, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, "keep me", string(data), "the link is removed, its target outside the cert store is not")
	_, lerr := os.Lstat(filepath.Join(img.certStoreDir, readmitPaceFileName))
	assert.True(t, os.IsNotExist(lerr))
}

func TestPrepareImage_RefusesWithoutToken(t *testing.T) {
	img := newEnrolledImage(t)
	require.NoError(t, os.WriteFile(img.serviceDef, []byte(`ExecStart=launcher run`), 0600))
	before := listFiles(t, img.certStoreDir)

	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration token")

	assert.ElementsMatch(t, before, listFiles(t, img.certStoreDir), "nothing may be removed")
	assert.Equal(t, 0, img.svc.stopped)
}

func TestPrepareImage_RequiresElevation(t *testing.T) {
	img := newEnrolledImage(t)
	img.svc.elevated = false
	before := listFiles(t, img.certStoreDir)

	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated")
	assert.ElementsMatch(t, before, listFiles(t, img.certStoreDir))
}

func TestPrepareImage_StopFailureRemovesNothing(t *testing.T) {
	img := newEnrolledImage(t)
	img.svc.stopErr = os.ErrPermission
	before := listFiles(t, img.certStoreDir)

	_, err := img.run(t, prepareImageOptions{Yes: true})
	require.Error(t, err)
	assert.ElementsMatch(t, before, listFiles(t, img.certStoreDir))
}

func TestPrepareImage_ConfirmationPrompt(t *testing.T) {
	img := newEnrolledImage(t)
	before := listFiles(t, img.certStoreDir)

	var out bytes.Buffer
	err := prepareImage(prepareImageOptions{CertStoreDir: img.certStoreDir}, img.svc, strings.NewReader("no\n"), &out)
	require.Error(t, err)
	assert.ElementsMatch(t, before, listFiles(t, img.certStoreDir))
	assert.Equal(t, 0, img.svc.stopped)

	err = prepareImage(prepareImageOptions{CertStoreDir: img.certStoreDir}, img.svc, strings.NewReader("yes\n"), &out)
	require.NoError(t, err)
	assert.NotContains(t, listFiles(t, img.certStoreDir), identityFileName)
}

func TestPrepareImage_TOFUCaveatReported(t *testing.T) {
	img := newEnrolledImage(t)
	id, err := loadIdentity(img.certStoreDir)
	require.NoError(t, err)
	require.NotNil(t, id)
	id.TrustMode = "tofu"
	require.NoError(t, saveIdentity(img.certStoreDir, *id))

	out, err := img.run(t, prepareImageOptions{Yes: true})
	require.NoError(t, err)
	assert.Contains(t, out, "trust-on-first-use")
	assert.Contains(t, out, "re-pin")
}

func TestPrepareImageCommand_Registered(t *testing.T) {
	root := buildRootCommand()
	cmd, _, err := root.Find([]string{"prepare-image"})
	require.NoError(t, err)
	assert.Equal(t, "prepare-image", cmd.Name())
	for _, f := range []string{"yes", "dry-run", "cert-store-dir"} {
		assert.NotNil(t, cmd.Flags().Lookup(f), "missing --%s", f)
	}
}
