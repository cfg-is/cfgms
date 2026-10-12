// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

// certRevocationFileName and certSigningCursorFileName are the node-local
// pkg/cert file-store records the steward keeps next to the issued credential.
// They are defined unexported in pkg/cert; the names are mirrored here and
// pinned by TestPrepareImage_RemovesIdentityKeepsTrustAnchorAndToken.
const (
	certRevocationFileName    = "revocation.json"
	certSigningCursorFileName = "signing-cursor.json"
	certStoreCADirName        = "ca"
	certMetadataFileName      = "metadata.json"
)

// imageService is the part of service.Manager prepare-image needs.
type imageService interface {
	IsElevated() bool
	Stop() error
	RegistrationTokenConfigured() (bool, error)
}

var _ imageService = service.Manager(nil)

// prepareImageOptions configures prepareImage.
type prepareImageOptions struct {
	CertStoreDir string
	DryRun       bool
	Yes          bool
}

// identityFileNames are the files directly inside the cert store directory that
// name or authenticate the enrolled identity.
func identityFileNames() []string {
	return []string{
		identity.StoredKeyFileName(), // device identity key
		identityFileName,             // steward ID, tenant, device ID, TOFU pin
		pendingStateFileName,         // pending registration (holds a client key)
		refreshPendingStateFileName,  // queued re-admission request
		readmitPaceFileName,          // re-admission pacing
		certRevocationFileName,       // revocation list of the issued credential
		certSigningCursorFileName,    // signing certificate cursor of the old identity
	}
}

const prepareImageLongHelp = `Prepare this machine to be captured as a base image.

An image built from a machine that already enrolled a steward carries that
steward's device key, client certificate and steward ID into every clone, and
every clone then presents the same identity. prepare-image removes the enrolled
identity so each clone enrolls as its own device on first boot through the
normal registration and approval flow (ADR-034 §6).

Removed, from the certificate store directory (--cert-store-dir):
  device_identity.enc            device identity key
  steward-identity.json          steward ID, tenant, device ID and, for
                                 trust-on-first-use installs, the CA pin
  steward-pending.json           pending registration state
  steward-refresh-pending.json   queued re-admission request
  steward-readmit-pace.json      re-admission pacing
  revocation.json                revocation list of the issued credential
  signing-cursor.json            signing certificate cursor
  ca/                            local certificate-store CA and its key
  <serial>/                      each issued mTLS credential directory
                                 (cert.pem, chain.pem, key.pem, metadata.json)

Kept:
  the installed binary
  the service definition and its registration token (--regtoken)
  the trust anchor: the install-pinned CA file (controller-ca.crt); a
    compile-baked trust anchor needs nothing
  machine-generic state: the key-derivation salt and machine-id files, the
    steward secrets store (its offline-queue key names no identity)

The steward keeps no DNA cache or offline queue on disk, so there is nothing
to remove for them.

Trust-on-first-use installs pin the controller CA inside steward-identity.json.
Removing it means each clone re-pins the CA at first boot, which is a weaker
trust path than an install-pinned CA.

The service is stopped and left enabled; prepare-image does not start it.
It refuses to run if the service definition carries no registration token,
and removes nothing in that case. Running it again on a prepared machine
reports "nothing to remove".

Requires elevated privileges (Administrator on Windows, root on Linux/macOS).`

// buildPrepareImageCommand builds the `cfgms-steward prepare-image` subcommand.
func buildPrepareImageCommand() *cobra.Command {
	var opts prepareImageOptions

	cmd := &cobra.Command{
		Use:   "prepare-image",
		Short: "Remove the enrolled identity before this machine is imaged",
		Long:  prepareImageLongHelp,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("failed to determine executable path: %w", err)
			}
			return prepareImage(opts, service.New(exe), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}

	cmd.Flags().BoolVar(&opts.Yes, "yes", false, "Skip the confirmation prompt")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "List what would be removed and remove nothing")
	cmd.Flags().StringVar(&opts.CertStoreDir, "cert-store-dir", defaultCertStoreDir(),
		"Certificate store directory holding the steward identity (non-default installs and tests)")

	return cmd
}

// prepareImage removes the enrolled identity from opts.CertStoreDir. It checks
// every precondition before it stops the service or removes anything.
func prepareImage(opts prepareImageOptions, svc imageService, in io.Reader, out io.Writer) error {
	if !svc.IsElevated() {
		return fmt.Errorf("prepare-image requires elevated privileges\n" +
			"  Windows: right-click the binary and select 'Run as administrator'\n" +
			"  Linux/macOS: re-run with sudo")
	}

	hasToken, err := svc.RegistrationTokenConfigured()
	if err != nil {
		return fmt.Errorf("failed to inspect the service definition: %w", err)
	}
	if !hasToken {
		return fmt.Errorf("the service definition carries no registration token; nothing was removed\n" +
			"  a clone could not enroll without one: run 'cfgms-steward install --regtoken TOKEN' first")
	}

	dir := opts.CertStoreDir
	if info, lerr := os.Lstat(dir); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to prepare %s: the certificate store directory is a symlink", dir)
	}

	// Read the trust mode before the identity file is removed.
	trustMode := ""
	if id, lerr := loadIdentity(dir); lerr == nil && id != nil {
		trustMode = id.TrustMode
	}

	plan, err := planIdentityRemoval(dir)
	if err != nil {
		return err
	}

	if len(plan.remove) == 0 {
		_, _ = fmt.Fprintf(out, "There is nothing to remove: no enrolled identity found in %s.\n", dir)
		return nil
	}

	verb := "Will remove"
	if opts.DryRun {
		verb = "Would remove (dry run)"
	}
	_, _ = fmt.Fprintf(out, "%s from %s:\n", verb, dir)
	for _, p := range plan.remove {
		_, _ = fmt.Fprintf(out, "  %s\n", p)
	}
	for _, p := range plan.leftInPlace {
		_, _ = fmt.Fprintf(out, "  left in place (unexpected subdirectory): %s\n", p)
	}
	printTrustNotes(out, trustMode)

	if opts.DryRun {
		return nil
	}

	if !opts.Yes {
		_, _ = fmt.Fprint(out, "Stop the steward service and remove the identity above? [y/N]: ")
		answer, _ := bufio.NewReader(in).ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
		default:
			return errors.New("aborted: nothing was removed")
		}
	}

	_, _ = fmt.Fprintln(out, "Stopping the steward service...")
	if err := svc.Stop(); err != nil {
		return fmt.Errorf("failed to stop the steward service; nothing was removed: %w", err)
	}

	removed := 0
	keyPath := filepath.Join(dir, identity.StoredKeyFileName())
	for _, p := range plan.remove {
		var err error
		if p == keyPath {
			err = identity.RemoveStoredKey(dir)
		} else {
			err = removeNoFollow(p)
		}
		if err != nil {
			return fmt.Errorf("removed %d of %d items before failing: %w", removed, len(plan.remove), err)
		}
		removed++
	}

	_, _ = fmt.Fprintf(out, "\nRemoved %d items. The steward service is stopped and still enabled; it was not started.\n", removed)
	_, _ = fmt.Fprintln(out, "Capture the image now. Each clone enrolls as a new device on first boot.")
	return nil
}

// printTrustNotes states which trust anchor survives in the image.
func printTrustNotes(out io.Writer, trustMode string) {
	_, _ = fmt.Fprintln(out, "\nKept: the installed binary, the service definition with its registration token, and the trust anchor.")
	if trustMode == "tofu" {
		_, _ = fmt.Fprintln(out, "NOTE: this steward trusts the controller by trust-on-first-use. The CA pin is stored in\n"+
			"      steward-identity.json and is removed with it, so each clone will re-pin the CA at first\n"+
			"      boot. That is a weaker trust path than an install-pinned CA (install --controller-ca).")
	}
}

type identityRemovalPlan struct {
	remove      []string // files, then directories, in removal order
	leftInPlace []string // unexpected subdirectories that are not removed
}

// planIdentityRemoval lists what prepare-image removes from dir without
// following symlinks. A missing directory yields an empty plan.
func planIdentityRemoval(dir string) (*identityRemovalPlan, error) {
	plan := &identityRemovalPlan{}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return plan, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate store %s: %w", dir, err)
	}

	known := make(map[string]bool)
	for _, n := range identityFileNames() {
		known[n] = true
	}

	var dirs []string
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		switch {
		case known[e.Name()] && !e.IsDir():
			plan.remove = append(plan.remove, path)
		case e.IsDir() && isCredentialDir(path, e.Name()):
			dirs = append(dirs, path)
		}
	}

	for _, d := range dirs {
		children, err := os.ReadDir(d)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", d, err)
		}
		for _, c := range children {
			cp := filepath.Join(d, c.Name())
			if c.IsDir() {
				plan.leftInPlace = append(plan.leftInPlace, cp)
				continue
			}
			plan.remove = append(plan.remove, cp)
		}
	}
	// Directories last, so they are empty when removed.
	plan.remove = append(plan.remove, dirs...)
	return plan, nil
}

// isCredentialDir reports whether path is the local CA directory or a
// per-serial credential directory of the pkg/cert file store (one that holds a
// metadata.json). Other directories are not the steward's identity state.
func isCredentialDir(path, name string) bool {
	if name == certStoreCADirName {
		return true
	}
	info, err := os.Lstat(filepath.Join(path, certMetadataFileName))
	return err == nil && info.Mode().IsRegular()
}

// removeNoFollow removes one planned path. Removing a file that is already
// gone succeeds; a directory that still holds an unexpected subdirectory is
// left in place. Symlinks are removed as links, never followed.
func removeNoFollow(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if info.IsDir() {
		entries, rerr := os.ReadDir(path)
		if rerr == nil && len(entries) > 0 {
			return nil
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove %s: %w", path, err)
	}
	return nil
}
