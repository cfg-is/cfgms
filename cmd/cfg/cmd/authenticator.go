// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/registration/identity"
)

// maxAuthenticatorCACertBytes bounds the --ca-cert file read.
const maxAuthenticatorCACertBytes = 1 << 20

// authenticatorCmd is the parent command: cfg authenticator ...
var authenticatorCmd = newAuthenticatorCmd()

// newAuthenticatorCmd builds the command tree. Flag state lives on the commands,
// so each call returns a tree with fresh flags.
func newAuthenticatorCmd() *cobra.Command {
	parent := &cobra.Command{
		Use:   "authenticator",
		Short: "Manage software WebAuthn authenticators for headless step-up",
		Long: `Manage software WebAuthn authenticators: P-256 keys bound to one controller's
RP ID and origin, for operators and agents that have no hardware key or browser.

On Windows each key is, by default, a non-exportable per-user key in the
platform key provider (the TPM through the Platform Crypto Provider when
present, otherwise the software key provider). Its private bytes never exist
in cfg or on disk; the encrypted credential store (credential name
authenticator.<name>) holds only the binding and where the key is. Elsewhere,
or with --key-provider store, the key itself is kept in the encrypted
credential store and is never printed or written anywhere else. With
--key-provider tpm (Linux and Windows) the key is created inside the host TPM
and the store holds only TPM-wrapped blobs that are useless on any other
machine; only such a key can register on a root agent account.

Either way, any process running as the same user on this machine can sign with
the key, so treat it as a credential of that user.

Subcommands:
  create  Create an authenticator bound to a controller
  list    List authenticators
  delete  Delete an authenticator`,
	}

	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a software authenticator bound to a controller",
		Long: `Generates a P-256 key and credential ID and stores them, encrypted, as an
authenticator bound to the controller's RP ID and origin. Nothing is sent to the
controller; registering the authenticator is a separate step.

--url must be https. The RP ID defaults to the URL's host and the origin to
scheme://host[:port]; --rp-id and --origin override them (the origin must be https
and its host the RP ID or a subdomain of it). --ca-cert pins the controller's CA
certificate for later connections. Controller TLS certificates are always verified.

--key-provider chooses where the key lives:
  platform  a per-user key in the Windows platform key provider whose private
            bytes cannot be read out (Windows only; the Windows default)
  store     a key kept in the encrypted credential store (the default on other
            operating systems)
  tpm       a key created inside the host TPM 2.0 (Linux /dev/tpmrm0 or Windows
            TBS; not macOS), as the TPM attestation of a root agent account
            requires. It refuses, and creates nothing, when there is no usable
            TPM or the TPM has no endorsement key certificate in NV storage;
            there is no fallback.
With no --key-provider, Windows falls back to store only when no platform key
provider is available, and says so. 'cfg authenticator list' shows which
protection each authenticator has.

An existing name is refused; delete it first to replace it.

Examples:
  cfg authenticator create agent-1 --url https://controller.example.test
  cfg authenticator create agent-1 --url https://10.0.0.5:8443 --rp-id controller.example.test --origin https://controller.example.test:8443 --ca-cert ./ca.pem`,
		Args: cobra.ExactArgs(1),
		RunE: runAuthenticatorCreate,
	}
	create.Flags().String("url", "", "controller URL (https, required)")
	create.Flags().String("rp-id", "", "WebAuthn RP ID (default: host of --url)")
	create.Flags().String("origin", "", "WebAuthn origin, https (default: scheme://host[:port] of --url)")
	create.Flags().String("ca-cert", "", "PEM file with the CA certificate that signs the controller's TLS certificate")
	create.Flags().String("label", "", "free-text label for the authenticator")
	create.Flags().String("key-provider", "", "where the key lives: platform (Windows), store or tpm (default: platform on Windows, store elsewhere)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List software authenticators",
		Long: `Lists the software authenticators in the credential store: name, RP ID, origin,
credential ID (base64url), whether it is registered, and its protection level.
Key material is never shown.

Examples:
  cfg authenticator list
  cfg authenticator list --json`,
		Args: cobra.NoArgs,
		RunE: runAuthenticatorList,
	}
	list.Flags().Bool("json", false, "output as JSON")

	del := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a software authenticator",
		Long: `Deletes the authenticator from the credential store and, for a platform key,
deletes the key from the platform key provider. The key cannot be recovered.
This does not touch the controller: it still lists the credential until it is
revoked (cfg webauthn revoke <credential-id>).

Use --force to skip the interactive confirmation prompt.

Examples:
  cfg authenticator delete agent-1
  cfg authenticator delete agent-1 --force`,
		Args: cobra.ExactArgs(1),
		RunE: runAuthenticatorDelete,
	}
	del.Flags().Bool("force", false, "skip confirmation prompt")

	parent.AddCommand(create, list, del)
	return parent
}

// parseAuthenticatorHTTPSURL parses raw and requires an https URL with a host and
// no embedded credentials. flag names the option in the error.
func parseAuthenticatorHTTPSURL(flag, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("--%s %q is not a valid https URL", flag, raw)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("--%s must be an https URL (got scheme %q): a software authenticator is only ever bound to a TLS-verified controller", flag, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("--%s must not contain credentials", flag)
	}
	return u, nil
}

// readAuthenticatorCACert reads path and returns its PEM if it parses as at least
// one certificate.
func readAuthenticatorCACert(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("--ca-cert: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxAuthenticatorCACertBytes {
		return "", fmt.Errorf("--ca-cert %s is not a regular file of at most %d bytes", path, maxAuthenticatorCACertBytes)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path to their own CA file
	if err != nil {
		return "", fmt.Errorf("--ca-cert: %w", err)
	}
	if _, err := cert.CertPoolFromPEM(data); err != nil {
		return "", fmt.Errorf("--ca-cert %s contains no PEM certificate", path)
	}
	return string(data), nil
}

// authenticatorOrigin returns the origin for controller URL u: the --origin
// override when given (https, scheme://host[:port] only), else scheme://host[:port]
// of u.
func authenticatorOrigin(override string, u *url.URL) (string, error) {
	if override == "" {
		return "https://" + u.Host, nil
	}
	ou, err := parseAuthenticatorHTTPSURL("origin", override)
	if err != nil {
		return "", err
	}
	origin := ou.Scheme + "://" + ou.Host
	if strings.TrimRight(override, "/") != origin {
		return "", fmt.Errorf("--origin %q must be scheme://host[:port] only", override)
	}
	return origin, nil
}

// authenticatorKeyChoice is where create puts the key.
type authenticatorKeyChoice struct {
	protection string // authenticatorProtectionPlatform, authenticatorProtectionStore or authenticatorProtectionTPM
	// fallback allows store when no platform provider is available. It is set
	// only for the Windows default, never for an explicit --key-provider.
	fallback bool
}

// authenticatorHostOS is the operating system key-provider choices are checked
// against. Tests replace it to exercise the macOS refusal on other hosts.
var authenticatorHostOS = runtime.GOOS

// resolveAuthenticatorKeyProvider turns the --key-provider value into a choice.
// It is checked before anything is written.
func resolveAuthenticatorKeyProvider(flag string) (authenticatorKeyChoice, error) {
	switch flag {
	case "":
		if identity.UserKeysSupported() {
			return authenticatorKeyChoice{protection: authenticatorProtectionPlatform, fallback: true}, nil
		}
		return authenticatorKeyChoice{protection: authenticatorProtectionStore}, nil
	case authenticatorProtectionPlatform:
		if !identity.UserKeysSupported() {
			return authenticatorKeyChoice{}, fmt.Errorf("--key-provider platform is not supported on %s: "+
				"platform keys are Windows only; use --key-provider store", runtime.GOOS)
		}
		return authenticatorKeyChoice{protection: authenticatorProtectionPlatform}, nil
	case authenticatorProtectionStore:
		return authenticatorKeyChoice{protection: authenticatorProtectionStore}, nil
	case authenticatorProtectionTPM:
		if authenticatorHostOS == "darwin" {
			return authenticatorKeyChoice{}, errors.New("--key-provider tpm is not supported on macOS: " +
				"there is no TPM key or attestation there, so a root agent account cannot be used from macOS; " +
				"use --key-provider store for an authenticator on an account that does not require a TPM")
		}
		return authenticatorKeyChoice{protection: authenticatorProtectionTPM}, nil
	default:
		return authenticatorKeyChoice{}, fmt.Errorf("--key-provider must be %q, %q or %q (got %q)",
			authenticatorProtectionPlatform, authenticatorProtectionStore, authenticatorProtectionTPM, flag)
	}
}

// makeTPMKeyFirst creates the TPM key when choice asks for one. A TPM key is only
// wrapped blobs in the record, with no state left in the TPM, so it is made before
// the credential store is opened: a host with no usable TPM is refused before the
// store is touched, and a key made for a name that turns out to exist is dropped.
func makeTPMKeyFirst(rec *authenticatorRecord, choice authenticatorKeyChoice) error {
	if choice.protection != authenticatorProtectionTPM {
		return nil
	}
	return rec.setTPMKey()
}

// setAuthenticatorKey gives rec its key as choice says. It reports whether the
// Windows default fell back to the credential store.
func setAuthenticatorKey(rec *authenticatorRecord, choice authenticatorKeyChoice) (fellBack bool, err error) {
	switch choice.protection {
	case authenticatorProtectionStore:
		return false, rec.setStoreKey()
	case authenticatorProtectionTPM:
		return false, nil // runAuthenticatorCreate made the key before opening the store
	}
	err = rec.setPlatformKey()
	if err == nil {
		return false, nil
	}
	if choice.fallback && errors.Is(err, identity.ErrUserKeyUnavailable) {
		return true, rec.setStoreKey()
	}
	return false, err
}

// buildAuthenticatorRecord validates the create flags and returns a new record
// with no key yet. It touches no file and creates no key: a refusal must leave
// the credentials directory and the platform key provider untouched, so neither
// is used until the record is known to be good.
func buildAuthenticatorRecord(name string, flags *pflag.FlagSet) (*authenticatorRecord, error) {
	rawURL, _ := flags.GetString("url")
	if rawURL == "" {
		return nil, errors.New("--url is required")
	}
	u, err := parseAuthenticatorHTTPSURL("url", rawURL)
	if err != nil {
		return nil, err
	}
	originFlag, _ := flags.GetString("origin")
	origin, err := authenticatorOrigin(originFlag, u)
	if err != nil {
		return nil, err
	}
	rpID, _ := flags.GetString("rp-id")
	if rpID == "" {
		rpID = u.Hostname()
	}
	var caPEM string
	if v, _ := flags.GetString("ca-cert"); v != "" {
		if caPEM, err = readAuthenticatorCACert(v); err != nil {
			return nil, err
		}
	}

	rec, err := newAuthenticatorRecordWithoutKey(name)
	if err != nil {
		return nil, err
	}
	rec.RPID = rpID
	rec.Origin = origin
	rec.ControllerURL = strings.TrimRight(u.String(), "/")
	rec.CACertPEM = caPEM
	rec.Label, _ = flags.GetString("label")
	// softauthn is the authority on whether the RP ID and origin are a valid pair.
	if err := rec.checkBinding(); err != nil {
		return nil, err
	}
	return rec, nil
}

func runAuthenticatorCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateAuthenticatorName(name); err != nil {
		return err
	}
	keyProvider, _ := cmd.Flags().GetString("key-provider")
	choice, err := resolveAuthenticatorKeyProvider(keyProvider)
	if err != nil {
		return err
	}
	rec, err := buildAuthenticatorRecord(name, cmd.Flags())
	if err != nil {
		return err
	}

	if err := makeTPMKeyFirst(rec, choice); err != nil {
		return err
	}

	ctx := context.Background()
	store, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("failed to open credential store: %w", err)
	}
	exists, err := authenticatorExists(ctx, store, name)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("authenticator %q already exists; delete it first with 'cfg authenticator delete %s' to replace it", name, name)
	}
	fellBack, err := setAuthenticatorKey(rec, choice)
	if err != nil {
		return err
	}
	if err := saveAuthenticatorRecord(ctx, store, rec); err != nil {
		// Do not leave a platform key behind that no record points to.
		return errors.Join(err, rec.deletePlatformKey())
	}

	printAuthenticatorCreated(cmd.OutOrStdout(), rec, fellBack)
	return nil
}

// printAuthenticatorCreated reports a new authenticator. It never prints key material.
// softwareKeyProviderName is the CNG provider CreateUserKey uses when the
// Platform Crypto Provider (TPM) cannot hold a key.
const softwareKeyProviderName = "Microsoft Software Key Storage Provider"

func printAuthenticatorCreated(out io.Writer, rec *authenticatorRecord, fellBack bool) {
	s := rec.summary()
	if fellBack {
		_, _ = fmt.Fprintln(out, "No platform key provider is available; the key is kept in the encrypted credential store instead.")
	}
	_, _ = fmt.Fprintf(out, "Authenticator %q created (not yet registered with a controller)\n", s.Name)
	_, _ = fmt.Fprintf(out, "RP ID:         %s\n", s.RPID)
	_, _ = fmt.Fprintf(out, "Origin:        %s\n", s.Origin)
	_, _ = fmt.Fprintf(out, "Credential ID: %s\n", s.CredentialID)
	_, _ = fmt.Fprintf(out, "Protection:    %s\n", s.Protection)
	switch rec.Protection {
	case authenticatorProtectionPlatform:
		_, _ = fmt.Fprintf(out, "Private key:   held by %s as a per-user key that cannot be read out of it\n", rec.KeyProvider)
		if rec.KeyProvider == softwareKeyProviderName {
			_, _ = fmt.Fprintln(out, "Note:          the TPM could not hold the key, so the software provider holds it; it is protected by your Windows profile, not by hardware")
		}
	case authenticatorProtectionTPM:
		_, _ = fmt.Fprintf(out, "Private key:   held inside this machine's TPM; credential %q stores only TPM-wrapped blobs that work on this TPM alone\n",
			authenticatorCredentialName(rec.Name))
	default:
		_, _ = fmt.Fprintf(out, "Private key:   stored encrypted as credential %q; it is never displayed or exported\n",
			authenticatorCredentialName(rec.Name))
	}
}

func runAuthenticatorList(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Flags().GetBool("json")
	store, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("failed to open credential store: %w", err)
	}
	recs, err := listAuthenticatorRecords(context.Background(), store)
	if err != nil {
		return err
	}
	summaries := make([]authenticatorSummary, 0, len(recs))
	for _, r := range recs {
		summaries = append(summaries, r.summary())
	}

	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(summaries)
	}
	if len(summaries) == 0 {
		_, _ = fmt.Fprintln(out, "No software authenticators. Create one with 'cfg authenticator create <name> --url <controller URL>'.")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tRP ID\tORIGIN\tCREDENTIAL ID\tREGISTERED\tPROTECTION\tKEY PROVIDER")
	for _, s := range summaries {
		provider := s.KeyProvider
		if provider == "" {
			provider = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\t%s\n", s.Name, s.RPID, s.Origin, s.CredentialID, s.Registered, s.Protection, provider)
	}
	return tw.Flush()
}

// deleteAuthenticatorPlatformKey deletes the platform key the stored record
// names, if any. A key that cannot be deleted stops the delete, so the record
// that locates the key is kept; with force the record is deleted anyway and the
// key is left behind with a warning.
func deleteAuthenticatorPlatformKey(ctx context.Context, out io.Writer, store *CredentialStore, name string, force bool) error {
	rec, err := loadAuthenticatorRecord(ctx, store, name)
	if err != nil {
		_, _ = fmt.Fprintf(out, "Warning: the stored record could not be read, so any platform key it named was not deleted: %v\n", err)
		return nil
	}
	err = rec.deletePlatformKey()
	if err == nil {
		return nil
	}
	if !force {
		return fmt.Errorf("%w; the record was kept. 'cfg authenticator delete %s --force' deletes the record and leaves the platform key", err, name)
	}
	_, _ = fmt.Fprintf(out, "Warning: the platform key could not be deleted and is left in its provider: %v\n", err)
	return nil
}

func runAuthenticatorDelete(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateAuthenticatorName(name); err != nil {
		return err
	}
	force, _ := cmd.Flags().GetBool("force")
	ctx := context.Background()
	store, err := newCredentialStore()
	if err != nil {
		return fmt.Errorf("failed to open credential store: %w", err)
	}
	// Existence is checked, not decryptability: an unreadable record (for example an
	// unknown version) must still be deletable.
	exists, err := authenticatorExists(ctx, store, name)
	if err != nil {
		return err
	}
	if !exists {
		return notFoundAuthenticator(name)
	}
	if err := confirmDestructive(cmd,
		fmt.Sprintf("Delete authenticator %q? Its key cannot be recovered", name),
		force); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	// The platform key goes first: if deleting the record then fails, running
	// delete again finds the record and finishes, since an absent key is not an
	// error. A record that cannot be read is still deleted, but its platform key,
	// if it had one, cannot be located.
	if err := deleteAuthenticatorPlatformKey(ctx, out, store, name, force); err != nil {
		return err
	}
	if err := store.Delete(ctx, authenticatorCredentialName(name)); err != nil {
		return fmt.Errorf("failed to delete authenticator: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Authenticator %q deleted.\n", name)
	_, _ = fmt.Fprintln(out, "The controller still lists its credential until it is revoked: cfg webauthn revoke <credential-id>")
	return nil
}
