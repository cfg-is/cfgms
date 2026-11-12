// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cfgis/cfgms/pkg/cert"
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

Each key is stored only in the encrypted credential store (credential name
authenticator.<name>). It is never printed or written anywhere else.
The key is readable by any process running as the same user on this machine,
so treat it as a credential of that user.

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
		Long: `Deletes the authenticator's key from the credential store. The key cannot be
recovered. This does not touch the controller: it still lists the credential
until it is revoked (cfg webauthn revoke <credential-id>).

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

// buildAuthenticatorRecord validates the create flags and returns a new record
// with a fresh key. It touches no file: a refusal must leave the credentials
// directory untouched, so the store (which creates the directory and key salt) is
// not opened until the record is known to be good.
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

	rec, err := newAuthenticatorRecord(name)
	if err != nil {
		return nil, err
	}
	rec.RPID = rpID
	rec.Origin = origin
	rec.ControllerURL = strings.TrimRight(u.String(), "/")
	rec.CACertPEM = caPEM
	rec.Label, _ = flags.GetString("label")
	// softauthn is the authority on whether the RP ID and origin are a valid pair.
	if _, err := rec.authenticator(); err != nil {
		return nil, err
	}
	return rec, nil
}

func runAuthenticatorCreate(cmd *cobra.Command, args []string) error {
	name := args[0]
	if err := validateAuthenticatorName(name); err != nil {
		return err
	}
	rec, err := buildAuthenticatorRecord(name, cmd.Flags())
	if err != nil {
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
	if err := saveAuthenticatorRecord(ctx, store, rec); err != nil {
		return err
	}

	s := rec.summary()
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Authenticator %q created (not yet registered with a controller)\n", s.Name)
	_, _ = fmt.Fprintf(out, "RP ID:         %s\n", s.RPID)
	_, _ = fmt.Fprintf(out, "Origin:        %s\n", s.Origin)
	_, _ = fmt.Fprintf(out, "Credential ID: %s\n", s.CredentialID)
	_, _ = fmt.Fprintf(out, "Private key:   stored encrypted as credential %q; it is never displayed or exported\n",
		authenticatorCredentialName(name))
	return nil
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
	_, _ = fmt.Fprintln(tw, "NAME\tRP ID\tORIGIN\tCREDENTIAL ID\tREGISTERED\tPROTECTION")
	for _, s := range summaries {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\n", s.Name, s.RPID, s.Origin, s.CredentialID, s.Registered, s.Protection)
	}
	return tw.Flush()
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
	if err := store.Delete(ctx, authenticatorCredentialName(name)); err != nil {
		return fmt.Errorf("failed to delete authenticator: %w", err)
	}
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Authenticator %q deleted.\n", name)
	_, _ = fmt.Fprintln(out, "The controller still lists its credential until it is revoked: cfg webauthn revoke <credential-id>")
	return nil
}
