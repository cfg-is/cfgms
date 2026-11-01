// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// configSourceStdin is where the repository token is read; tests replace it.
var configSourceStdin io.Reader = os.Stdin

var configSourceURL string

var tenantConfigSourceCmd = &cobra.Command{
	Use:   "config-source",
	Short: "Manage a tenant's git config source credential",
}

var tenantConfigSourceSetCredentialCmd = &cobra.Command{
	Use:   "set-credential <tenant-id>",
	Short: "Store a git access token bound to one repository URL",
	Long: `Store the access token for a tenant's git config source together with the repository
URL it is bound to. A second call replaces both.

The token is never accepted as a flag or argument. Write it as one line on standard input,
or run the command in a terminal and type it at the no-echo prompt. The command prints the
credential reference; it never prints the token.

After storing the credential, set these tenant metadata keys:
  config_source_credential = the printed credential reference
  config_source_url        = the same repository URL

Example:
  printf '%s\n' "$TOKEN" | cfg tenant config-source set-credential client-1 --url https://git.example.com/org/configs.git`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantConfigSourceSetCredential,
}

func init() {
	tenantConfigSourceSetCredentialCmd.Flags().StringVar(&configSourceURL, "url", "", "Repository URL the token is bound to (required)")
	_ = tenantConfigSourceSetCredentialCmd.MarkFlagRequired("url")
	tenantConfigSourceSetCredentialCmd.Flags().BoolVar(&tenantJSONOutput, "json", false, "Emit the response data as received instead of human-readable text")
	tenantConfigSourceCmd.AddCommand(tenantConfigSourceSetCredentialCmd)
	tenantCmd.AddCommand(tenantConfigSourceCmd)
}

// APIConfigSourceCredential is the response of the credential route; it never holds the token.
type APIConfigSourceCredential struct {
	CredentialRef      string `json:"credential_ref"`
	BoundRepositoryURL string `json:"bound_repository_url"`
}

// PutConfigSourceCredentialViaAPI stores the token and its repository binding for a tenant.
func (c *APIClient) PutConfigSourceCredentialViaAPI(ctx context.Context, tenantID, repoURL, token string) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodPut,
		"/api/v1/tenants/"+url.PathEscape(tenantID)+"/config-source/credential",
		map[string]string{"url": repoURL, "token": token})
}

// readConfigSourceToken reads the token from r: a no-echo prompt when r is the process's
// terminal, otherwise one line.
func readConfigSourceToken(r io.Reader) (string, error) {
	if f, ok := r.(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		fmt.Fprint(os.Stderr, "Token: ")
		b, err := term.ReadPassword(int(f.Fd())) // #nosec G115 -- file descriptors fit in int
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("failed to read token: %w", err)
		}
		if len(b) == 0 {
			return "", errors.New("no token entered")
		}
		return string(b), nil
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("failed to read token from stdin: %w", err)
	}
	token := strings.TrimRight(line, "\r\n")
	if token == "" {
		return "", errors.New("no token on stdin: write the token as one line")
	}
	return token, nil
}

func runTenantConfigSourceSetCredential(_ *cobra.Command, args []string) error {
	tenantID := args[0]
	if strings.TrimSpace(configSourceURL) == "" {
		return errors.New("--url is required")
	}
	token, err := readConfigSourceToken(configSourceStdin)
	if err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.PutConfigSourceCredentialViaAPI(context.Background(), tenantID, configSourceURL, token)
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	var cred APIConfigSourceCredential
	if err := decodeM365(raw, &cred); err != nil {
		return err
	}
	fmt.Printf("Credential stored for tenant %s, bound to %s\n", tenantID, cred.BoundRepositoryURL)
	fmt.Printf("Set the tenant metadata config_source_credential to: %s\n", cred.CredentialRef)
	return nil
}
