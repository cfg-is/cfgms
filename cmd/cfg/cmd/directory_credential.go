// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/spf13/cobra"
)

// One-time initial passwords (Issue #5559). The controller generates the password for
// an account a cfg declared and holds it until an admin reveals it. The reveal needs a
// passkey tap: the 401 step-up challenge is answered by the presence relay in
// stepup.go, then the request is retried. The password goes to stdout and nowhere else
// — never a file, shell history, the keychain or a log.

const credentialMaxResponseBytes = 1 << 20

var credentialIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

var directoryCredentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "List and reveal one-time initial passwords for new directory accounts",
	Long: `The controller generates the initial password for each account a cfg creates and
holds it until an admin reveals it. Each password can be revealed exactly once.

If the response to a reveal is lost, the password is lost with it: delete the account
and have it recreated.

Examples:
  cfg directory credential list
  cfg directory credential reveal 3f2a9c0e1b7d4e58a6c1d2e3f4a5b6c7`,
}

var directoryCredentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List pending initial passwords (never their values)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getDirectoryClient()
		if err != nil {
			return err
		}
		return runDirectoryCredentialList(context.Background(), cmd.OutOrStdout(), client, directoryCredentialOutput)
	},
}

var directoryCredentialRevealCmd = &cobra.Command{
	Use:   "reveal <id>",
	Short: "Reveal an initial password once (requires a passkey tap)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getDirectoryClient()
		if err != nil {
			return err
		}
		return runDirectoryCredentialReveal(context.Background(), cmd.OutOrStdout(), cmd.ErrOrStderr(), client, args[0])
	},
}

var directoryCredentialOutput string

func init() {
	directoryCredentialListCmd.Flags().StringVar(&directoryCredentialOutput, "output", directoryOutputTable, "Output format: table or json")
	directoryCredentialCmd.AddCommand(directoryCredentialListCmd, directoryCredentialRevealCmd)
	directoryCmd.AddCommand(directoryCredentialCmd)
}

// APIDirectoryCredential is one pending record as the list route returns it.
type APIDirectoryCredential struct {
	ID         string    `json:"id"`
	ResourceID string    `json:"resource_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func runDirectoryCredentialList(ctx context.Context, out io.Writer, client *APIClient, output string) error {
	if output != directoryOutputTable && output != directoryOutputJSON {
		return fmt.Errorf("--output must be %q or %q", directoryOutputTable, directoryOutputJSON)
	}
	body, err := directoryGet(ctx, client, "/api/v1/directory/credentials", nil)
	if err != nil {
		return err
	}
	var resp struct {
		Items []APIDirectoryCredential `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	if output == directoryOutputJSON {
		return writeDirectoryJSON(out, map[string]interface{}{"items": nonNil(resp.Items)})
	}
	if len(resp.Items) == 0 {
		directoryEmptyMessage(out, "pending credentials")
		return nil
	}
	rows := make([][]string, 0, len(resp.Items))
	for _, c := range resp.Items {
		rows = append(rows, []string{c.ID, c.ResourceID, directoryTime(c.CreatedAt), directoryTime(c.ExpiresAt)})
	}
	return writeDirectoryTable(out, []string{"ID", "RESOURCE_ID", "CREATED", "EXPIRES"}, rows)
}

// runDirectoryCredentialReveal reveals one password. The password is written to out
// only; the one-time warning goes to errOut so redirecting stdout keeps it clean.
func runDirectoryCredentialReveal(ctx context.Context, out, errOut io.Writer, client *APIClient, id string) error {
	if !credentialIDPattern.MatchString(id) {
		return errors.New("credential id must be 32 lowercase hex characters (see: cfg directory credential list)")
	}
	resp, err := client.doRequest(ctx, http.MethodPost, "/api/v1/directory/credentials/"+id+"/reveal", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, credentialMaxResponseBytes))
	if err != nil {
		// The reveal may have been consumed: say so rather than suggest a retry will work.
		return errors.New("the response was interrupted; if the controller already revealed the password it is lost: delete the account and have it recreated")
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return errors.New("credential not found")
	case http.StatusGone:
		return errors.New("this password is no longer available (already revealed, expired or lost): delete the account and have it recreated")
	case http.StatusConflict:
		return errors.New("a reveal of this credential is in progress; retry in a minute")
	default:
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error.Message == "" {
			return fmt.Errorf("credential reveal failed (status %d)", resp.StatusCode)
		}
		return fmt.Errorf("credential reveal failed (status %d): %s", resp.StatusCode, escapeControl(e.Error.Message))
	}

	var reveal struct {
		ResourceID string `json:"resource_id"`
		Password   string `json:"password"`
	}
	if err := json.Unmarshal(raw, &reveal); err != nil || reveal.Password == "" {
		return errors.New("the controller returned no password; it may be lost: delete the account and have it recreated")
	}
	if escapeControl(reveal.Password) != reveal.Password {
		return errors.New("the revealed password contains control characters and was not printed; it cannot be shown again")
	}
	directoryPrintf(errOut, "Initial password for %s. It is shown once and cannot be retrieved again; it is not saved anywhere.\n", escapeControl(reveal.ResourceID))
	directoryPrintf(out, "%s\n", reveal.Password)
	return nil
}
