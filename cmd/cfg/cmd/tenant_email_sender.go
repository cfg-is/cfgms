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
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// emailSenderStdin is where --password-stdin reads the password; tests replace it.
var emailSenderStdin io.Reader = os.Stdin

var (
	emailSenderHost          string
	emailSenderPort          int
	emailSenderTLSMode       string
	emailSenderFrom          string
	emailSenderUsername      string
	emailSenderPasswordStdin bool
	emailSenderYes           bool
)

var tenantEmailSenderCmd = &cobra.Command{
	Use:   "email-sender",
	Short: "Manage an MSP's own email sender",
	Long: `Manage the SMTP sender an MSP tenant uses for its operational mail. The sender exists
only on an MSP tenant; any other tenant is reported as not found.

The SMTP password is never accepted as a flag value. Pass --password-stdin and write the
password as one line on standard input, or run 'set' in a terminal and type it at the
no-echo prompt. No command here prints the password.`,
}

var tenantEmailSenderShowCmd = &cobra.Command{
	Use:   "show <msp-tenant>",
	Short: "Show an MSP's email sender settings (never the password)",
	Long: `Show the host, port, TLS mode, from-address and username of an MSP's email sender, and
whether a password is stored ("password: present" or "password: absent").`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantEmailSenderShow,
}

var tenantEmailSenderSetCmd = &cobra.Command{
	Use:   "set <msp-tenant>",
	Short: "Set or replace an MSP's email sender",
	Long: `Set or replace the email sender of an MSP tenant. The request replaces every setting,
so pass all the settings you want to keep.

The password is read as one line from stdin (--password-stdin), or typed at a no-echo
prompt when no flag is given and stdin is a terminal. When the MSP already has a stored
password, leaving it out (no --password-stdin, or an empty entry at the prompt) keeps the
stored one. A first-time sender needs a password.

Example:
  printf '%s\n' "$SMTP_PASSWORD" | cfg tenant email-sender set msp-a --host smtp.example.com --port 587 \
    --tls-mode starttls --from alerts@msp-a.example.com --username alerts --password-stdin`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantEmailSenderSet,
}

var tenantEmailSenderRemoveCmd = &cobra.Command{
	Use:   "remove <msp-tenant>",
	Short: "Remove an MSP's email sender and its stored password",
	Long: `Remove the email sender and the stored password of an MSP tenant. Mail for the MSP then
falls back to the platform sender.

It prints what it will remove and asks for confirmation. --yes skips the prompt; without a
terminal and without --yes the command refuses and exits non-zero.`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantEmailSenderRemove,
}

var tenantEmailSenderTestCmd = &cobra.Command{
	Use:   "test <msp-tenant>",
	Short: "Send one test message through an MSP's email sender",
	Long: `Send one fixed test message to the sender's own from-address through the MSP's sender, and
print each recipient as accepted or rejected, followed by the failure reason if there is one.
The recipient and the content cannot be changed. The command exits non-zero when the message
was not delivered.`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantEmailSenderTest,
}

func init() {
	f := tenantEmailSenderSetCmd.Flags()
	f.StringVar(&emailSenderHost, "host", "", "SMTP server host name (required)")
	_ = tenantEmailSenderSetCmd.MarkFlagRequired("host")
	f.IntVar(&emailSenderPort, "port", 0, "SMTP server port; 0 uses the server default")
	f.StringVar(&emailSenderTLSMode, "tls-mode", "", "TLS mode: starttls or implicit_tls (default starttls)")
	f.StringVar(&emailSenderFrom, "from", "", "From-address, a bare address (required)")
	_ = tenantEmailSenderSetCmd.MarkFlagRequired("from")
	f.StringVar(&emailSenderUsername, "username", "", "SMTP username")
	f.BoolVar(&emailSenderPasswordStdin, "password-stdin", false, "Read the SMTP password as one line from stdin")
	tenantEmailSenderRemoveCmd.Flags().BoolVarP(&emailSenderYes, "yes", "y", false, "Skip the confirmation prompt")
	for _, c := range []*cobra.Command{tenantEmailSenderShowCmd, tenantEmailSenderSetCmd, tenantEmailSenderRemoveCmd, tenantEmailSenderTestCmd} {
		c.Flags().BoolVar(&tenantJSONOutput, "json", false, "Emit the response data as received instead of human-readable text")
		tenantEmailSenderCmd.AddCommand(c)
	}
	tenantCmd.AddCommand(tenantEmailSenderCmd)
}

// --- API client ---

// APIEmailSender is the password-free view of an MSP's email sender.
type APIEmailSender struct {
	Configured      bool   `json:"configured"`
	PasswordPresent bool   `json:"password_present"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	TLSMode         string `json:"tls_mode"`
	From            string `json:"from"`
	Username        string `json:"username"`
}

// APIEmailTestRecipient is one recipient of a test send.
type APIEmailTestRecipient struct {
	Address  string `json:"address"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason"`
}

// APIEmailTestResult is the response of the test-send route.
type APIEmailTestResult struct {
	Delivered     bool                    `json:"delivered"`
	Recipients    []APIEmailTestRecipient `json:"recipients"`
	FailureReason string                  `json:"failure_reason"`
}

func emailSenderPath(mspID string) string {
	return "/api/v1/tenants/" + url.PathEscape(mspID) + "/email-sender"
}

// GetEmailSenderViaAPI reads an MSP's email sender.
func (c *APIClient) GetEmailSenderViaAPI(ctx context.Context, mspID string) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodGet, emailSenderPath(mspID), nil)
}

// PutEmailSenderViaAPI sets or replaces an MSP's email sender.
func (c *APIClient) PutEmailSenderViaAPI(ctx context.Context, mspID string, body map[string]interface{}) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodPut, emailSenderPath(mspID), body)
}

// DeleteEmailSenderViaAPI removes an MSP's email sender and password.
func (c *APIClient) DeleteEmailSenderViaAPI(ctx context.Context, mspID string) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodDelete, emailSenderPath(mspID), nil)
}

// TestEmailSenderViaAPI sends the fixed test message through an MSP's email sender.
func (c *APIClient) TestEmailSenderViaAPI(ctx context.Context, mspID string) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodPost, emailSenderPath(mspID)+"/test", nil)
}

// --- helpers ---

// readEmailSenderPassword reads the password from r: a no-echo prompt when r is the
// process's terminal, otherwise one line. An empty entry returns "" without error
// only at the prompt, where it means "keep the stored password".
func readEmailSenderPassword(r io.Reader, promptOnly bool) (string, error) {
	if f, ok := r.(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		fmt.Fprint(os.Stderr, "SMTP password (empty keeps the stored password): ")
		b, err := term.ReadPassword(int(f.Fd())) // #nosec G115 -- file descriptors fit in int
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", errors.New("failed to read password")
		}
		return string(b), nil
	}
	if promptOnly {
		return "", nil
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("failed to read password from stdin")
	}
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", errors.New("no password on stdin: write the password as one line")
	}
	return password, nil
}

// emailSenderPasswordFromFlags returns the password to send, or "" to keep the stored
// one. Without --password-stdin it only prompts when stdin is a terminal.
func emailSenderPasswordFromFlags() (string, error) {
	return readEmailSenderPassword(emailSenderStdin, !emailSenderPasswordStdin)
}

func emailSenderYesNo(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}

func printEmailSender(w io.Writer, tenantID string, s APIEmailSender) {
	port := "-"
	if s.Port != 0 {
		port = strconv.Itoa(s.Port)
	}
	configured := "no"
	if s.Configured {
		configured = "yes"
	}
	_, _ = fmt.Fprintf(w, "tenant: %s\n", printableM365(tenantID))
	_, _ = fmt.Fprintf(w, "configured: %s\n", configured)
	_, _ = fmt.Fprintf(w, "host: %s\n", orDash(printableM365(s.Host)))
	_, _ = fmt.Fprintf(w, "port: %s\n", port)
	_, _ = fmt.Fprintf(w, "TLS mode: %s\n", orDash(printableM365(s.TLSMode)))
	_, _ = fmt.Fprintf(w, "from: %s\n", orDash(printableM365(s.From)))
	_, _ = fmt.Fprintf(w, "username: %s\n", orDash(printableM365(s.Username)))
	_, _ = fmt.Fprintf(w, "password: %s\n", emailSenderYesNo(s.PasswordPresent))
}

// renderEmailTestResult prints each recipient as accepted or rejected, then the
// failure reason when there is one.
func renderEmailTestResult(w io.Writer, res APIEmailTestResult) {
	if len(res.Recipients) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "RECIPIENT\tRESULT\tREASON")
		for _, r := range res.Recipients {
			result := "rejected"
			if r.Accepted {
				result = "accepted"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", printableM365(r.Address), result, orDash(printableM365(r.Reason)))
		}
		_ = tw.Flush()
	}
	if res.FailureReason != "" {
		_, _ = fmt.Fprintf(w, "failure: %s\n", printableM365(res.FailureReason))
	}
}

// --- commands ---

func runTenantEmailSenderShow(_ *cobra.Command, args []string) error {
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.GetEmailSenderViaAPI(context.Background(), args[0])
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	var s APIEmailSender
	if err := decodeM365(raw, &s); err != nil {
		return err
	}
	printEmailSender(os.Stdout, args[0], s)
	return nil
}

func runTenantEmailSenderSet(_ *cobra.Command, args []string) error {
	tenantID := args[0]
	password, err := emailSenderPasswordFromFlags()
	if err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.PutEmailSenderViaAPI(context.Background(), tenantID, map[string]interface{}{
		"host": emailSenderHost, "port": emailSenderPort, "tls_mode": emailSenderTLSMode,
		"from": emailSenderFrom, "username": emailSenderUsername, "password": password,
	})
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	var s APIEmailSender
	if err := decodeM365(raw, &s); err != nil {
		return err
	}
	fmt.Printf("Email sender set on tenant %s\n", tenantID)
	printEmailSender(os.Stdout, tenantID, s)
	return nil
}

func runTenantEmailSenderRemove(_ *cobra.Command, args []string) error {
	tenantID := args[0]
	if err := confirmCrossingAction(fmt.Sprintf(
		"This will remove the email sender and stored password of tenant %q; its mail falls back to the platform sender.", tenantID), emailSenderYes); err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.DeleteEmailSenderViaAPI(context.Background(), tenantID)
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	fmt.Printf("Email sender removed from tenant %s\n", tenantID)
	return nil
}

func runTenantEmailSenderTest(_ *cobra.Command, args []string) error {
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.TestEmailSenderViaAPI(context.Background(), args[0])
	if err != nil {
		return err
	}
	var res APIEmailTestResult
	if err := decodeM365(raw, &res); err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
	} else {
		renderEmailTestResult(os.Stdout, res)
	}
	if !res.Delivered {
		return errors.New("test message was not delivered")
	}
	if !tenantJSONOutput {
		fmt.Println("test message delivered")
	}
	return nil
}
