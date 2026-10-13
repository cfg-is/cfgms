// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// Operator verbs for a detected identity clone (ADR-034 §5): list the clones the
// controller has detected, rotate-and-revoke the original's credentials, or move
// the identity to the queued copy. Split and removal of a queued copy are the
// existing `cfg registration approve|deny`.

var (
	stewardClonesFormat string
	stewardMoveIdentTo  string
)

// APIIdentityCloneCopy is a queued registration that reported being a copy.
type APIIdentityCloneCopy struct {
	PendingID    string    `json:"pending_id"`
	Hostname     string    `json:"hostname"`
	SourceIP     string    `json:"source_ip"`
	RegisteredAt time.Time `json:"registered_at"`
}

// APIIdentityClone is the evidence for one steward ID with a detected copy.
type APIIdentityClone struct {
	StewardID       string                 `json:"steward_id"`
	TenantID        string                 `json:"tenant_id"`
	FirstDetected   *time.Time             `json:"first_detected,omitempty"`
	LastDetected    *time.Time             `json:"last_detected,omitempty"`
	DetectionCount  int                    `json:"detection_count"`
	ExistingPeer    string                 `json:"existing_peer,omitempty"`
	OtherPeer       string                 `json:"other_peer,omitempty"`
	Serials         []string               `json:"serials,omitempty"`
	DivergentFields []string               `json:"divergent_fields,omitempty"`
	QueuedCopies    []APIIdentityCloneCopy `json:"queued_copies"`
}

// APIRotateCredentialsResponse is the result of a rotate-and-revoke.
type APIRotateCredentialsResponse struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	RevokedSerials []string `json:"revoked_serials"`
	NextStep       string   `json:"next_step"`
}

// APIMoveIdentityResponse is the result of an identity move.
type APIMoveIdentityResponse struct {
	ID             string   `json:"id"`
	PendingID      string   `json:"pending_id"`
	Status         string   `json:"status"`
	RevokedSerials []string `json:"revoked_serials"`
	NextStep       string   `json:"next_step"`
}

// identityVerbError turns a non-2xx API response into an operator-readable error.
func identityVerbError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error.Message != "" {
		return fmt.Errorf("%s: %s", resp.Status, env.Error.Message)
	}
	return fmt.Errorf("API request failed: %s - %s", resp.Status, strings.TrimSpace(string(body)))
}

func identityVerbDo(ctx context.Context, c *APIClient, method, path string, payload interface{}, out interface{}) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	resp, err := c.doRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return identityVerbError(resp)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

// ListIdentityClones calls GET /api/v1/stewards/identity-clones.
func (c *APIClient) ListIdentityClones(ctx context.Context) ([]APIIdentityClone, error) {
	var out struct {
		Clones []APIIdentityClone `json:"clones"`
	}
	if err := identityVerbDo(ctx, c, http.MethodGet, "/api/v1/stewards/identity-clones", nil, &out); err != nil {
		return nil, err
	}
	return out.Clones, nil
}

// RotateStewardCredentials calls POST /api/v1/stewards/{id}/credentials/rotate.
func (c *APIClient) RotateStewardCredentials(ctx context.Context, stewardID string) (*APIRotateCredentialsResponse, error) {
	var out APIRotateCredentialsResponse
	path := "/api/v1/stewards/" + url.PathEscape(stewardID) + "/credentials/rotate"
	if err := identityVerbDo(ctx, c, http.MethodPost, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MoveStewardIdentity calls POST /api/v1/stewards/{id}/identity/move.
func (c *APIClient) MoveStewardIdentity(ctx context.Context, stewardID, pendingID string) (*APIMoveIdentityResponse, error) {
	var out APIMoveIdentityResponse
	path := "/api/v1/stewards/" + url.PathEscape(stewardID) + "/identity/move"
	if err := identityVerbDo(ctx, c, http.MethodPost, path, map[string]string{"pending_id": pendingID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// confirmIdentityAction asks the operator to confirm a destructive single-steward
// action. --yes skips the prompt; a non-interactive stdin without --yes fails
// closed rather than blocking on a hidden pipe.
func confirmIdentityAction(summary string, yes bool) error {
	if yes {
		return nil
	}
	fmt.Fprintln(os.Stderr, summary)
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return fmt.Errorf("this action is destructive; pass --yes/-y to confirm, or run interactively")
	}
	fmt.Fprint(os.Stderr, "Proceed? [y/N]: ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer == "y" || answer == "yes" {
			return nil
		}
	}
	return fmt.Errorf("aborted by operator")
}

var stewardClonesCmd = &cobra.Command{
	Use:   "clones",
	Short: "Inspect identities that appear to have been copied to a second machine",
}

var stewardClonesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List detected identity clones and their queued copies",
	Long: `List every steward ID the controller has detected on two machines (ADR-034).

For each steward the listing shows the first and last detection time, the peer
address of the machine that already held the identity and of the other one, and
every queued registration that reported being a copy of it (pending ID, hostname).
Provenance fields that differ are reported by name only, never by value.

Decide which machine is the original, then use:
  cfg registration approve <pending-id>       keep both: the copy becomes its own steward
  cfg registration deny <pending-id>          remove the copy
  cfg steward rotate-credentials <steward-id> revoke the original's credentials
  cfg steward move-identity <steward-id> --to <pending-id>  the copy is the real one`,
	Args: cobra.NoArgs,
	RunE: runStewardClonesList,
}

func runStewardClonesList(_ *cobra.Command, _ []string) error {
	if stewardClonesFormat != "" && stewardClonesFormat != "table" && stewardClonesFormat != "json" {
		return fmt.Errorf("unsupported --format %q (use table or json)", stewardClonesFormat)
	}
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	clones, err := client.ListIdentityClones(context.Background())
	if err != nil {
		return err
	}
	if stewardClonesFormat == "json" {
		if clones == nil {
			clones = []APIIdentityClone{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(clones)
	}
	if len(clones) == 0 {
		fmt.Println("No identity clones detected.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "STEWARD\tDETECTED\tLAST SEEN\tEXISTING PEER\tOTHER PEER\tQUEUED COPY\tHOSTNAME")
	for _, c := range clones {
		copies := c.QueuedCopies
		if len(copies) == 0 {
			copies = []APIIdentityCloneCopy{{}}
		}
		for _, q := range copies {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				c.StewardID, cloneTime(c.FirstDetected), cloneTime(c.LastDetected),
				dash(c.ExistingPeer), dash(c.OtherPeer), dash(q.PendingID), dash(q.Hostname))
		}
	}
	return w.Flush()
}

func cloneTime(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

var stewardRotateCredentialsCmd = &cobra.Command{
	Use:   "rotate-credentials <steward-id>",
	Short: "Revoke a steward's certificates and require approval for its next refresh",
	Long: `Revoke every client certificate issued for the steward ID and set the record to
archived, so the next refresh is queued for approval regardless of policy.

The certificate stored on the approved machine is refused immediately, including
on streams that are already open. That machine re-admits with its device key;
complete the rotation with 'cfg refresh approve <pending-id>'. A copy that does
not hold the device key cannot complete the handshake.

With a FILE-backed device key a copy that holds the key can also file a refresh
request, so approve only after checking the machine. Hardware-backed keys remove
that case. Requires strong assurance (admin mTLS or a passkey-elevated session).`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardRotateCredentials,
}

func runStewardRotateCredentials(_ *cobra.Command, args []string) error {
	stewardID := args[0]
	if err := confirmIdentityAction(fmt.Sprintf(
		"This revokes every certificate issued for steward %s and archives its record.", stewardID), stewardYes); err != nil {
		return err
	}
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	res, err := client.RotateStewardCredentials(context.Background(), stewardID)
	if err != nil {
		return err
	}
	fmt.Printf("Steward %s credentials rotated; record status: %s.\n", res.ID, res.Status)
	if len(res.RevokedSerials) == 0 {
		fmt.Println("Revoked serials: none issued by this controller.")
	} else {
		fmt.Println("Revoked serials:")
		for _, s := range res.RevokedSerials {
			fmt.Printf("  %s\n", s)
		}
	}
	fmt.Printf("Next: %s\n", res.NextStep)
	return nil
}

var stewardMoveIdentityCmd = &cobra.Command{
	Use:   "move-identity <steward-id> --to <pending-id>",
	Short: "Move a steward identity to the queued copy on the other machine",
	Long: `Use when the machine that kept the identity is the wrong one.

The steward record is rebound to the queued machine's device identity (the
provenance baseline is cleared so it re-baselines), the queued registration is
pointed at the original steward ID and approved, and every certificate previously
issued for that ID is revoked. The queued machine then claims its registration
under the original steward ID on its next poll.

The queued registration must be a pending copy of <steward-id> in the same tenant
(see 'cfg steward clones list'). Nothing moves an identity automatically.
Requires strong assurance (admin mTLS or a passkey-elevated session).`,
	Args: cobra.ExactArgs(1),
	RunE: runStewardMoveIdentity,
}

func runStewardMoveIdentity(_ *cobra.Command, args []string) error {
	stewardID := args[0]
	if strings.TrimSpace(stewardMoveIdentTo) == "" {
		return fmt.Errorf("--to <pending-id> is required")
	}
	if err := confirmIdentityAction(fmt.Sprintf(
		"This moves steward %s to queued registration %s and revokes the certificates of the machine that holds it now.",
		stewardID, stewardMoveIdentTo), stewardYes); err != nil {
		return err
	}
	client, err := getStewardClient()
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	res, err := client.MoveStewardIdentity(context.Background(), stewardID, stewardMoveIdentTo)
	if err != nil {
		return err
	}
	fmt.Printf("Steward %s moved to queued registration %s (%s).\n", res.ID, res.PendingID, res.Status)
	if len(res.RevokedSerials) > 0 {
		fmt.Println("Revoked serials:")
		for _, s := range res.RevokedSerials {
			fmt.Printf("  %s\n", s)
		}
	}
	fmt.Printf("Next: %s\n", res.NextStep)
	return nil
}

func init() {
	for _, c := range []*cobra.Command{stewardClonesListCmd, stewardRotateCredentialsCmd, stewardMoveIdentityCmd} {
		c.Flags().StringVar(&stewardURL, "url", "", "Controller API URL")
		c.Flags().StringVar(&stewardTLSCACert, "tls-ca-cert", "", "Path to CA certificate (env: CFGMS_TLS_CA_CERT)")
		c.Flags().BoolVar(&stewardTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
		c.Flags().StringVar(&stewardServerName, "server-name", "", "Override TLS server name for certificate verification")
	}
	stewardClonesListCmd.Flags().StringVar(&stewardClonesFormat, "format", "table", "Output format: table or json")
	stewardMoveIdentityCmd.Flags().StringVar(&stewardMoveIdentTo, "to", "", "Pending registration ID of the queued copy that becomes the steward (required)")
	stewardClonesCmd.AddCommand(stewardClonesListCmd)
	stewardCmd.AddCommand(stewardClonesCmd)
	stewardCmd.AddCommand(stewardRotateCredentialsCmd)
	stewardCmd.AddCommand(stewardMoveIdentityCmd)
}
