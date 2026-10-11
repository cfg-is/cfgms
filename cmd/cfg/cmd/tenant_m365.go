// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// m365Stdin is where --client-secret-stdin reads the secret; tests replace it.
var m365Stdin io.Reader = os.Stdin

var (
	m365AppID           string
	m365DirectoryTenant string
	m365PartnerTenant   string
	m365SecretStdin     bool
	m365Replace         bool
	m365Yes             bool
	m365Links           []string
	m365GDAPRoles       []string
)

var tenantM365Cmd = &cobra.Command{
	Use:   "m365",
	Short: "Connect client tenants to Microsoft 365",
	Long: `Connect a CFGMS client tenant to Microsoft 365, either directly or through a GDAP partner.

An M365 connection exists only on an existing client tenant: a tenant whose parent is an
MSP tenant. The root tenant, an MSP tenant, a tenant that does not exist and a tenant below
a client tenant are refused, and no command here creates a tenant.

A client secret is never accepted as a flag value. Pass --client-secret-stdin and write the
secret as one line on standard input. A confirm-gated command that reads the secret from
stdin has no terminal left to ask on, so it needs --yes.`,
}

var tenantM365SetCmd = &cobra.Command{
	Use:   "set <client-tenant>",
	Short: "Connect one client tenant to its own M365 directory (direct mode)",
	Long: `Store an application (client) ID, the client's M365 directory tenant ID and a client
secret as the M365 connection of one client tenant.

The secret is read as one line from stdin (--client-secret-stdin). A tenant that already
has a connection is refused unless --replace is set; --replace prints what it will change
and asks for confirmation (--yes skips the prompt; without a terminal and without --yes
the command refuses and exits non-zero).

Example:
  printf '%s\n' "$SECRET" | cfg tenant m365 set client-1 --app-id <id> --m365-tenant <directory-id> --client-secret-stdin`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantM365Set,
}

var tenantM365GetCmd = &cobra.Command{
	Use:   "get <client-tenant>",
	Short: "Show a client tenant's M365 connection (never the secret)",
	Args:  cobra.ExactArgs(1),
	RunE:  runTenantM365Get,
}

var tenantM365DeleteCmd = &cobra.Command{
	Use:   "delete <client-tenant>",
	Short: "Remove a client tenant's M365 connection and stored token",
	Long: `Remove the stored M365 connection and token of a client tenant.

It prints what it will remove and asks for confirmation. --yes skips the prompt; without a
terminal and without --yes the command refuses and exits non-zero.`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantM365Delete,
}

var tenantM365GDAPCustomersCmd = &cobra.Command{
	Use:   "gdap-customers <msp-tenant>",
	Short: "List an MSP's active GDAP customers and which client tenant each is linked to",
	Long: `List the active GDAP customer relationships of a partner tenant. LINKED TO shows the
client tenant of the MSP whose stored connection names the customer, or "unlinked".

The partner application's credentials are supplied on every call (--partner-tenant, --app-id
and the secret on stdin with --client-secret-stdin); nothing is stored by this command.

Example:
  printf '%s\n' "$SECRET" | cfg tenant m365 gdap-customers msp-a --partner-tenant <id> --app-id <id> --client-secret-stdin`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantM365GDAPCustomers,
}

var tenantM365GDAPLinkCmd = &cobra.Command{
	Use:   "gdap-link <msp-tenant>",
	Short: "Link GDAP customers to existing client tenants of an MSP",
	Long: `Link many GDAP customers to existing client tenants of one MSP in a single command.

Each --link is <customer-m365-tenant>=<client-tenant>. The request is validated as a whole
and nothing is written unless every link is valid: every target must be a client tenant of
the MSP, every customer must be in the partner's active GDAP list, no customer or target may
appear twice, no customer may already be linked to a different client tenant, and a target
that already has a connection is refused unless --replace is set.

The partner application's credentials are copied only into the connections of the client
tenants being linked. It prints the planned links and asks for confirmation (--yes skips the
prompt; without a terminal and without --yes the command refuses and exits non-zero).

Example:
  printf '%s\n' "$SECRET" | cfg tenant m365 gdap-link msp-a --partner-tenant <id> --app-id <id> \
    --client-secret-stdin --link <customer-1>=client-1 --link <customer-2>=client-2 --yes`,
	Args: cobra.ExactArgs(1),
	RunE: runTenantM365GDAPLink,
}

func init() {
	for _, c := range []*cobra.Command{tenantM365SetCmd, tenantM365GDAPCustomersCmd, tenantM365GDAPLinkCmd} {
		c.Flags().StringVar(&m365AppID, "app-id", "", "Application (client) ID (required)")
		_ = c.MarkFlagRequired("app-id")
		c.Flags().BoolVar(&m365SecretStdin, "client-secret-stdin", false, "Read the client secret as one line from stdin (required)")
	}
	tenantM365SetCmd.Flags().StringVar(&m365DirectoryTenant, "m365-tenant", "", "The client's M365 directory tenant ID (required)")
	_ = tenantM365SetCmd.MarkFlagRequired("m365-tenant")
	for _, c := range []*cobra.Command{tenantM365GDAPCustomersCmd, tenantM365GDAPLinkCmd} {
		c.Flags().StringVar(&m365PartnerTenant, "partner-tenant", "", "The partner's own M365 tenant ID (required)")
		_ = c.MarkFlagRequired("partner-tenant")
	}
	tenantM365GDAPLinkCmd.Flags().StringArrayVar(&m365Links, "link", nil, "<customer-m365-tenant>=<client-tenant>; repeat for each link (required)")
	_ = tenantM365GDAPLinkCmd.MarkFlagRequired("link")
	tenantM365GDAPLinkCmd.Flags().StringArrayVar(&m365GDAPRoles, "gdap-role", nil, "GDAP role the relationship must grant; repeatable")
	for _, c := range []*cobra.Command{tenantM365SetCmd, tenantM365GDAPLinkCmd} {
		c.Flags().BoolVar(&m365Replace, "replace", false, "Overwrite a connection the target already has")
	}
	for _, c := range []*cobra.Command{tenantM365SetCmd, tenantM365DeleteCmd, tenantM365GDAPLinkCmd} {
		c.Flags().BoolVarP(&m365Yes, "yes", "y", false, "Skip the confirmation prompt")
	}
	for _, c := range []*cobra.Command{tenantM365SetCmd, tenantM365GetCmd, tenantM365DeleteCmd, tenantM365GDAPCustomersCmd, tenantM365GDAPLinkCmd} {
		c.Flags().BoolVar(&tenantJSONOutput, "json", false, "Emit the response data as received instead of human-readable text")
		tenantM365Cmd.AddCommand(c)
	}
	tenantCmd.AddCommand(tenantM365Cmd)
}

// --- API client ---

// APIM365Connection is the secret-free view of a stored M365 connection.
type APIM365Connection struct {
	TenantID        string   `json:"tenant_id"`
	Mode            string   `json:"mode"`
	AppID           string   `json:"app_id"`
	M365TenantID    string   `json:"m365_tenant_id"`
	PartnerTenantID string   `json:"partner_tenant_id"`
	GDAPRoles       []string `json:"gdap_roles"`
	HasClientSecret bool     `json:"has_client_secret"`
}

// APIM365GDAPCustomer is one row of the GDAP customer list.
type APIM365GDAPCustomer struct {
	CustomerTenantID string `json:"customer_tenant_id"`
	Name             string `json:"name"`
	Status           string `json:"status"`
	ExpiresAt        string `json:"expires_at"`
	LinkState        string `json:"link_state"`
	LinkedTo         string `json:"linked_to"`
}

// APIM365Link is one customer-to-client-tenant link.
type APIM365Link struct {
	CustomerTenantID string `json:"customer_tenant_id"`
	TenantID         string `json:"tenant_id"`
}

// m365Request sends body (when non-nil) and returns the response's data payload as
// the server sent it. Any non-200 status becomes an error naming the server's code.
func (c *APIClient) m365Request(ctx context.Context, method, path string, body interface{}) (json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to encode request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	resp, err := c.doRequest(ctx, method, path, reader)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, m365ResponseError(resp)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return envelope.Data, nil
}

// m365APIError carries the server's error code so callers can branch on it.
type m365APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *m365APIError) Error() string {
	switch {
	case e.Message != "" && e.Code != "":
		return fmt.Sprintf("%s (%s)", e.Message, e.Code)
	case e.Message != "":
		return e.Message
	}
	return fmt.Sprintf("API error (status %d)", e.Status)
}

func m365ResponseError(resp *http.Response) error {
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return &m365APIError{Status: resp.StatusCode, Code: body.Error.Code, Message: body.Error.Message}
}

func m365ConnectionPath(tenantID string) string {
	return "/api/v1/tenants/" + url.PathEscape(tenantID) + "/m365-connection"
}

// PutM365ConnectionViaAPI sets a direct-mode connection on a client tenant.
func (c *APIClient) PutM365ConnectionViaAPI(ctx context.Context, tenantID string, body map[string]interface{}) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodPut, m365ConnectionPath(tenantID), body)
}

// GetM365ConnectionViaAPI reads a client tenant's connection.
func (c *APIClient) GetM365ConnectionViaAPI(ctx context.Context, tenantID string) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodGet, m365ConnectionPath(tenantID), nil)
}

// DeleteM365ConnectionViaAPI removes a client tenant's connection.
func (c *APIClient) DeleteM365ConnectionViaAPI(ctx context.Context, tenantID string) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodDelete, m365ConnectionPath(tenantID), nil)
}

// ListM365GDAPCustomersViaAPI lists an MSP's GDAP customers with their link state.
func (c *APIClient) ListM365GDAPCustomersViaAPI(ctx context.Context, mspID string, body map[string]interface{}) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodPost, "/api/v1/tenants/"+url.PathEscape(mspID)+"/m365-gdap-customers", body)
}

// LinkM365GDAPCustomersViaAPI links GDAP customers to client tenants of an MSP.
func (c *APIClient) LinkM365GDAPCustomersViaAPI(ctx context.Context, mspID string, body map[string]interface{}) (json.RawMessage, error) {
	return c.m365Request(ctx, http.MethodPost, "/api/v1/tenants/"+url.PathEscape(mspID)+"/m365-gdap-links", body)
}

// --- helpers ---

// readM365SecretFromStdin reads the client secret as one line from r.
func readM365SecretFromStdin(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("failed to read client secret from stdin: %w", err)
	}
	secret := strings.TrimRight(line, "\r\n")
	if secret == "" {
		return "", fmt.Errorf("no client secret on stdin: write the secret as one line")
	}
	return secret, nil
}

// m365SecretFromFlags requires --client-secret-stdin and reads the secret.
func m365SecretFromFlags() (string, error) {
	if !m365SecretStdin {
		return "", fmt.Errorf("--client-secret-stdin is required: the client secret is read from stdin and never accepted as a flag value")
	}
	return readM365SecretFromStdin(m365Stdin)
}

// parseM365Links parses repeated --link <customer>=<client-tenant> values.
func parseM365Links(values []string) ([]APIM365Link, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one --link <customer-m365-tenant>=<client-tenant> is required")
	}
	links := make([]APIM365Link, 0, len(values))
	for _, v := range values {
		cust, target, ok := strings.Cut(v, "=")
		cust, target = strings.TrimSpace(cust), strings.TrimSpace(target)
		if !ok || cust == "" || target == "" {
			return nil, fmt.Errorf("invalid --link %q: use <customer-m365-tenant>=<client-tenant>", v)
		}
		links = append(links, APIM365Link{CustomerTenantID: cust, TenantID: target})
	}
	return links, nil
}

func printM365Connection(c APIM365Connection) {
	fmt.Printf("tenant: %s\n", orDash(c.TenantID))
	fmt.Printf("mode: %s\n", orDash(c.Mode))
	fmt.Printf("app ID: %s\n", orDash(c.AppID))
	if c.Mode == "partner" {
		fmt.Printf("customer tenant: %s\n", orDash(c.M365TenantID))
		fmt.Printf("partner tenant: %s\n", orDash(c.PartnerTenantID))
		fmt.Printf("GDAP roles: %s\n", orDash(strings.Join(c.GDAPRoles, ", ")))
	} else {
		fmt.Printf("M365 tenant: %s\n", orDash(c.M365TenantID))
	}
	if c.HasClientSecret {
		fmt.Println("client secret: set")
	} else {
		fmt.Println("client secret: not set")
	}
}

func decodeM365(raw json.RawMessage, dst interface{}) error {
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

// --- commands ---

func runTenantM365Set(_ *cobra.Command, args []string) error {
	tenantID := args[0]
	secret, err := m365SecretFromFlags()
	if err != nil {
		return err
	}
	if m365Replace {
		if err := confirmCrossingAction(fmt.Sprintf(
			"This will replace the M365 connection of tenant %q with application %q on M365 tenant %q.",
			tenantID, m365AppID, m365DirectoryTenant), m365Yes); err != nil {
			return err
		}
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.PutM365ConnectionViaAPI(context.Background(), tenantID, map[string]interface{}{
		"app_id": m365AppID, "m365_tenant_id": m365DirectoryTenant, "client_secret": secret, "replace": m365Replace,
	})
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	var conn APIM365Connection
	if err := decodeM365(raw, &conn); err != nil {
		return err
	}
	fmt.Printf("M365 connection set on tenant %s\n", tenantID)
	printM365Connection(conn)
	return nil
}

func runTenantM365Get(_ *cobra.Command, args []string) error {
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.GetM365ConnectionViaAPI(context.Background(), args[0])
	if err != nil {
		var apiErr *m365APIError
		if errors.As(err, &apiErr) && apiErr.Code == "M365_CONNECTION_NOT_FOUND" {
			return fmt.Errorf("tenant %s has no M365 connection", args[0])
		}
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	var conn APIM365Connection
	if err := decodeM365(raw, &conn); err != nil {
		return err
	}
	printM365Connection(conn)
	return nil
}

func runTenantM365Delete(_ *cobra.Command, args []string) error {
	tenantID := args[0]
	if err := confirmCrossingAction(fmt.Sprintf(
		"This will remove the M365 connection and stored token of tenant %q.", tenantID), m365Yes); err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.DeleteM365ConnectionViaAPI(context.Background(), tenantID)
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	fmt.Printf("M365 connection removed from tenant %s\n", tenantID)
	return nil
}

func m365PartnerBody(secret string) map[string]interface{} {
	return map[string]interface{}{"partner_tenant_id": m365PartnerTenant, "app_id": m365AppID, "client_secret": secret}
}

func runTenantM365GDAPCustomers(_ *cobra.Command, args []string) error {
	secret, err := m365SecretFromFlags()
	if err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	raw, err := client.ListM365GDAPCustomersViaAPI(context.Background(), args[0], m365PartnerBody(secret))
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	var data struct {
		Customers []APIM365GDAPCustomer `json:"customers"`
	}
	if err := decodeM365(raw, &data); err != nil {
		return err
	}
	renderM365GDAPCustomers(os.Stdout, data.Customers)
	return nil
}

// printableM365 drops control characters from server-supplied text so a hostile
// customer name cannot inject terminal escape sequences.
func printableM365(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

func renderM365GDAPCustomers(w io.Writer, rows []APIM365GDAPCustomer) {
	if len(rows) == 0 {
		_, _ = fmt.Fprintln(w, "no active GDAP customers")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CUSTOMER TENANT\tNAME\tSTATUS\tEXPIRES\tLINKED TO")
	for _, r := range rows {
		expires := r.ExpiresAt
		if t, err := time.Parse(time.RFC3339, r.ExpiresAt); err == nil {
			expires = t.UTC().Format("2006-01-02")
		}
		linked := "unlinked"
		if r.LinkState == "linked" && r.LinkedTo != "" {
			linked = r.LinkedTo
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", printableM365(r.CustomerTenantID), orDash(printableM365(r.Name)), orDash(printableM365(r.Status)), orDash(expires), printableM365(linked))
	}
	_ = tw.Flush()
}

func runTenantM365GDAPLink(_ *cobra.Command, args []string) error {
	mspID := args[0]
	links, err := parseM365Links(m365Links)
	if err != nil {
		return err
	}
	secret, err := m365SecretFromFlags()
	if err != nil {
		return err
	}
	var plan strings.Builder
	fmt.Fprintf(&plan, "This will link %d GDAP customer(s) of partner tenant %q to client tenants of %q:", len(links), m365PartnerTenant, mspID)
	for _, l := range links {
		fmt.Fprintf(&plan, "\n  %s -> %s", l.CustomerTenantID, l.TenantID)
	}
	if len(m365GDAPRoles) > 0 {
		fmt.Fprintf(&plan, "\nRequired GDAP roles: %s", strings.Join(m365GDAPRoles, ", "))
	}
	if m365Replace {
		plan.WriteString("\nExisting connections on these client tenants will be replaced.")
	}
	if err := confirmCrossingAction(plan.String(), m365Yes); err != nil {
		return err
	}
	client, err := crossingClient()
	if err != nil {
		return err
	}
	body := m365PartnerBody(secret)
	body["links"] = links
	body["gdap_roles"] = m365GDAPRoles
	body["replace"] = m365Replace
	raw, err := client.LinkM365GDAPCustomersViaAPI(context.Background(), mspID, body)
	if err != nil {
		return err
	}
	if tenantJSONOutput {
		fmt.Printf("%s\n", raw)
		return nil
	}
	var data struct {
		Linked []APIM365Link `json:"linked"`
	}
	if err := decodeM365(raw, &data); err != nil {
		return err
	}
	fmt.Printf("linked %d GDAP customer(s)\n", len(data.Linked))
	for _, l := range data.Linked {
		fmt.Printf("  %s -> %s\n", l.CustomerTenantID, l.TenantID)
	}
	return nil
}
