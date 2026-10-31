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
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

const (
	// directoryAllCap is the most rows --all follows page tokens for. It bounds what one
	// invocation pulls from the controller; the command says so when it stops there.
	directoryAllCap = 10000
	// directoryMaxPageLimit is the largest page the directory API serves.
	directoryMaxPageLimit = 500
	// directoryMaxPages bounds the requests one --all invocation makes, so a server that
	// keeps returning empty pages with a token cannot hold the command forever.
	directoryMaxPages = 1000
	// directoryMaxResponseBytes bounds how much of one response is read: a full page of
	// 500 objects is far below it.
	directoryMaxResponseBytes = 32 << 20
)

var (
	directoryURL         string
	directoryTLSInsecure bool
	directoryServerName  string
)

// directoryCmd is the parent command: cfg directory ...
var directoryCmd = &cobra.Command{
	Use:   "directory",
	Short: "Read directory users and groups (Active Directory and Microsoft 365)",
	Long: `Read the directory users and groups the controller holds, and group membership.

Everything shown is served from the controller's stored state (the last sync), not from
the directory itself. Each object carries last_observed and stale.

Examples:
  cfg directory user list --source m365 --enabled
  cfg directory user show ad/jdoe
  cfg directory group show m365/3f2a --all
  cfg directory group changes ad/helpdesk --since 2026-10-01T00:00:00Z`,
}

func init() {
	directoryCmd.PersistentFlags().StringVar(&directoryURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
	directoryCmd.PersistentFlags().BoolVar(&directoryTLSInsecure, "tls-insecure", false, "Skip TLS verification (env: CFGMS_TLS_INSECURE)")
	directoryCmd.PersistentFlags().StringVar(&directoryServerName, "server-name", "", "Override TLS server name for certificate verification")
	rootCmd.AddCommand(directoryCmd)
}

// getDirectoryClient returns an API client for the directory commands.
func getDirectoryClient() (*APIClient, error) {
	apiURL := directoryURL
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	tlsInsecure := directoryTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	client, err := requireSessionOrBundleClient(apiURL, tlsInsecure, directoryServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	return client, nil
}

// directoryListFlags are the flags shared by the directory list, show and changes verbs.
type directoryListFlags struct {
	source    string
	query     string
	enabled   bool
	disabled  bool
	managed   bool
	limit     int
	limitSet  bool
	all       bool
	pageToken string
	output    string
	authority string
	// changes only
	since           string
	until           string
	member          string
	includeBaseline bool
}

// directoryOutput formats are the values --output accepts.
const (
	directoryOutputTable = "table"
	directoryOutputJSON  = "json"
)

func (f *directoryListFlags) validateOutput() error {
	switch f.output {
	case directoryOutputTable, directoryOutputJSON:
		return nil
	}
	return fmt.Errorf("invalid --output %q: use table or json", escapeControl(f.output))
}

func (f *directoryListFlags) validate() error {
	if err := f.validateOutput(); err != nil {
		return err
	}
	if f.limit < 1 || f.limit > directoryMaxPageLimit {
		return fmt.Errorf("--limit must be between 1 and %d", directoryMaxPageLimit)
	}
	if f.enabled && f.disabled {
		return errors.New("--enabled and --disabled cannot be used together")
	}
	if f.all && f.pageToken != "" {
		return errors.New("--all and --page-token cannot be used together")
	}
	if f.source != "" && f.source != "ad" && f.source != "m365" {
		return fmt.Errorf("invalid --source %q: use ad or m365", f.source)
	}
	return nil
}

// pageSize is the limit sent with each request. --all with no explicit --limit asks for
// the largest page, since the caller wants everything.
func (f *directoryListFlags) pageSize() int {
	if f.all && !f.limitSet {
		return directoryMaxPageLimit
	}
	return f.limit
}

func addDirectoryPagingFlags(c *cobra.Command, f *directoryListFlags, what string) {
	c.Flags().IntVar(&f.limit, "limit", 100, "Rows per page (1-500)")
	c.Flags().BoolVar(&f.all, "all", false, fmt.Sprintf("Follow page tokens until the end, up to %d %s", directoryAllCap, what))
	c.Flags().StringVar(&f.pageToken, "page-token", "", "Continue from the next-page token a previous call printed")
	c.Flags().StringVar(&f.output, "output", directoryOutputTable, "Output format: table or json")
}

// bindLimitSet records whether --limit was given, so --all can pick a larger page size.
func bindLimitSet(cmd *cobra.Command, f *directoryListFlags) {
	f.limitSet = cmd.Flags().Changed("limit")
}

// --- references ---

var directoryObjectIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// parseDirectoryRef splits <source>/<id>. A malformed reference is refused before any
// request is made.
func parseDirectoryRef(arg string) (source, id string, err error) {
	source, id, ok := strings.Cut(arg, "/")
	if !ok || (source != "ad" && source != "m365") || id == "." || id == ".." || !directoryObjectIDPattern.MatchString(id) {
		return "", "", fmt.Errorf("invalid reference %q: use <source>/<id> where source is ad or m365", escapeControl(arg))
	}
	return source, id, nil
}

// --- API field set (Issue #5557) ---
//
// These types carry exactly the JSON fields the directory API returns, under the same
// names, so table and JSON output expose the API's field set and nothing is renamed.

// APIDirectoryObject is a directory user or group.
type APIDirectoryObject struct {
	Source            string              `json:"source"`
	Kind              string              `json:"kind"`
	ID                string              `json:"id"`
	Authority         string              `json:"authority"`
	DisplayName       string              `json:"display_name,omitempty"`
	SamAccountName    string              `json:"sam_account_name,omitempty"`
	UserPrincipalName string              `json:"user_principal_name,omitempty"`
	Mail              string              `json:"mail,omitempty"`
	Description       string              `json:"description,omitempty"`
	Enabled           *bool               `json:"enabled,omitempty"`
	Managed           bool                `json:"managed"`
	LastObserved      time.Time           `json:"last_observed"`
	Stale             bool                `json:"stale"`
	Groups            []APIDirectoryGroup `json:"groups,omitempty"`
	GroupsTruncated   bool                `json:"groups_truncated,omitempty"`
}

// APIDirectoryGroup is a group reference on a user.
type APIDirectoryGroup struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
}

// APIDirectoryMember is one direct member of a group.
type APIDirectoryMember struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name,omitempty"`
}

// APIDirectoryChange is one membership change event.
type APIDirectoryChange struct {
	Group      string    `json:"group"`
	Member     string    `json:"member"`
	MemberType string    `json:"member_type"`
	Op         string    `json:"op"`
	ObservedAt time.Time `json:"observed_at"`
	RecordedAt time.Time `json:"recorded_at"`
	Source     string    `json:"source"`
	Baseline   bool      `json:"baseline"`
}

// --- requests ---

// directoryGet issues one GET and returns the raw body of a 200. A 404 is the neutral
// "not found" — the same answer for an object that does not exist and one the caller may
// not see, and never a hint about which tenant owns it.
func directoryGet(ctx context.Context, client *APIClient, path string, q url.Values) ([]byte, error) {
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	resp, err := client.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(io.LimitReader(resp.Body, directoryMaxResponseBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		return body, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("not found")
	}
	var body struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	msg := escapeControl(body.Error.Message)
	if msg == "" {
		return nil, fmt.Errorf("directory request failed (status %d)", resp.StatusCode)
	}
	return nil, fmt.Errorf("directory request failed (status %d): %s", resp.StatusCode, msg)
}

// directoryResult is the outcome of reading a list route.
type directoryResult[T any] struct {
	items []T
	// next is the token for the page after the last one returned; empty at the end.
	next string
	// capped is true when --all stopped at directoryAllCap with more remaining.
	capped bool
}

// directoryFetch reads one page of a list route, or with all set follows next_page_token
// until the end or directoryAllCap rows. key names the array in the response.
func directoryFetch[T any](ctx context.Context, client *APIClient, path, key string, base url.Values, f *directoryListFlags) (*directoryResult[T], error) {
	res := &directoryResult[T]{}
	token := f.pageToken
	size := f.pageSize()
	for pages := 0; ; pages++ {
		q := url.Values{}
		for k, v := range base {
			q[k] = v
		}
		q.Set("limit", strconv.Itoa(size))
		if token != "" {
			q.Set("page_token", token)
		}
		body, err := directoryGet(ctx, client, path, q)
		if err != nil {
			return nil, err
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		var items []T
		if raw, ok := page[key]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, fmt.Errorf("failed to decode response: %w", err)
			}
		}
		res.items = append(res.items, items...)
		var next string
		if raw, ok := page["next_page_token"]; ok {
			if err := json.Unmarshal(raw, &next); err != nil {
				return nil, fmt.Errorf("failed to decode response: %w", err)
			}
		}
		res.next = next
		if !f.all || next == "" {
			return res, nil
		}
		if len(res.items) >= directoryAllCap {
			res.capped = true
			return res, nil
		}
		if next == token || pages+1 >= directoryMaxPages {
			return nil, errors.New("the controller kept returning page tokens without reaching the end; stopped")
		}
		token = next
		if remaining := directoryAllCap - len(res.items); remaining < size {
			size = remaining
		}
	}
}

// --- rendering ---

// directoryCell makes one value safe for a terminal. Directory strings are attacker-
// influenced (a display name or description is whatever the directory holds), so C0/C1
// control characters, ESC (and with it ANSI and OSC sequences) and line separators are
// rendered as visible escapes instead of reaching the terminal.
func directoryCell(s string) string {
	s = escapeControl(s)
	s = strings.ReplaceAll(s, "\u2028", `\u2028`)
	s = strings.ReplaceAll(s, "\u2029", `\u2029`)
	if s == "" {
		return "-"
	}
	return s
}

func directoryPrintf(w io.Writer, format string, args ...interface{}) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func directoryBool(b bool) string { return strconv.FormatBool(b) }

func directoryTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func writeDirectoryJSON(w io.Writer, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode output: %w", err)
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// writeDirectoryTable prints header and rows with every cell made terminal-safe.
func writeDirectoryTable(w io.Writer, header []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = directoryCell(c)
		}
		_, _ = fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}

// writeDirectoryHint prints what to do next after a list: the continuation token of a
// single page, or the reason --all stopped.
func writeDirectoryHint(w io.Writer, next string, capped bool, count int) {
	switch {
	case capped:
		_, _ = fmt.Fprintf(w, "Stopped after %d rows (the --all cap is %d). More remain: continue with --page-token %s\n",
			count, directoryAllCap, escapeControl(next))
	case next != "":
		_, _ = fmt.Fprintf(w, "More results: --page-token %s (or --all)\n", escapeControl(next))
	}
}

func directoryEmptyMessage(w io.Writer, what string) {
	_, _ = fmt.Fprintf(w, "No %s found.\n", what)
}

// writeDirectoryFields prints an object as "name: value" lines under its API field names.
func writeDirectoryFields(w io.Writer, o *APIDirectoryObject) {
	line := func(name, val string) { _, _ = fmt.Fprintf(w, "%s: %s\n", name, directoryCell(val)) }
	line("source", o.Source)
	line("kind", o.Kind)
	line("id", o.ID)
	line("authority", o.Authority)
	line("display_name", o.DisplayName)
	line("sam_account_name", o.SamAccountName)
	line("user_principal_name", o.UserPrincipalName)
	line("mail", o.Mail)
	line("description", o.Description)
	if o.Enabled != nil {
		line("enabled", directoryBool(*o.Enabled))
	}
	line("managed", directoryBool(o.Managed))
	line("last_observed", directoryTime(o.LastObserved))
	line("stale", directoryBool(o.Stale))
}

// getDirectoryObject reads one user or group by reference.
func getDirectoryObject(ctx context.Context, client *APIClient, kindPath, ref, authority string) (*APIDirectoryObject, string, error) {
	source, id, err := parseDirectoryRef(ref)
	if err != nil {
		return nil, "", err
	}
	base := "/api/v1/directory/" + kindPath + "/" + source + "/" + id
	q := url.Values{}
	if authority != "" {
		q.Set("authority", authority)
	}
	body, err := directoryGet(ctx, client, base, q)
	if err != nil {
		return nil, "", err
	}
	var obj APIDirectoryObject
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, "", fmt.Errorf("failed to decode response: %w", err)
	}
	return &obj, base, nil
}
