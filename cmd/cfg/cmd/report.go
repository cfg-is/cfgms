// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	reportTemplatesPath = "/api/v1/reports/custom-templates"
	reportGeneratePath  = "/api/v1/reports/custom/generate"
	reportDataPath      = "/api/v1/reports/custom/data"
)

var (
	reportURL         string
	reportTLSInsecure bool
	reportServerName  string

	reportFile        string
	reportYes         bool
	reportShareWith   []string
	reportSharePerms  []string
	reportShareExpiry string

	reportStreamToken string
	reportPage        int
	reportPageSize    int
)

// reportCmd is the parent command for custom report operations.
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Manage custom report templates and run custom reports",
	Long: `Commands for custom report templates and custom reports.

The controller derives the tenant and author from your credential; the CLI never
sends them.`,
}

var reportTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage custom report templates",
}

var reportCustomCmd = &cobra.Command{
	Use:   "custom",
	Short: "Run custom reports and page through their data",
}

var reportTemplateListCmd = &cobra.Command{
	Use:   "list",
	Short: "List custom report templates accessible to your tenant",
	Args:  cobra.NoArgs,
	RunE:  runReportTemplateList,
}

var reportTemplateShowCmd = &cobra.Command{
	Use:   "show <template-id>",
	Short: "Show a custom report template",
	Args:  cobra.ExactArgs(1),
	RunE:  runReportTemplateShow,
}

var reportTemplateCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a custom report template from a JSON or YAML file",
	Long: `Create a custom report template from a definition file.

The file must not set tenant_id or created_by; the controller derives them.

Examples:
  cfg report template create --file template.yaml`,
	Args: cobra.NoArgs,
	RunE: runReportTemplateCreate,
}

var reportTemplateDeleteCmd = &cobra.Command{
	Use:   "delete <template-id>",
	Short: "Delete a custom report template",
	Args:  cobra.ExactArgs(1),
	RunE:  runReportTemplateDelete,
}

var reportTemplateShareCmd = &cobra.Command{
	Use:   "share <template-id>",
	Short: "Share a custom report template with other tenants",
	Long: `Share a template with one or more tenants.

Examples:
  cfg report template share <id> --with acme-corp --permission read --permission execute --expires-in 72h`,
	Args: cobra.ExactArgs(1),
	RunE: runReportTemplateShare,
}

var reportCustomRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Generate a custom report from a JSON or YAML definition file",
	Long: `Generate a custom report from a definition file.

The file must not set tenant_id or created_by; the controller derives them.

Examples:
  cfg report custom run --file report.json`,
	Args: cobra.NoArgs,
	RunE: runReportCustomRun,
}

var reportCustomPageCmd = &cobra.Command{
	Use:   "page",
	Short: "Fetch one page of a streamed custom report",
	Long: `Fetch a page of a streamed custom report using the stream token printed by
'cfg report custom run'.

Examples:
  cfg report custom page --stream-token <token> --page 2`,
	Args: cobra.NoArgs,
	RunE: runReportCustomPage,
}

func init() {
	leaves := []*cobra.Command{
		reportTemplateListCmd, reportTemplateShowCmd, reportTemplateCreateCmd,
		reportTemplateDeleteCmd, reportTemplateShareCmd, reportCustomRunCmd, reportCustomPageCmd,
	}
	for _, c := range leaves {
		c.Flags().StringVar(&reportURL, "url", "", "Controller API URL (env: CFGMS_API_URL)")
		c.Flags().BoolVar(&reportTLSInsecure, "tls-insecure", false, "Skip TLS verification (development only, env: CFGMS_TLS_INSECURE)")
		c.Flags().StringVar(&reportServerName, "server-name", "", "Override TLS server name for certificate verification")
	}

	for _, c := range []*cobra.Command{reportTemplateCreateCmd, reportCustomRunCmd} {
		c.Flags().StringVarP(&reportFile, "file", "f", "", "Path to a JSON or YAML definition file (required)")
		_ = c.MarkFlagRequired("file")
	}

	reportTemplateDeleteCmd.Flags().BoolVarP(&reportYes, "yes", "y", false, "Skip the confirmation prompt")

	reportTemplateShareCmd.Flags().StringArrayVar(&reportShareWith, "with", nil, "Tenant to share with (repeatable, required)")
	reportTemplateShareCmd.Flags().StringArrayVar(&reportSharePerms, "permission", nil, "Permission to grant: read, execute or modify (repeatable, required)")
	reportTemplateShareCmd.Flags().StringVar(&reportShareExpiry, "expires-in", "", "Share lifetime as a Go duration such as 72h (default: no expiry)")
	_ = reportTemplateShareCmd.MarkFlagRequired("with")
	_ = reportTemplateShareCmd.MarkFlagRequired("permission")

	reportCustomPageCmd.Flags().StringVar(&reportStreamToken, "stream-token", "", "Stream token from 'cfg report custom run' (required)")
	reportCustomPageCmd.Flags().IntVar(&reportPage, "page", 1, "Page number")
	reportCustomPageCmd.Flags().IntVar(&reportPageSize, "page-size", 0, "Rows per page (0 = controller default)")
	_ = reportCustomPageCmd.MarkFlagRequired("stream-token")

	reportTemplateCmd.AddCommand(reportTemplateListCmd, reportTemplateShowCmd, reportTemplateCreateCmd,
		reportTemplateDeleteCmd, reportTemplateShareCmd)
	reportCustomCmd.AddCommand(reportCustomRunCmd, reportCustomPageCmd)
	reportCmd.AddCommand(reportTemplateCmd, reportCustomCmd)
}

func getReportClient() (*APIClient, error) {
	apiURL := strings.TrimSuffix(reportURL, "/")
	if apiURL == "" {
		apiURL = os.Getenv("CFGMS_API_URL")
	}
	tlsInsecure := reportTLSInsecure
	if !tlsInsecure {
		tlsInsecure = os.Getenv("CFGMS_TLS_INSECURE") == "true"
	}
	client, err := requireSessionOrBundleClient(apiURL, tlsInsecure, reportServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	return client, nil
}

// reportControllerError extracts the controller's message from a non-2xx response.
func reportControllerError(resp *http.Response, what string) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	msg := strings.TrimSpace(string(raw))
	var env struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &env) == nil && len(env.Error) > 0 {
		var s string
		var o struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(env.Error, &s) == nil && s != "" {
			msg = s
		} else if json.Unmarshal(env.Error, &o) == nil && o.Message != "" {
			msg = o.Message
		}
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("%s failed (%s): %s", what, resp.Status, msg)
}

// reportDo sends one request and returns the body of a 2xx response.
func reportDo(method, path string, body interface{}, what string) ([]byte, http.Header, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	client, err := getReportClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.doRequest(context.Background(), method, path, reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%s failed: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, reportControllerError(resp, what)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response: %w", err)
	}
	return data, resp.Header, nil
}

// loadReportDefinition reads a JSON or YAML definition file and rejects keys the
// controller derives from the credential. It runs before any request is made.
func loadReportDefinition(path string) (map[string]interface{}, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied definition path
	if err != nil {
		return nil, fmt.Errorf("failed to read definition file: %w", err)
	}
	var def map[string]interface{}
	if err := yaml.Unmarshal(raw, &def); err != nil {
		return nil, fmt.Errorf("failed to parse definition file as JSON or YAML: %w", err)
	}
	if def == nil {
		return nil, fmt.Errorf("definition file %q is empty", path)
	}
	for _, key := range []string{"tenant_id", "created_by"} {
		if _, ok := def[key]; ok {
			return nil, fmt.Errorf("definition file must not set %q: the controller derives it from your credential", key)
		}
	}
	return def, nil
}

func reportJSONOutput() bool { return output == "json" }

func printReportJSON(data []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	fmt.Println(buf.String())
	return nil
}

func reportCell(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "-"
	case string:
		if t == "" {
			return "-"
		}
		return t
	case []interface{}, map[string]interface{}:
		b, _ := json.Marshal(t)
		return string(b)
	default:
		return fmt.Sprint(t)
	}
}

type reportTemplateRow struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	TenantID    string `json:"tenant_id"`
	IsShared    bool   `json:"is_shared"`
	UpdatedAt   string `json:"updated_at"`
	UsageCount  int    `json:"usage_count"`
}

func runReportTemplateList(_ *cobra.Command, _ []string) error {
	data, _, err := reportDo(http.MethodGet, reportTemplatesPath, nil, "list templates")
	if err != nil {
		return err
	}
	if reportJSONOutput() {
		return printReportJSON(data)
	}
	var env struct {
		Templates []reportTemplateRow `json:"templates"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if len(env.Templates) == 0 {
		fmt.Println("No templates.")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tTENANT\tSHARED\tUSES\tUPDATED")
	for _, t := range env.Templates {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%d\t%s\n", t.ID, t.Name, reportCell(t.TenantID), t.IsShared, t.UsageCount, reportCell(t.UpdatedAt))
	}
	return tw.Flush()
}

func runReportTemplateShow(_ *cobra.Command, args []string) error {
	data, _, err := reportDo(http.MethodGet, reportTemplatesPath+"/"+url.PathEscape(args[0]), nil, "show template")
	if err != nil {
		return err
	}
	if reportJSONOutput() {
		return printReportJSON(data)
	}
	var t struct {
		reportTemplateRow
		CreatedBy string   `json:"created_by"`
		Category  string   `json:"category"`
		Tags      []string `json:"tags"`
		Query     struct {
			DataSources []string `json:"data_sources"`
		} `json:"query"`
		Parameters []interface{} `json:"parameters"`
	}
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "ID:\t%s\n", t.ID)
	_, _ = fmt.Fprintf(tw, "Name:\t%s\n", t.Name)
	_, _ = fmt.Fprintf(tw, "Description:\t%s\n", reportCell(t.Description))
	_, _ = fmt.Fprintf(tw, "Tenant:\t%s\n", reportCell(t.TenantID))
	_, _ = fmt.Fprintf(tw, "Created by:\t%s\n", reportCell(t.CreatedBy))
	_, _ = fmt.Fprintf(tw, "Shared:\t%t\n", t.IsShared)
	_, _ = fmt.Fprintf(tw, "Data sources:\t%s\n", reportCell(strings.Join(t.Query.DataSources, ",")))
	_, _ = fmt.Fprintf(tw, "Parameters:\t%d\n", len(t.Parameters))
	_, _ = fmt.Fprintf(tw, "Updated:\t%s\n", reportCell(t.UpdatedAt))
	return tw.Flush()
}

func runReportTemplateCreate(_ *cobra.Command, _ []string) error {
	def, err := loadReportDefinition(reportFile)
	if err != nil {
		return err
	}
	data, _, err := reportDo(http.MethodPost, reportTemplatesPath, def, "create template")
	if err != nil {
		return err
	}
	if reportJSONOutput() {
		return printReportJSON(data)
	}
	var t reportTemplateRow
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	fmt.Printf("Template ID: %s\n", t.ID)
	fmt.Printf("Name:        %s\n", t.Name)
	return nil
}

func runReportTemplateDelete(_ *cobra.Command, args []string) error {
	id := args[0]
	if err := confirmCrossingAction(fmt.Sprintf("This will permanently delete report template %q.", id), reportYes); err != nil {
		return err
	}
	if _, _, err := reportDo(http.MethodDelete, reportTemplatesPath+"/"+url.PathEscape(id), nil, "delete template"); err != nil {
		return err
	}
	if reportJSONOutput() {
		fmt.Println(`{"status":"deleted"}`)
		return nil
	}
	fmt.Printf("Deleted template %s\n", id)
	return nil
}

func runReportTemplateShare(_ *cobra.Command, args []string) error {
	for _, p := range reportSharePerms {
		if p != "read" && p != "execute" && p != "modify" {
			return fmt.Errorf("invalid --permission %q: use read, execute or modify", p)
		}
	}
	body := map[string]interface{}{
		"shared_with_tenants": reportShareWith,
		"permissions":         reportSharePerms,
	}
	if reportShareExpiry != "" {
		d, err := time.ParseDuration(reportShareExpiry)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid --expires-in %q: use a positive Go duration such as 72h", reportShareExpiry)
		}
		body["expires_at"] = time.Now().UTC().Add(d).Format(time.RFC3339)
	}
	data, _, err := reportDo(http.MethodPost, reportTemplatesPath+"/"+url.PathEscape(args[0])+"/share", body, "share template")
	if err != nil {
		return err
	}
	if reportJSONOutput() {
		return printReportJSON(data)
	}
	fmt.Printf("Shared template %s with %s (%s)\n", args[0], strings.Join(reportShareWith, ","), strings.Join(reportSharePerms, ","))
	return nil
}

func runReportCustomRun(_ *cobra.Command, _ []string) error {
	def, err := loadReportDefinition(reportFile)
	if err != nil {
		return err
	}
	data, _, err := reportDo(http.MethodPost, reportGeneratePath, def, "run custom report")
	if err != nil {
		return err
	}
	if reportJSONOutput() {
		return printReportJSON(data)
	}
	var r struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DataPoints  int    `json:"data_points"`
		GeneratedAt string `json:"generated_at"`
		IsStreamed  bool   `json:"is_streamed"`
		StreamToken string `json:"stream_token"`
		TotalPages  int    `json:"total_pages"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Report ID:\t%s\n", r.ID)
	_, _ = fmt.Fprintf(tw, "Name:\t%s\n", r.Name)
	_, _ = fmt.Fprintf(tw, "Data points:\t%d\n", r.DataPoints)
	_, _ = fmt.Fprintf(tw, "Generated:\t%s\n", reportCell(r.GeneratedAt))
	_, _ = fmt.Fprintf(tw, "Streamed:\t%t\n", r.IsStreamed)
	if r.IsStreamed {
		_, _ = fmt.Fprintf(tw, "Stream token:\t%s\n", r.StreamToken)
		_, _ = fmt.Fprintf(tw, "Total pages:\t%d\n", r.TotalPages)
	}
	return tw.Flush()
}

func runReportCustomPage(_ *cobra.Command, _ []string) error {
	q := url.Values{}
	q.Set("stream_token", reportStreamToken)
	q.Set("page", strconv.Itoa(reportPage))
	if reportPageSize > 0 {
		q.Set("page_size", strconv.Itoa(reportPageSize))
	}
	data, hdr, err := reportDo(http.MethodGet, reportDataPath+"?"+q.Encode(), nil, "fetch report page")
	if err != nil {
		return err
	}
	if reportJSONOutput() {
		return printReportJSON(data)
	}
	var rows []map[string]interface{}
	if err := json.Unmarshal(data, &rows); err != nil {
		// Not a list of records: show the page as JSON.
		return printReportJSON(data)
	}
	if len(rows) == 0 {
		fmt.Println("No rows.")
	} else {
		seen := map[string]bool{}
		var cols []string
		for _, row := range rows {
			for k := range row {
				if !seen[k] {
					seen[k] = true
					cols = append(cols, k)
				}
			}
		}
		sort.Strings(cols)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, strings.ToUpper(strings.Join(cols, "\t")))
		for _, row := range rows {
			cells := make([]string, len(cols))
			for i, c := range cols {
				cells[i] = reportCell(row[c])
			}
			_, _ = fmt.Fprintln(tw, strings.Join(cells, "\t"))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if hdr.Get("X-Has-More") == "true" {
		fmt.Fprintf(os.Stderr, "More pages available: use --page %d\n", reportPage+1)
	}
	return nil
}
