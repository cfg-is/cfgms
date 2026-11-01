// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"io"
	"net/url"

	"github.com/spf13/cobra"
)

var (
	directoryUserFlags  directoryListFlags
	directoryGroupFlags directoryListFlags
)

var directoryUserCmd = &cobra.Command{
	Use:   "user",
	Short: "List and show directory users",
}

var directoryUserListCmd = &cobra.Command{
	Use:   "list",
	Short: "List directory users, one page at a time",
	Long: `List directory users from Active Directory and Microsoft 365.

Prints one page and, when more remain, the token to continue with (--page-token). --all
follows the tokens to the end, up to 10000 users.

Examples:
  cfg directory user list --source ad --query smith
  cfg directory user list --disabled --managed --output json
  cfg directory user list --all`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		bindLimitSet(cmd, &directoryUserFlags)
		client, err := getDirectoryClient()
		if err != nil {
			return err
		}
		return runDirectoryUserList(context.Background(), cmd.OutOrStdout(), client, &directoryUserFlags)
	},
}

var directoryUserShowCmd = &cobra.Command{
	Use:   "show <source>/<id>",
	Short: "Show one directory user and its groups",
	Long: `Show one user and the groups it belongs to. <source> is ad or m365.

If the same id exists in more than one domain or tenant, the controller answers with a
conflict; --authority (the domain or tenant GUID) picks one.

Example:
  cfg directory user show ad/jdoe`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := getDirectoryClient()
		if err != nil {
			return err
		}
		return runDirectoryUserShow(context.Background(), cmd.OutOrStdout(), client, args[0], &directoryUserFlags)
	},
}

func init() {
	f := &directoryUserFlags
	l := directoryUserListCmd
	l.Flags().StringVar(&f.source, "source", "", "Only this source: ad or m365 (default both)")
	l.Flags().StringVar(&f.query, "query", "", "Text match on display name, account name, user principal name, mail and id")
	l.Flags().BoolVar(&f.enabled, "enabled", false, "Only enabled users")
	l.Flags().BoolVar(&f.disabled, "disabled", false, "Only disabled users")
	l.Flags().BoolVar(&f.managed, "managed", false, "Only users CFGMS manages")
	addDirectoryPagingFlags(l, f, "users")

	s := directoryUserShowCmd
	s.Flags().StringVar(&f.authority, "authority", "", "Domain or tenant GUID, when the id exists in more than one")
	s.Flags().StringVar(&f.output, "output", directoryOutputTable, "Output format: table or json")

	directoryUserCmd.AddCommand(l, s)
	directoryCmd.AddCommand(directoryUserCmd)
}

func directoryListQuery(f *directoryListFlags, users bool) url.Values {
	q := url.Values{}
	if f.source != "" {
		q.Set("source", f.source)
	}
	if f.query != "" {
		q.Set("q", f.query)
	}
	if users {
		if f.enabled {
			q.Set("enabled", "true")
		}
		if f.disabled {
			q.Set("enabled", "false")
		}
	}
	if f.managed {
		q.Set("managed", "true")
	}
	return q
}

// directoryListOutput is the JSON shape of a list: the API's own, items and next_page_token.
type directoryListOutput struct {
	Items         []APIDirectoryObject `json:"items"`
	NextPageToken string               `json:"next_page_token,omitempty"`
}

func runDirectoryUserList(ctx context.Context, out io.Writer, client *APIClient, f *directoryListFlags) error {
	if err := f.validate(); err != nil {
		return err
	}
	res, err := directoryFetch[APIDirectoryObject](ctx, client, "/api/v1/directory/users", "items", directoryListQuery(f, true), f)
	if err != nil {
		return err
	}
	if f.output == directoryOutputJSON {
		return writeDirectoryJSON(out, directoryListOutput{Items: nonNil(res.items), NextPageToken: res.next})
	}
	if len(res.items) == 0 && res.next == "" {
		directoryEmptyMessage(out, "users")
		return nil
	}
	rows := make([][]string, 0, len(res.items))
	for _, u := range res.items {
		enabled := ""
		if u.Enabled != nil {
			enabled = directoryBool(*u.Enabled)
		}
		rows = append(rows, []string{u.Source, u.Kind, u.ID, u.Authority, u.DisplayName, u.SamAccountName,
			u.UserPrincipalName, u.Mail, u.Description, enabled, directoryBool(u.Managed), directoryTime(u.LastObserved), directoryBool(u.Stale)})
	}
	if err := writeDirectoryTable(out, []string{"SOURCE", "KIND", "ID", "AUTHORITY", "DISPLAY_NAME", "SAM_ACCOUNT_NAME",
		"USER_PRINCIPAL_NAME", "MAIL", "DESCRIPTION", "ENABLED", "MANAGED", "LAST_OBSERVED", "STALE"}, rows); err != nil {
		return err
	}
	writeDirectoryHint(out, res.next, res.capped, len(res.items))
	return nil
}

func runDirectoryUserShow(ctx context.Context, out io.Writer, client *APIClient, ref string, f *directoryListFlags) error {
	if err := f.validateOutput(); err != nil {
		return err
	}
	obj, _, err := getDirectoryObject(ctx, client, "users", ref, f.authority)
	if err != nil {
		return err
	}
	if f.output == directoryOutputJSON {
		return writeDirectoryJSON(out, obj)
	}
	writeDirectoryFields(out, obj)
	if obj.GroupsTruncated {
		directoryPrintf(out, "groups_truncated: true\n")
	}
	directoryPrintf(out, "\nGROUPS\n")
	if len(obj.Groups) == 0 {
		directoryPrintf(out, "(none)\n")
		return nil
	}
	rows := make([][]string, 0, len(obj.Groups))
	for _, g := range obj.Groups {
		rows = append(rows, []string{g.ID, g.DisplayName})
	}
	return writeDirectoryTable(out, []string{"ID", "DISPLAY_NAME"}, rows)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
