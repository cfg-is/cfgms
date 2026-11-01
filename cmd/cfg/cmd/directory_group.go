// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"io"
	"net/url"

	"github.com/spf13/cobra"
)

var directoryGroupCmd = &cobra.Command{
	Use:   "group",
	Short: "List and show directory groups, their members and membership changes",
}

var directoryGroupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List directory groups, one page at a time",
	Long: `List directory groups from Active Directory and Microsoft 365.

Prints one page and, when more remain, the token to continue with (--page-token). --all
follows the tokens to the end, up to 10000 groups.

Examples:
  cfg directory group list --source m365 --query helpdesk
  cfg directory group list --managed --output json`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		bindLimitSet(cmd, &directoryGroupFlags)
		client, err := getDirectoryClient()
		if err != nil {
			return err
		}
		return runDirectoryGroupList(context.Background(), cmd.OutOrStdout(), client, &directoryGroupFlags)
	},
}

var directoryGroupShowCmd = &cobra.Command{
	Use:   "show <source>/<id>",
	Short: "Show one directory group and its direct members",
	Long: `Show one group and its direct members, one page at a time. <source> is ad or m365.

Prints one page of members and, when more remain, the token to continue with
(--page-token). --all follows the tokens to the end, up to 10000 members.

If the same id exists in more than one domain or tenant, the controller answers with a
conflict; --authority (the domain or tenant GUID) picks one.

Example:
  cfg directory group show ad/helpdesk --all`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bindLimitSet(cmd, &directoryGroupFlags)
		client, err := getDirectoryClient()
		if err != nil {
			return err
		}
		return runDirectoryGroupShow(context.Background(), cmd.OutOrStdout(), client, args[0], &directoryGroupFlags)
	},
}

func init() {
	f := &directoryGroupFlags
	l := directoryGroupListCmd
	l.Flags().StringVar(&f.source, "source", "", "Only this source: ad or m365 (default both)")
	l.Flags().StringVar(&f.query, "query", "", "Text match on display name, account name, mail and id")
	l.Flags().BoolVar(&f.managed, "managed", false, "Only groups CFGMS manages")
	addDirectoryPagingFlags(l, f, "groups")

	s := directoryGroupShowCmd
	s.Flags().StringVar(&f.authority, "authority", "", "Domain or tenant GUID, when the id exists in more than one")
	addDirectoryPagingFlags(s, f, "members")

	directoryGroupCmd.AddCommand(l, s)
	directoryCmd.AddCommand(directoryGroupCmd)
}

func runDirectoryGroupList(ctx context.Context, out io.Writer, client *APIClient, f *directoryListFlags) error {
	if err := f.validate(); err != nil {
		return err
	}
	res, err := directoryFetch[APIDirectoryObject](ctx, client, "/api/v1/directory/groups", "items", directoryListQuery(f, false), f)
	if err != nil {
		return err
	}
	if f.output == directoryOutputJSON {
		return writeDirectoryJSON(out, directoryListOutput{Items: nonNil(res.items), NextPageToken: res.next})
	}
	if len(res.items) == 0 && res.next == "" {
		directoryEmptyMessage(out, "groups")
		return nil
	}
	rows := make([][]string, 0, len(res.items))
	for _, g := range res.items {
		rows = append(rows, []string{g.Source, g.Kind, g.ID, g.Authority, g.DisplayName, g.SamAccountName,
			g.UserPrincipalName, g.Mail, g.Description, directoryBool(g.Managed), directoryTime(g.LastObserved), directoryBool(g.Stale)})
	}
	if err := writeDirectoryTable(out, []string{"SOURCE", "KIND", "ID", "AUTHORITY", "DISPLAY_NAME", "SAM_ACCOUNT_NAME",
		"USER_PRINCIPAL_NAME", "MAIL", "DESCRIPTION", "MANAGED", "LAST_OBSERVED", "STALE"}, rows); err != nil {
		return err
	}
	writeDirectoryHint(out, res.next, res.capped, len(res.items))
	return nil
}

// directoryGroupShowOutput is the JSON shape of group show: the group object with the
// requested page of members alongside it.
type directoryGroupShowOutput struct {
	APIDirectoryObject
	Members       []APIDirectoryMember `json:"members"`
	NextPageToken string               `json:"next_page_token,omitempty"`
}

func runDirectoryGroupShow(ctx context.Context, out io.Writer, client *APIClient, ref string, f *directoryListFlags) error {
	if err := f.validate(); err != nil {
		return err
	}
	obj, base, err := getDirectoryObject(ctx, client, "groups", ref, f.authority)
	if err != nil {
		return err
	}
	q := url.Values{}
	if f.authority != "" {
		q.Set("authority", f.authority)
	}
	res, err := directoryFetch[APIDirectoryMember](ctx, client, base+"/members", "members", q, f)
	if err != nil {
		return err
	}
	if f.output == directoryOutputJSON {
		return writeDirectoryJSON(out, directoryGroupShowOutput{APIDirectoryObject: *obj, Members: nonNil(res.items), NextPageToken: res.next})
	}
	writeDirectoryFields(out, obj)
	directoryPrintf(out, "\nMEMBERS\n")
	if len(res.items) == 0 && res.next == "" {
		directoryPrintf(out, "(none)\n")
		return nil
	}
	rows := make([][]string, 0, len(res.items))
	for _, m := range res.items {
		rows = append(rows, []string{m.ID, m.Type, m.DisplayName})
	}
	if err := writeDirectoryTable(out, []string{"ID", "TYPE", "DISPLAY_NAME"}, rows); err != nil {
		return err
	}
	writeDirectoryHint(out, res.next, res.capped, len(res.items))
	return nil
}
