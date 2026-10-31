// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"io"
	"net/url"

	"github.com/spf13/cobra"
)

var directoryGroupChangesCmd = &cobra.Command{
	Use:   "changes <source>/<id>",
	Short: "List membership changes of one group, newest first",
	Long: `List the members added to and removed from one group, newest first.

The first observation of a group is recorded as a baseline, not a change, and is left out
unless --include-baseline is set. --since and --until are RFC 3339 times that bound when
the change was recorded. Prints one page and, when more remain, the token to continue
with (--page-token); --all follows the tokens to the end, up to 10000 events.

Example:
  cfg directory group changes ad/helpdesk --since 2026-10-01T00:00:00Z --member jdoe`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bindLimitSet(cmd, &directoryGroupFlags)
		client, err := getDirectoryClient()
		if err != nil {
			return err
		}
		return runDirectoryGroupChanges(context.Background(), cmd.OutOrStdout(), client, args[0], &directoryGroupFlags)
	},
}

func init() {
	f := &directoryGroupFlags
	c := directoryGroupChangesCmd
	c.Flags().StringVar(&f.since, "since", "", "Only changes recorded at or after this RFC 3339 time")
	c.Flags().StringVar(&f.until, "until", "", "Only changes recorded at or before this RFC 3339 time")
	c.Flags().StringVar(&f.member, "member", "", "Only changes to this member id")
	c.Flags().BoolVar(&f.includeBaseline, "include-baseline", false, "Include the baseline recorded at the first observation of the group")
	c.Flags().StringVar(&f.authority, "authority", "", "Domain or tenant GUID, when the id exists in more than one")
	addDirectoryPagingFlags(c, f, "events")
	directoryGroupCmd.AddCommand(c)
}

func runDirectoryGroupChanges(ctx context.Context, out io.Writer, client *APIClient, ref string, f *directoryListFlags) error {
	if err := f.validate(); err != nil {
		return err
	}
	source, id, err := parseDirectoryRef(ref)
	if err != nil {
		return err
	}
	q := url.Values{}
	for name, val := range map[string]string{"since": f.since, "until": f.until, "member": f.member, "authority": f.authority} {
		if val != "" {
			q.Set(name, val)
		}
	}
	if f.includeBaseline {
		q.Set("include_baseline", "true")
	}
	res, err := directoryFetch[APIDirectoryChange](ctx, client,
		"/api/v1/directory/groups/"+source+"/"+id+"/membership-changes", "events", q, f)
	if err != nil {
		return err
	}
	if f.output == directoryOutputJSON {
		return writeDirectoryJSON(out, struct {
			Events        []APIDirectoryChange `json:"events"`
			NextPageToken string               `json:"next_page_token,omitempty"`
		}{Events: nonNil(res.items), NextPageToken: res.next})
	}
	if len(res.items) == 0 && res.next == "" {
		directoryEmptyMessage(out, "membership changes")
		return nil
	}
	rows := make([][]string, 0, len(res.items))
	for _, e := range res.items {
		rows = append(rows, []string{e.Group, e.Member, e.MemberType, e.Op, directoryTime(e.ObservedAt),
			directoryTime(e.RecordedAt), e.Source, directoryBool(e.Baseline)})
	}
	if err := writeDirectoryTable(out, []string{"GROUP", "MEMBER", "MEMBER_TYPE", "OP", "OBSERVED_AT", "RECORDED_AT", "SOURCE", "BASELINE"}, rows); err != nil {
		return err
	}
	writeDirectoryHint(out, res.next, res.capped, len(res.items))
	return nil
}
