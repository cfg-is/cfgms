# GitHub CLI Project Management Reference

This document provides essential GitHub CLI commands and patterns for managing the CFGMS project board. These commands were consolidated from operational experience to avoid repeatedly looking up complex project management operations.

## Project Information

```bash
# List all projects in the organization
gh project list --owner cfg-is

# Get project field information (including status options)
gh project field-list PROJECT_NUMBER --owner cfg-is --format json

# Example output shows Status field with options:
# {"id":"PVTSSF_...", "name":"Status", "options":[
#   {"id":"0e6b51d0","name":"Backlog"},
#   {"id":"f75ad846","name":"Todo"}, 
#   {"id":"47fc9ee4","name":"In Progress"},
#   {"id":"98236657","name":"Done"}
# ]}
```

## Issue Management

```bash
# List open issues with JSON output
gh issue list --repo cfg-is/cfgms --state open --limit 50 --json number,title,labels

# Add issues to project by URL
gh project item-add PROJECT_NUMBER --owner cfg-is --url "https://github.com/cfg-is/cfgms/issues/ISSUE_NUMBER"

# Add multiple issues in batch
for i in {33..39}; do 
  gh project item-add 1 --owner cfg-is --url "https://github.com/cfg-is/cfgms/issues/$i"
done
```

## Project Item Operations

```bash
# List project items with details
gh project item-list PROJECT_NUMBER --owner cfg-is --format json --limit 50

# Filter project items by issue number
gh project item-list 1 --owner cfg-is --format json --limit 50 | \
  jq '.items[] | select(.content.number >= 29 and .content.number <= 39)'

# Get specific item details (ID, number, title)
gh project item-list 1 --owner cfg-is --format json --limit 50 | \
  jq '.items[] | {id, number: .content.number, title: .content.title}'
```

## Status Updates

```bash
# Update item status (requires project-id, item-id, field-id, and option-id)
gh project item-edit \
  --project-id PROJECT_ID \
  --id ITEM_ID \
  --field-id FIELD_ID \
  --single-select-option-id OPTION_ID

# Example: Move issue to "Todo" status
gh project item-edit \
  --project-id PVT_kwDOCrV4cc4A18Ip \
  --id PVTI_lADOCrV4cc4A18IpzgcSU0g \
  --field-id PVTSSF_lADOCrV4cc4A18IpzgrVDWc \
  --single-select-option-id f75ad846
```

## Important Notes

- **Project ID Format**: Use the full project ID (e.g., `PVT_kwDOCrV4cc4A18Ip`), not just the number
- **Item IDs**: Each project item has a unique ID that must be obtained from item-list command
- **Field IDs**: Status field ID is consistent but must be retrieved from field-list
- **Option IDs**: Status options (Backlog, Todo, In Progress, Done) have specific IDs
- **Batch Operations**: Use shell loops and `&&` operators for multiple updates
- **Error Handling**: Always verify IDs exist before attempting updates

## Status Option IDs (for CFGMS project)

- **Backlog**: `0e6b51d0`
- **Todo**: `f75ad846`
- **In Progress**: `47fc9ee4`
- **Done**: `98236657`

## Common Workflow

1. Get project information and field IDs
2. Add new issues to project if needed
3. List project items to get item IDs
4. Update item status using project-id, item-id, field-id, and option-id
5. Verify changes with another item-list command
