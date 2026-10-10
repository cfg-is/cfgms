#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Create or update the GitHub Release for a tag and attach the release assets.
# The release is a draft unless PUBLIC is exactly "true"; a draft is visible
# only to accounts with write access. An existing published release is never
# given binaries unless PUBLIC is "true".
#
# Usage: publish-release.sh TAG PUBLIC ASSETS_DIR NOTES_FILE
# Environment: GITHUB_REPOSITORY (owner/name), GH_TOKEN for gh.

set -euo pipefail

TAG="${1:?usage: publish-release.sh TAG PUBLIC ASSETS_DIR NOTES_FILE}"
PUBLIC="${2-}"
ASSETS_DIR="${3:?usage: publish-release.sh TAG PUBLIC ASSETS_DIR NOTES_FILE}"
NOTES_FILE="${4:?usage: publish-release.sh TAG PUBLIC ASSETS_DIR NOTES_FILE}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

shopt -s nullglob
assets=("$ASSETS_DIR"/*)
if [[ ${#assets[@]} -eq 0 ]]; then
    echo "Error: no release assets in $ASSETS_DIR" >&2
    exit 1
fi

make_public=false
if [[ "$PUBLIC" == "true" ]]; then
    make_public=true
fi

# gh release view does not always resolve drafts, so match the tag in the list.
existing=""
while IFS=$'\t' read -r name is_draft; do
    if [[ "$name" == "$TAG" ]]; then
        existing="$is_draft"
        break
    fi
done < <(gh release list --repo "$REPO" --limit 1000 --json tagName,isDraft \
    --jq '.[] | [.tagName, .isDraft] | @tsv')

if [[ -z "$existing" ]]; then
    draft_args=(--draft)
    if [[ "$make_public" == "true" ]]; then
        draft_args=()
    fi
    gh release create "$TAG" "${assets[@]}" \
        --repo "$REPO" \
        --verify-tag \
        --title "CFGMS $TAG" \
        --notes-file "$NOTES_FILE" \
        "${draft_args[@]}"
    exit 0
fi

if [[ "$existing" != "true" && "$make_public" != "true" ]]; then
    echo "Error: $TAG already has a published release; refusing to attach binaries to it." >&2
    echo "  Binaries go on a draft release unless the CFGMS_PUBLIC_RELEASE_BINARIES variable is 'true'." >&2
    echo "  The published release was not changed." >&2
    exit 1
fi

gh release upload "$TAG" "${assets[@]}" --repo "$REPO" --clobber
if [[ "$make_public" == "true" ]]; then
    gh release edit "$TAG" --repo "$REPO" --notes-file "$NOTES_FILE" --draft=false
else
    gh release edit "$TAG" --repo "$REPO" --notes-file "$NOTES_FILE" --draft
fi
