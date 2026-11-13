#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# Tests for scripts/agent-image-filter.sh (Issue #6228).
#
# Covers: (a) the real Dockerfile — every cfgms-context COPY source yields
# build=true, so a future COPY is covered; (b) fixture Dockerfiles — a new COPY,
# a --from= copy, a continuation, a directory source, a multi-source line, a
# `COPY . .` that must not trigger; (c) the pre-change inline grep entries, the
# gitlink and the devcontainer tree; (d) unrelated files yield build=false;
# (e) every defect in the input fails closed to build=true.
#
# Usage: bash scripts/agent-image-filter_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILTER="$REPO_ROOT/scripts/agent-image-filter.sh"
REAL_DOCKERFILE="$REPO_ROOT/.claude/tooling/devcontainer/Dockerfile"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

PASS=0
FAIL=0

ok()  { echo "  ✅ $1"; PASS=$((PASS + 1)); }
bad() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }

# expect <name> <expected-output> <filter args...>
expect() {
    local name="$1" want="$2" got
    shift 2
    got="$(bash "$FILTER" "$@" 2>/dev/null)"
    if [ "$got" = "$want" ]; then
        ok "$name"
    else
        bad "$name: want '$want', got '$got'"
    fi
}

# list <name> <line...> writes a changed-file list and echoes its path.
list() {
    local f="$work/$1.txt"
    shift
    printf '%s\n' "$@" > "$f"
    printf '%s' "$f"
}

# A fixture mirroring the context COPY sources of the real Dockerfile at the
# time of writing, so the legacy-entry checks below are meaningful even when the
# tooling submodule is not checked out.
mirror="$work/mirror.Dockerfile"
cat > "$mirror" <<'DOCKER'
FROM golang:1 AS cfg-builder
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build ./...
FROM node:22 AS web
COPY web/.nvmrc web/package.json web/package-lock.json /web/
FROM base
COPY --from=cfg-builder /out/cfg /usr/local/bin/cfg
COPY scripts/install-go-analyzers.sh /tmp/install-go-analyzers.sh
COPY .claude/model-routing.yaml /etc/model-routing.yaml
COPY .claude/tooling/metrics/token_report.py \
     .claude/tooling/metrics/pricing.json \
     /opt/metrics/
COPY .claude/tooling/devcontainer/entrypoint.sh /usr/local/bin/entrypoint.sh
DOCKER

echo "real Dockerfile -> every context COPY source yields build=true"
if [ -f "$REAL_DOCKERFILE" ]; then
    sources="$(bash "$FILTER" --print-sources 2>/dev/null)"
    if [ -n "$sources" ]; then
        ok "sources derived from the real Dockerfile ($(wc -l <<< "$sources") entries)"
    else
        bad "no sources derived from the real Dockerfile"
    fi
    n=0
    while IFS= read -r src; do
        [ -n "$src" ] || continue
        n=$((n + 1))
        case "$src" in
            */) path="${src}x/y.txt" ;;
            *)  path="$src" ;;
        esac
        expect "real COPY source $src" build=true --files "$(list "r$n" "$path")"
    done <<< "$sources"
    for must in go.mod go.sum web/.nvmrc web/package.json web/package-lock.json \
        scripts/install-go-analyzers.sh .claude/model-routing.yaml \
        .claude/tooling/metrics/token_report.py .claude/tooling/metrics/pricing.json; do
        if grep -qxF "$must" <<< "$sources"; then ok "real Dockerfile copies $must"; else bad "real Dockerfile no longer copies $must"; fi
    done
    if grep -qxE '\.|\./' <<< "$sources"; then bad "COPY . . leaked into the sources"; else ok "COPY . . is not a source"; fi
else
    # The tooling submodule is not initialised in this checkout, so the real
    # Dockerfile cannot be read; the filter must fail closed instead.
    echo "  (real Dockerfile absent: submodule not checked out; asserting fail-closed instead)"
    expect "absent real Dockerfile builds" build=true --files "$(list ra docs/README.md)"
fi

echo "fixture mirroring the pre-change inline grep -> build=true"
i=0
for p in .claude/tooling .claude/tooling/devcontainer/Dockerfile .claude/tooling/devcontainer/new/file.sh \
    go.mod go.sum web/.nvmrc web/package.json web/package-lock.json \
    .claude/tooling/metrics/token_report.py .claude/tooling/metrics/pricing.json \
    .claude/model-routing.yaml .dockerignore .github/workflows/agent-image-build.yml \
    scripts/install-go-analyzers.sh scripts/agent-image-filter.sh scripts/agent-image-filter_test.sh; do
    i=$((i + 1))
    expect "$p" build=true --dockerfile "$mirror" --files "$(list "m$i" "$p")"
done
expect "script among unrelated files" build=true --dockerfile "$mirror" \
    --files "$(list m100 docs/a.md cmd/steward/main.go scripts/install-go-analyzers.sh)"
printf 'go.mod\r\n' > "$work/crlf.txt"
expect "CRLF-terminated list" build=true --dockerfile "$mirror" --files "$work/crlf.txt"
printf 'docs/a.md\ngo.sum' > "$work/nonl.txt"
expect "last line without newline" build=true --dockerfile "$mirror" --files "$work/nonl.txt"

echo "unrelated files -> build=false"
expect "go source (COPY . . is not a trigger)" build=false --dockerfile "$mirror" \
    --files "$(list f1 pkg/cert/manager.go cmd/steward/main.go)"
expect "docs only" build=false --dockerfile "$mirror" --files "$(list f2 docs/README.md)"
expect "other workflow" build=false --dockerfile "$mirror" \
    --files "$(list f3 .github/workflows/test-suite.yml)"
expect "other script" build=false --dockerfile "$mirror" \
    --files "$(list f4 scripts/check-no-python-in-core.sh)"
expect "look-alike go.mod.bak" build=false --dockerfile "$mirror" --files "$(list f5 go.mod.bak)"
expect "look-alike .claude/tooling-notes" build=false --dockerfile "$mirror" \
    --files "$(list f6 .claude/tooling-notes.md)"
expect "path only mentioned mid-line" build=false --dockerfile "$mirror" \
    --files "$(list f7 docs/scripts/install-go-analyzers.sh)"
expect "other .claude file" build=false --dockerfile "$mirror" \
    --files "$(list f8 .claude/settings.json)"
if [ -f "$REAL_DOCKERFILE" ]; then
    expect "real Dockerfile: go source" build=false --files "$(list f9 pkg/cert/manager.go)"
    expect "real Dockerfile: docs" build=false --files "$(list f10 docs/README.md)"
fi

echo "fixture Dockerfile: new COPY, --from, continuation, directory source"
fx="$work/fixture.Dockerfile"
cat > "$fx" <<'DOCKER'
# COPY ignored/in-comment.txt /x
FROM base
COPY . .
copy --chown=1000:1000 scripts/new-helper.sh /usr/local/bin/new-helper.sh
COPY --from=cfg-builder /out/tool /usr/local/bin/tool
COPY --from=cfg-builder --chown=1:1 stage/only.txt /stage/
COPY assets/one.txt \
     # a comment inside a continuation
     assets/two.txt \
     /dest/
COPY tools/dir/ /opt/dir/
COPY ["json/form.txt", "/json/"]
ADD https://example.com/remote.tar /remote.tar
COPY <<HEREDOC /inline.txt
inline content
HEREDOC
DOCKER
expect "new COPY source" build=true --dockerfile "$fx" --files "$(list x1 scripts/new-helper.sh)"
expect "continuation first source" build=true --dockerfile "$fx" --files "$(list x2 assets/one.txt)"
expect "continuation second source" build=true --dockerfile "$fx" --files "$(list x3 assets/two.txt)"
expect "directory source, nested file" build=true --dockerfile "$fx" --files "$(list x4 tools/dir/sub/a.go)"
expect "JSON-form source" build=true --dockerfile "$fx" --files "$(list x5 json/form.txt)"
expect "--from source is not a context path" build=false --dockerfile "$fx" --files "$(list x6 stage/only.txt)"
expect "--from source (first form)" build=false --dockerfile "$fx" --files "$(list x7 out/tool)"
expect "destination is not a source" build=false --dockerfile "$fx" --files "$(list x8 dest/x)"
expect "directory prefix look-alike" build=false --dockerfile "$fx" --files "$(list x9 tools/dirx/a.go)"
expect "comment text is not a source" build=false --dockerfile "$fx" --files "$(list x10 ignored/in-comment.txt)"
expect "remote ADD is not a source" build=false --dockerfile "$fx" --files "$(list x11 remote.tar)"
expect "COPY . . is not a trigger" build=false --dockerfile "$fx" --files "$(list x12 pkg/a.go)"
out="$(bash "$FILTER" --print-sources --dockerfile "$fx" 2>/dev/null | tr '\n' ' ')"
want="scripts/new-helper.sh assets/one.txt assets/two.txt tools/dir/ json/form.txt "
if [ "$out" = "$want" ]; then ok "derived sources are exactly the context sources"; else bad "derived sources: want '$want', got '$out'"; fi

echo "fail closed -> build=true"
: > "$work/empty.txt"
printf '\n  \n\n' > "$work/blank.txt"
expect "empty list" build=true --dockerfile "$mirror" --files "$work/empty.txt"
expect "blank-only list" build=true --dockerfile "$mirror" --files "$work/blank.txt"
expect "missing list" build=true --dockerfile "$mirror" --files "$work/does-not-exist.txt"
expect "directory as list" build=true --dockerfile "$mirror" --files "$work"
expect "no arguments" build=true --dockerfile "$mirror"
expect "--files without value" build=true --dockerfile "$mirror" --files
expect "unknown argument" build=true --dockerfile "$mirror" --bogus
expect "missing Dockerfile" build=true --dockerfile "$work/nope" --files "$(list d1 docs/a.md)"
expect "directory as Dockerfile" build=true --dockerfile "$work" --files "$(list d2 docs/a.md)"
expect "--dockerfile without value" build=true --files "$(list d3 docs/a.md)" --dockerfile
: > "$work/empty.Dockerfile"
expect "Dockerfile without COPY/ADD" build=true --dockerfile "$work/empty.Dockerfile" --files "$(list d4 docs/a.md)"
printf 'FROM base\nCOPY $SRC /dest\n' > "$work/var.Dockerfile"
expect "variable COPY source" build=true --dockerfile "$work/var.Dockerfile" --files "$(list d5 docs/a.md)"
if [ "$(id -u)" -ne 0 ]; then
    unreadable="$(list u1 docs/a.md)"
    chmod 000 "$unreadable"
    expect "unreadable list (mode 000)" build=true --dockerfile "$mirror" --files "$unreadable"
    chmod 600 "$unreadable"
    cp "$mirror" "$work/unreadable.Dockerfile"
    chmod 000 "$work/unreadable.Dockerfile"
    expect "unreadable Dockerfile (mode 000)" build=true --dockerfile "$work/unreadable.Dockerfile" --files "$(list u2 docs/a.md)"
    chmod 600 "$work/unreadable.Dockerfile"
else
    # Root reads mode-000 files, so the case cannot be constructed.
    echo "  (skipped: unreadable-by-mode cases need a non-root user)"
fi

# Exactly one stdout line, and warnings (not stdout) on a defect.
lines="$(bash "$FILTER" --dockerfile "$mirror" --files "$work/empty.txt" 2>/dev/null | wc -l)"
if [ "$lines" -eq 1 ]; then ok "exactly one stdout line on fail-closed"; else bad "stdout had $lines lines"; fi
if bash "$FILTER" --dockerfile "$mirror" --files "$work/empty.txt" 2>&1 >/dev/null | grep -q '^::warning::'; then
    ok "fail-closed warning goes to stderr"
else
    bad "no ::warning:: on stderr when failing closed"
fi

echo ""
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
