#!/usr/bin/env bash
# Backport a change that is merged on main to a release branch, as a pull
# request against release/vX.Y.
#
# Usage:
#   hack/cherry-pick.sh <PR number | commit> <X.Y | release/vX.Y>
#   make cherry-pick PR=431 BRANCH=0.8
#
# Fixes always land on main first. This finds the commits of the PR on
# <REMOTE>/main, picks them onto release/vX.Y with `git cherry-pick -x` (so
# every commit names its origin), pushes a branch to your fork and prints the
# link to open the pull request. On a conflict it stops on the branch and tells
# you how to finish.
#
# PRs are rebase-merged: their commits keep their own subjects, so they are
# looked up on GitHub (the PR's merge commit, then every commit GitHub
# associates with the PR, walking back from there). This needs the GitHub CLI.
# A squash-merged PR (subject ending in "(#431)") is found locally without it.
#
# Environment:
#   REMOTE       git remote of the canonical repo (default: the remote pointing
#                at seebom-labs/*, otherwise origin)
#   PUSH_REMOTE  where the cherry-pick branch is pushed (default: origin)
#   GH           GitHub CLI binary (default: gh)
#   DRY_RUN      1 = show what would be picked, change nothing
set -euo pipefail
# shellcheck source=hack/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit "${1:-0}"
}

[[ $# -eq 2 ]] || usage 1
WHAT="$1"
TARGET="${2#release/}"
TARGET="${TARGET#v}"
[[ "$TARGET" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die "target must be X.Y or release/vX.Y, got '$2'"
BRANCH="release/v$TARGET"

REMOTE=$(upstream_remote)
PUSH_REMOTE="${PUSH_REMOTE:-origin}"
git remote get-url "$PUSH_REMOTE" >/dev/null 2>&1 || die "git remote '$PUSH_REMOTE' does not exist (set PUSH_REMOTE=...)"

info "Fetching $REMOTE ..."
git fetch --quiet --prune "$REMOTE"
git rev-parse --verify --quiet "refs/remotes/$REMOTE/$BRANCH" >/dev/null \
  || die "$BRANCH does not exist on $REMOTE (create it: make release-branch VERSION=$TARGET)"

GH="${GH:-gh}"
UPSTREAM_SLUG=$(repo_slug "$REMOTE")
PR=""
TITLE=""
PICKS=()

is_merge_commit() { [[ "$(git rev-list --parents -n1 "$1" | wc -w)" -gt 2 ]]; }

pr_commits_from_github() {
  "$GH" --version 2>/dev/null | grep -q '^gh version' \
    || die "no commit on $REMOTE/main ends with (#$PR). Finding a rebase-merged PR needs the GitHub CLI (install it or set GH=/path/to/gh) — is the PR merged?"
  local view state merge count sha prs
  view=$("$GH" pr view "$PR" --repo "$UPSTREAM_SLUG" --json state,mergeCommit,commits,title \
    --jq '"\(.state) \(.mergeCommit.oid // "-") \(.commits | length) \(.title)"') \
    || die "cannot look up PR #$PR on $UPSTREAM_SLUG — is the PR merged?"
  read -r state merge count TITLE <<<"$view"
  [[ "$state" == "MERGED" ]] || die "PR #$PR is ${state:-unknown} — is the PR merged?"
  if ! git cat-file -e "$merge^{commit}" 2>/dev/null || ! git merge-base --is-ancestor "$merge" "$REMOTE/main"; then
    die "PR #$PR merged as ${merge:0:7}, which is not on $REMOTE/main"
  fi
  ! is_merge_commit "$merge" || die "PR #$PR was merged with a merge commit; pick its individual commits instead"
  sha="$merge"
  while (( ${#PICKS[@]} < count )); do
    prs=$("$GH" api "repos/$UPSTREAM_SLUG/commits/$sha/pulls" --jq '.[].number') \
      || die "cannot look up the pull requests of ${sha:0:7} on $UPSTREAM_SLUG"
    grep -qx "$PR" <<<"$prs" || break
    PICKS=("$sha" ${PICKS[@]+"${PICKS[@]}"})
    is_merge_commit "$sha" && break
    sha=$(git rev-parse "$sha^")
  done
  (( ${#PICKS[@]} > 0 )) || die "GitHub associates no commit on $REMOTE/main with PR #$PR; pass the commit instead"
}

if [[ "$WHAT" =~ ^#?([0-9]+)$ ]]; then
  PR="${BASH_REMATCH[1]}"
  COMMITS=$(git log "$REMOTE/main" --format='%H %s' \
    | awk -v suffix="(#$PR)" 'substr($0, length($0) - length(suffix) + 1) == suffix { print $1 }')
  COUNT=$(printf '%s' "$COMMITS" | grep -c . || true)
  [[ "$COUNT" -le 1 ]] || die "$COUNT commits on $REMOTE/main end with (#$PR); pass the commit instead"
  if [[ "$COUNT" -eq 1 ]]; then
    PICKS=("$COMMITS")
  else
    pr_commits_from_github
  fi
else
  COMMIT=$(git rev-parse --verify --quiet "$WHAT^{commit}") || die "cannot resolve '$WHAT'"
  if ! git merge-base --is-ancestor "$COMMIT" "$REMOTE/main"; then
    warn "$(git rev-parse --short "$COMMIT") is not on $REMOTE/main. Fixes land on main first, then get backported."
  fi
  PICKS=("$COMMIT")
fi

PICKED=$(git log "$REMOTE/$BRANCH" --format=%B)
for COMMIT in "${PICKS[@]}"; do
  SHORT=$(git rev-parse --short "$COMMIT")
  if grep -qF "cherry picked from commit $COMMIT" <<<"$PICKED"; then
    die "$SHORT is already on $BRANCH"
  fi
  if git merge-base --is-ancestor "$COMMIT" "$REMOTE/$BRANCH"; then
    die "$SHORT is already on $BRANCH (it predates the branch cut)"
  fi
  ! is_merge_commit "$COMMIT" || die "$SHORT is a merge commit; pick its individual commits instead"
done
LAST="${PICKS[${#PICKS[@]}-1]}"
TITLE="${TITLE:-$(git log -1 --format=%s "$LAST")}" 

LOCAL_BRANCH="cherry-pick/${PR:-$(git rev-parse --short "$LAST")}-to-release-v$TARGET"
if git rev-parse --verify --quiet "refs/heads/$LOCAL_BRANCH" >/dev/null; then
  die "local branch $LOCAL_BRANCH already exists (delete it: git branch -D $LOCAL_BRANCH)"
fi

echo
LABEL="Pick:"
for COMMIT in "${PICKS[@]}"; do
  printf '  %-10s %s\n' "$LABEL" "$(git log -1 --format='%h %s' "$COMMIT")"
  LABEL=""
done
echo "  Onto:      $REMOTE/$BRANCH"
echo "  Branch:    $LOCAL_BRANCH → $PUSH_REMOTE"
echo

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  info "DRY_RUN=1 — nothing changed."
  exit 0
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  die "working tree has uncommitted changes; commit or stash them first"
fi

ORIGINAL=$(git symbolic-ref --short -q HEAD || git rev-parse HEAD)
git checkout --quiet --no-track -b "$LOCAL_BRANCH" "$REMOTE/$BRANCH"

if ! git cherry-pick -x "${PICKS[@]}"; then
  echo
  warn "Conflict. You are on $LOCAL_BRANCH. To finish:"
  echo "    1. resolve the conflicts, git add <files>"
  echo "    2. git cherry-pick --continue"
  echo "    3. git push -u $PUSH_REMOTE $LOCAL_BRANCH"
  echo "    4. open a pull request against $BRANCH, and note in it what you resolved"
  echo "  To give up: git cherry-pick --abort && git checkout $ORIGINAL && git branch -D $LOCAL_BRANCH"
  exit 1
fi

git push --quiet -u "$PUSH_REMOTE" "$LOCAL_BRANCH"
git checkout --quiet "$ORIGINAL"

PUSH_SLUG=$(repo_slug "$PUSH_REMOTE")
if [[ "$UPSTREAM_SLUG" == "$PUSH_SLUG" ]]; then
  HEAD_SPEC="$LOCAL_BRANCH"
else
  HEAD_SPEC="${PUSH_SLUG%%/*}:${PUSH_SLUG#*/}:$LOCAL_BRANCH"
fi

echo
info "Pushed $LOCAL_BRANCH to $PUSH_REMOTE. Open the pull request:"
echo "    https://github.com/$UPSTREAM_SLUG/compare/$BRANCH...$HEAD_SPEC?expand=1"
echo
echo "  Title: [$BRANCH] $TITLE"
if [[ -n "$PR" ]]; then
  echo "  Body:  Cherry-pick of #$PR onto $BRANCH."
fi
