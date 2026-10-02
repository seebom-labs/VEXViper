# Shared helpers for hack/cut-release.sh and hack/cherry-pick.sh. Source, don't run.
# shellcheck shell=bash

die()  { echo "❌ $*" >&2; exit 1; }
info() { echo "▸ $*"; }
warn() { echo "⚠️  $*" >&2; }

# The remote pointing at the canonical repository (seebom-labs/*), else origin.
# Respects $REMOTE if set.
upstream_remote() {
  local remote="${REMOTE:-}"
  if [[ -z "$remote" ]]; then
    remote=$(git remote -v | awk 'tolower($2) ~ /github\.com[:\/]seebom-labs\// && $3 == "(push)" { print $1; exit }')
    remote="${remote:-origin}"
  fi
  git remote get-url "$remote" >/dev/null 2>&1 || die "git remote '$remote' does not exist (set REMOTE=...)"
  printf '%s' "$remote"
}

# owner/repo for a remote, as GitHub Actions sees it. Non-GitHub remotes (for
# tests) are returned as a slash-normalized path and never contacted.
repo_slug() {
  local url slug
  url=$(git remote get-url --push "$1")
  if [[ "$url" =~ github\.com[:/] ]]; then
    slug=$(printf '%s' "$url" | sed -E 's#^(ssh://)?(git@|https://)github\.com[:/]##; s#\.git$##; s#/$##')
  else
    slug=$(printf '%s' "$url" | sed -E 's#\.git$##; s#/$##')
    if [[ "$slug" == */* ]]; then
      local repo owner_path owner
      repo="${slug##*/}"
      owner_path="${slug%/*}"
      owner="${owner_path##*/}"
      slug="$owner/$repo"
    fi
  fi
  printf '%s' "$slug"
}

# Highest final (non-pre-release) tag vX.Y.* for a minor "X.Y", or empty.
latest_patch_tag() {
  git tag -l "v$1.*" | grep -E "^v${1//./\.}\.[0-9]+$" | sort -V | tail -n1 || true
}
