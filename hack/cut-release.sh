#!/usr/bin/env bash
# Cut VEXViper releases. Every release tag lands on a release branch
# release/vX.Y; .github/workflows/release.yml rejects tags that do not. The tag
# push triggers that workflow, which builds and publishes binaries, the image,
# the Helm chart and the GitHub (pre-)release.
#
# Usage:
#   hack/cut-release.sh rc     X.Y.Z   next release candidate vX.Y.Z-rc.N. For X.Y.0
#                                      without release/vX.Y this is the branch cut:
#                                      the branch is created from main first.
#   hack/cut-release.sh final  X.Y.Z   final release vX.Y.Z from release/vX.Y
#   hack/cut-release.sh branch X.Y     only create release/vX.Y — from main for an
#                                      unreleased minor, from the latest vX.Y.* tag
#                                      for a released one (to backport a patch)
#
# Make targets: make release-rc VERSION=X.Y.Z, make release VERSION=X.Y.Z,
#               make release-branch VERSION=X.Y
#
# Environment:
#   REMOTE   git remote of the canonical repo (default: the remote pointing at
#            seebom-labs/*, otherwise origin)
#   REF      commit-ish to tag (default: head of <REMOTE>/release/vX.Y). Must be
#            on that branch, e.g. REF=v0.8.0-rc.2 to release exactly a tested RC
#   DRY_RUN  1 = print what would happen, create and push nothing
#   YES      1 = do not ask for confirmation
#
# Everything is resolved from the remote, never from your local checkout, so
# unpushed local commits cannot end up in a release by accident.
set -euo pipefail
# shellcheck source=hack/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit "${1:-0}"
}

[[ $# -eq 2 ]] || usage 1
KIND="$1"
VERSION="${2#v}"

case "$KIND" in
  rc|final)
    [[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
      || die "VERSION must be X.Y.Z (without -rc suffix), got '$VERSION'"
    MINOR="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
    ;;
  branch)
    [[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.[0-9]+)?$ ]] \
      || die "VERSION must be X.Y, got '$VERSION'"
    MINOR="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
    PATCH=""
    ;;
  *) die "first argument must be 'rc', 'final' or 'branch', got '$KIND'" ;;
esac

REMOTE=$(upstream_remote)
info "Fetching $REMOTE ..."
git fetch --quiet --prune --tags --force "$REMOTE"
SLUG=$(repo_slug "$REMOTE")
OWNER="${SLUG%%/*}"
[[ "$OWNER" == "$SLUG" ]] && OWNER="seebom-labs"
GHCR_OWNER="ghcr.io/$(printf '%s' "$OWNER" | tr '[:upper:]' '[:lower:]')"

BRANCH="release/v$MINOR"
LAST_FINAL=$(latest_patch_tag "$MINOR")

if [[ "$KIND" != "branch" ]]; then
  FINAL_TAG="v$VERSION"
  if git rev-parse --verify --quiet "refs/tags/$FINAL_TAG" >/dev/null; then
    die "$FINAL_TAG is already released — there is nothing left to cut for $VERSION"
  fi
fi

CREATE_BRANCH=""
BRANCH_BASE=""
if BRANCH_HEAD=$(git rev-parse --verify --quiet "refs/remotes/$REMOTE/$BRANCH^{commit}"); then
  if [[ "$KIND" == "branch" ]]; then die "$BRANCH already exists on $REMOTE"; fi
else
  if [[ -n "$LAST_FINAL" ]]; then
    BRANCH_BASE="$LAST_FINAL"
  else
    BRANCH_BASE="$REMOTE/main"
  fi
  case "$KIND" in
    branch) ;;
    rc)
      [[ "$PATCH" == "0" ]] \
        || die "$BRANCH does not exist. Create it (make release-branch VERSION=$MINOR), cherry-pick the fixes (make cherry-pick PR=<n> BRANCH=$MINOR), then cut the RC."
      ;;
    final)
      if [[ "$PATCH" == "0" ]]; then
        die "$BRANCH does not exist — no release candidate was cut. Start with: make release-rc VERSION=$VERSION"
      fi
      die "$BRANCH does not exist. Create it (make release-branch VERSION=$MINOR), cherry-pick the fixes (make cherry-pick PR=<n> BRANCH=$MINOR), then release."
      ;;
  esac
  CREATE_BRANCH=$(git rev-parse "$BRANCH_BASE^{commit}")
  BRANCH_HEAD="$CREATE_BRANCH"
fi

confirm() {
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    info "DRY_RUN=1 — nothing created or pushed."
    exit 0
  fi
  if [[ "${YES:-0}" != "1" ]]; then
    local answer
    read -r -p "$1 [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || die "aborted"
  fi
}

after_branch_cut() {
  echo
  info "$BRANCH is cut. From now on:"
  echo "    - main is open for the next minor; nothing merged there reaches $MINOR by itself"
  echo "    - fixes for $MINOR merge to main first, then: make cherry-pick PR=<n> BRANCH=$MINOR"
}

if [[ "$KIND" == "branch" ]]; then
  echo
  echo "  Branch:    $BRANCH (new) on $REMOTE ($SLUG)"
  echo "  From:      $BRANCH_BASE — $(git log -1 --format='%h %s' "$CREATE_BRANCH")"
  echo
  confirm "Create and push $BRANCH to $REMOTE?"
  git push "$REMOTE" "$CREATE_BRANCH:refs/heads/$BRANCH"
  after_branch_cut
  exit 0
fi

if [[ -n "${REF:-}" ]]; then
  COMMIT=$(git rev-parse --verify --quiet "$REF^{commit}") || die "cannot resolve REF '$REF'"
  git merge-base --is-ancestor "$COMMIT" "$BRANCH_HEAD" \
    || die "$REF is not on $BRANCH; the release workflow only accepts tags on the release branch. Backport it first: make cherry-pick"
  FROM="$REF (on $BRANCH)"
else
  COMMIT="$BRANCH_HEAD"
  FROM="$BRANCH"
fi

LAST_RC=$(git tag -l "v$VERSION-rc.*" | sed -nE "s/^v${VERSION//./\\.}-rc\.([0-9]+)$/\1/p" | sort -n | tail -n1)
LAST_RC="${LAST_RC:-0}"

if [[ "$KIND" == "rc" ]]; then
  TAG="v$VERSION-rc.$((LAST_RC + 1))"
else
  TAG="$FINAL_TAG"
fi

if [[ -n "$LAST_FINAL" ]] && [[ "$(git rev-list --count "$LAST_FINAL..$COMMIT")" == "0" ]]; then
  die "nothing on $BRANCH since $LAST_FINAL — cherry-pick the fixes first (make cherry-pick PR=<n> BRANCH=$MINOR)"
fi

WARNINGS=()
if [[ "$LAST_RC" != "0" ]]; then
  RC_COMMIT=$(git rev-parse "v$VERSION-rc.$LAST_RC^{commit}")
  if [[ "$KIND" == "rc" && "$RC_COMMIT" == "$COMMIT" ]]; then
    die "v$VERSION-rc.$LAST_RC already points at $(git rev-parse --short "$COMMIT"); nothing new to test"
  fi
  if [[ "$KIND" == "final" && "$RC_COMMIT" != "$COMMIT" ]]; then
    WARNINGS+=("$FROM ($(git rev-parse --short "$COMMIT")) is not the commit of v$VERSION-rc.$LAST_RC ($(git rev-parse --short "$RC_COMMIT")); the release ships $(git rev-list --count "$RC_COMMIT..$COMMIT") commit(s) nobody tested as an RC. To release the RC as tested: REF=v$VERSION-rc.$LAST_RC")
  fi
elif [[ "$KIND" == "final" && "$PATCH" == "0" ]]; then
  WARNINGS+=("no release candidate was cut for $VERSION")
fi

PREVIOUS=$( { git tag -l 'v*' | grep -Ev -- '-' | grep -vxF "$FINAL_TAG" || true; echo "$FINAL_TAG"; } \
  | sort -V | grep -B1 -xF "$FINAL_TAG" | head -n1)
if [[ "$PREVIOUS" == "$FINAL_TAG" ]]; then PREVIOUS=""; fi

echo
echo "  Tag:       $TAG"
echo "  Commit:    $(git log -1 --format='%h %s' "$COMMIT")"
if [[ -n "$CREATE_BRANCH" ]]; then
  echo "  Branch:    $BRANCH — NEW, cut from $BRANCH_BASE (branch cut: $MINOR stops following main)"
else
  echo "  From:      $FROM"
fi
echo "  Remote:    $REMOTE ($SLUG)"
echo "  Publishes: $GHCR_OWNER/vexviper:${TAG#v}, chart oci://$GHCR_OWNER/charts/vexviper --version ${TAG#v}, binaries on the GitHub release"
if [[ -n "$PREVIOUS" ]]; then
  echo "  Changes:   $(git rev-list --count "$PREVIOUS..$COMMIT") commit(s) since $PREVIOUS"
fi
for w in ${WARNINGS[@]+"${WARNINGS[@]}"}; do
  echo "  ⚠️  $w"
done
echo

if [[ -n "$CREATE_BRANCH" ]]; then
  confirm "Create $BRANCH, tag $TAG and push both to $REMOTE?"
else
  confirm "Create and push $TAG to $REMOTE?"
fi

if [[ "$KIND" == "rc" ]]; then
  MESSAGE="VEXViper $TAG (release candidate for v$VERSION)"
else
  MESSAGE="VEXViper $TAG"
fi
git tag -a "$TAG" -m "$MESSAGE" "$COMMIT"

REFSPECS=()
if [[ -n "$CREATE_BRANCH" ]]; then REFSPECS+=("$CREATE_BRANCH:refs/heads/$BRANCH"); fi
REFSPECS+=("refs/tags/$TAG")
if ! git push --atomic "$REMOTE" "${REFSPECS[@]}"; then
  git tag -d "$TAG" >/dev/null
  die "push failed; local tag $TAG removed again"
fi

if [[ -n "$CREATE_BRANCH" ]]; then after_branch_cut; fi

echo
info "Pushed $TAG. The release workflow is building it now:"
echo "    https://github.com/$SLUG/actions/workflows/release.yml"
echo
info "Once it is green, install it with:"
echo "    helm install vexviper oci://$GHCR_OWNER/charts/vexviper --version ${TAG#v}"
echo "  or pull the image:"
echo "    docker pull $GHCR_OWNER/vexviper:${TAG#v}"
