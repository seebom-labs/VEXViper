# VEXViper Release Process

VEXViper follows the same release-branch model as BOMHort: every minor has a
`release/vX.Y` branch, every release tag is cut from that branch, and fixes land
on `main` first before being backported.

```
main           ●──●──●──●──●──●──●──▶   next minor continues here
               │        │        │
          branch cut  fix #42  fix #47     merge fixes on main first,
               │        ↓        ↓         then make cherry-pick
release/v0.8   ●────────●────────●──▶
            v0.8.0-rc.1 rc.2   v0.8.0
```

## Release branches

- The first `make release-rc VERSION=X.Y.0` cuts `release/vX.Y` from remote
  `main` and tags `vX.Y.0-rc.1` on it.
- Later RCs, the final release and patch releases tag the head of
  `release/vX.Y` (or a `REF=` on that branch).
- Fixes always merge to `main` first. Backport them with
  `make cherry-pick PR=<n> BRANCH=X.Y`, review the generated PR, then cut the
  next RC or patch release.
- To patch a minor that predates release branches, run
  `make release-branch VERSION=X.Y`; it starts from the latest final `vX.Y.*`
  tag, not from current `main`.
- Dependabot targets `main` only. Security dependency updates reach release
  branches through reviewed cherry-picks.

**Repository settings:** protect `release/**` like `main`: require pull
requests, required CI/E2E checks and review; disallow force pushes and deletion.
The scripts create the branch, but all later changes should arrive through PRs.

## Commands

Preview with `DRY_RUN=1`; skip prompts with `YES=1`. Scripts resolve commits
from the canonical remote, never from unpushed local state. `REMOTE=` overrides
the remote pointing at `seebom-labs/*`; cherry-picks push to `PUSH_REMOTE=`
(default `origin`).

```sh
make release-rc VERSION=0.8.0 DRY_RUN=1
make release-rc VERSION=0.8.0 YES=1        # v0.8.0-rc.1, cuts release/v0.8 if needed

make cherry-pick PR=42 BRANCH=0.8          # fix merged on main → backport PR
make release-rc VERSION=0.8.0 YES=1        # v0.8.0-rc.2 after the backport

make release VERSION=0.8.0 DRY_RUN=1
make release VERSION=0.8.0 YES=1           # final; warns if branch moved past last RC
make release VERSION=0.8.0 REF=v0.8.0-rc.2 # final exactly what was tested

make release-branch VERSION=0.7 YES=1      # old minor branch from latest v0.7.*
make release VERSION=0.7.2 YES=1           # patch after backports
```

`make cherry-pick` finds squash-merged PRs locally by the `(#N)` subject suffix.
For rebase-merged PRs it needs the real GitHub CLI (`GH=/path/to/gh`) to ask
GitHub which commits belong to the PR. The `gh` binary on some developer
machines is not GitHub CLI; set `GH=` explicitly when needed.

## Publishing

Pushing a tag starts `.github/workflows/release.yml`:

1. validate `X.Y.Z` or `X.Y.Z-{rc,alpha,beta}.N` and reject tags that are not
   on `release/vX.Y`;
2. run the normal lint/test/race suite;
3. publish the multi-arch image `ghcr.io/<owner>/vexviper:<version>`;
4. for final releases only, also move `ghcr.io/<owner>/vexviper:X.Y` and
   `ghcr.io/<owner>/vexviper:latest` (RCs never move stable tags);
5. package the Helm chart with `--version <version> --app-version <version>` and
   push `oci://ghcr.io/<owner>/charts/vexviper --version <version>`;
6. attach linux/darwin amd64/arm64 binaries, checksums and an SPDX SBOM to the
   GitHub release;
7. generate release notes against the previous **final** release, not the
   previous RC, using `.github/release.yml` label categories.

Pushes to `main` still publish only `ghcr.io/<owner>/vexviper:main`.

## Installing a release candidate

RCs are SemVer pre-releases. Helm and Docker users must ask for them explicitly;
production installs tracking `latest` or an unqualified chart version will not
receive an RC.

```sh
helm install vexviper oci://ghcr.io/seebom-labs/charts/vexviper \
  --version 0.8.0-rc.1 \
  --set bomhort.url=http://bomhort-api-gateway:8080

helm upgrade vexviper oci://ghcr.io/seebom-labs/charts/vexviper \
  --version 0.8.0-rc.1 --reuse-values

docker pull ghcr.io/seebom-labs/vexviper:0.8.0-rc.1
```

The chart `appVersion` is the RC version and `image.tag` defaults to it. If your
values pin `image.tag`, unset it or set it to the RC tag.

## Release candidate from a branch

To publish an installable RC from a branch that is not merged yet, run the
Release workflow manually and enter a pre-release version such as
`0.8.0-rc.1`. Final versions are rejected in manual runs. The workflow builds
from the selected branch, creates tag `v0.8.0-rc.1` at the built commit and
publishes the same image, chart and release assets as a tag-triggered RC.

A fork publishes to `ghcr.io/<fork-owner>/vexviper` and
`oci://ghcr.io/<fork-owner>/charts/vexviper`; make those packages public or log
in to GHCR before installing.

## E2E pin on release branches

The E2E workflow runs on PRs and pushes to `release/**` as well as `main`. Keep
`BOMHORT_PINNED_REF` at the BOMHort commit that the minor was tested against on
that release branch; do not silently advance it while stabilising a patch unless
the patch deliberately depends on newer BOMHort API behaviour.
