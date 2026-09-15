# Integrating VEXViper with BOMHort

This document records how VEXViper couples to BOMHort, which API contract it relies on,
and what an upstream integration could look like.

## 1. Integration model

BOMHort (`backend/`, Go 1.25, stdlib HTTP, ClickHouse) exposes **no plugin mechanism**:
no Go `plugin` loading, no gRPC/webhook hooks, no MCP. Its contribution guidelines require
stdlib-only tests, discourage frameworks and ask contributors to *ask first* before adding
Go dependencies. VEXViper needs `openvex/go-vex`, the MCP Go SDK, `packageurl-go` and
`yaml.v3`, so the correct integration is an **out-of-tree sidecar speaking the public REST
API** (`docs/api-reference` calls this "custom tooling"). Benefits:

* zero changes to BOMHort; survives the announced 1.0 API freeze;
* independent release cadence and security review of LLM code;
* deployable next to BOMHort (CronJob/Deployment) or on a developer laptop (stdio MCP).

## 2. API contract used

| Call | Purpose | Client method |
|---|---|---|
| `GET /health` | readiness | `Healthy` |
| `GET /api/v1/sboms?page&page_size&search` | enumerate SBOMs (watch mode, `--sbom` lookup by id / `document_name` / `source_file`) | `ListSBOMs`, `AllSBOMs`, `FindSBOM` |
| `GET /api/v1/sboms/{id}/vulnerabilities` | **the findings**: `vuln_id`, `purl`, `severity`, `summary`, `fixed_version`, `vex_status` | `Vulnerabilities` |
| `GET /api/v1/sboms/{id}/dependencies` | dependency tree → direct/transitive evidence | `Dependencies` |
| `GET /api/v1/sboms/{id}/download` | original SBOM → repository hints only (VCS external refs, root PURLs, main Go module) | `DownloadSBOM` |
| `POST /api/v1/sboms/upload` + `X-Filename: <name>.openvex.json` + `X-API-Key` | ingest the generated document | `UploadVEX` |
| `GET /api/v1/vex/statements` | verify ingestion (`--wait`) | `VEXStatements` |

Rate limit (100 req / 10 s) is respected by the client's paging and there is no polling
tighter than `--wait`'s 2 s interval.

### Matching rules that shape the output

BOMHort applies a VEX statement to a finding when `statement.vuln_id == finding.vuln_id`
**and** `statement.product_purl == finding.purl` — plain string equality. Therefore every
statement VEXViper emits:

* uses `vulnerability.name = finding.vuln_id` (exactly as BOMHort returned it, e.g. `GO-2025-…`
  or `GHSA-…`, whatever BOMHort chose as primary id);
* uses `products[0].@id = finding.purl` **and** `products[0].identifiers.purl = finding.purl`
  (BOMHort reads `identifiers.purl` first, then `@id`);
* never normalises, re-encodes or re-qualifies the PURL.

Only OpenVEX is supported by BOMHort, hence only OpenVEX is emitted.

`GET /sboms/{id}/vulnerabilities` LEFT JOINs `vex_statements` without collapsing to the
newest statement, so after several uploads for the same SBOM the endpoint returns **one row
per matching statement** (same `vuln_id`/`purl`, possibly differing `vex_status`). VEXViper
dedupes findings by `(vuln_id, purl)` — any non-empty status counts as "already VEXed" — and
uses `/api/v1/vex/statements` (`vex_timestamp`) whenever the *newest* verdict matters
(re-assessment TTL). Worth raising upstream alongside #255 ("latest statement wins").

### Upload requirements

* `AUTH_ENABLED=true` with `API_KEYS=…` (or `SERVICE_TOKEN`) on the api-gateway;
* the gateway must be able to write `SBOM_DIR/pushed/` (or use the S3 `skipScan` bucket);
* the ingestion-watcher picks the file up and the parsing-worker applies it; typical
  latency in the E2E stack is 5–20 s. `vexviper generate --upload --wait 3m` polls
  `/api/v1/vex/statements` until the document's statements appear.

## 3. Deployment next to BOMHort

`deploy/helm/vexviper` renders

* `mode: cronjob` (default) — `vexviper watch --once` every 6 h, state and repo cache on an
  optional PVC. Idempotent: an SBOM is re-processed only when its
  `vuln_count@ingested_at` fingerprint changes or `--regenerate` is set. Settled verdicts
  (`not_affected`, `fixed`) are never re-sent to the provider unless `--force` is used.
* `mode: deployment` — continuous poller.
* `mode: mcp` — `mcp-serve --transport http` behind a ClusterIP Service so agents/LLM hosts
  in the cluster can run interactive triage.

Secrets: one Secret with `api-key` (BOMHort) and optionally `openai-api-key`.

## 4. Safety posture

* Default provider is **heuristic**; it can only produce `not_affected` when govulncheck
  proves the vulnerable symbol unreachable. LLM providers are opt-in.
* LLM claims of `not_affected`/`fixed` without deterministic evidence are downgraded to
  `under_investigation` unless explicitly allowed.
* Upload is opt-in; the default is a reviewable file. `author_role` and `status_notes` are
  transparent about automation and confidence.
* No SBOM content is sent anywhere except to the configured provider; with `heuristic`
  nothing leaves the machine besides the git clone and OSV lookups.

## 5. Upstream issues (seebom-labs/BOMHort)

Filed as tracking epic [BOMHort#338](https://github.com/seebom-labs/BOMHort/issues/338):

| Issue | Feature | Why VEXViper needs it |
|---|---|---|
| [#332](https://github.com/seebom-labs/BOMHort/issues/332) | `source_repo` / `source_ref` per SBOM | repo resolution without PURL guessing or `repo.sboms` pins |
| [#333](https://github.com/seebom-labs/BOMHort/issues/333) | `since`/cursor listing, `vex_status=missing` filter | `watch` passes over 15k SBOMs without O(n) re-reads |
| [#335](https://github.com/seebom-labs/BOMHort/issues/335) | one row per `(vuln_id, purl)`, latest statement wins, `vex_timestamp` | re-triage TTL without paging `/vex/statements` |
| [#336](https://github.com/seebom-labs/BOMHort/issues/336) | idempotent upload + job status | know whether a pushed document matched anything |
| [#334](https://github.com/seebom-labs/BOMHort/issues/334) | statement provenance + automated/human badge | make LLM drafts reviewable and auditable |
| [#337](https://github.com/seebom-labs/BOMHort/issues/337) | outbound webhooks | trigger generation instead of polling |

The original proposal text is kept below for context.


> **Title:** Document VEXViper as a VEX-generation companion; expose `vex_justification` in the vulnerabilities API
>
> BOMHort can consume OpenVEX but has no way to produce it, so every finding stays
> effective until a human writes VEX. [VEXViper](https://github.com/mfahlandt/VEXViper) is
> an out-of-tree Go sidecar that reads `/api/v1/sboms/{id}/vulnerabilities`, resolves the
> product repository, runs govulncheck/collects evidence, asks a configurable assessment
> provider (rules / OpenAI-compatible / MCP tool) and uploads a go-vex-validated OpenVEX
> document via `/api/v1/sboms/upload`. Verified against BOMHort's own 0.6.1 SBOM (9/9
> statements applied).
>
> Proposals:
> 1. Add a `docs/integrations/vexviper` page (I can open the PR).
> 2. Return `vex_justification`, `vex_status_notes` and `vex_updated_at` alongside
>    `vex_status` in `/api/v1/sboms/{id}/vulnerabilities` so overlays (#255) and reviewers
>    can see *why* and *when* a statement was applied (and re-triage tools can age them
>    without paging `/api/v1/vex/statements`).
> 3. Make the ingestion result observable: an endpoint (or a field on the upload response)
>    that reports whether a pushed `*.openvex.json` was applied and to how many findings —
>    today clients must poll `/api/v1/vex/statements`.
> 4. (Optional) accept `X-Filename` documents with a `vexviper` tooling marker in the
>    "companion OpenVEX" export planned in #255 so generated and hand-written statements can
>    be distinguished.

## 6. Re-running VEX generation over time

BOMHort periodically refreshes its OSV database and recomputes findings, but it has no
scheduler or hook for *re-triage* — an applied statement stays until a newer one for the
same `(vuln_id, purl)` is ingested. VEXViper therefore owns the re-run policy
(`watch.reassess_after`, see README "Re-running over time"): fingerprint changes trigger
assessment of new findings; a TTL re-opens `under_investigation`/`affected` verdicts using
`vex_timestamp` from `/api/v1/vex/statements`. Because BOMHort resolves conflicts by newest
timestamp, re-uploads are idempotent. An upstream `vex_updated_at` on the vulnerabilities
endpoint would remove the need to page through all statements (proposal 2/3 above).

### Scale: many SBOMs, few distinct questions

A BOMHort instance with 15 000 SBOMs typically describes a few hundred product builds.
VEXViper's assessment cache (`cache.*`, README "Scaling to thousands of SBOMs") keys verdicts
by provider, product commit, finding and an evidence fingerprint, so each distinct question
is paid for once and reused for every SBOM that shares the build. What limits this today is
BOMHort's data model, not VEXViper:

* there is no per-SBOM **source repository / commit** field — VEXViper infers it from
  PURLs and SBOM hints, which is where most misses come from (see proposal 1 in §5 and the
  upstream issues linked there);
* `GET /api/v1/sboms` has no `since`/cursor and `/vulnerabilities` no `vex_filter=missing`,
  so `watch` must list everything each pass.

SBOM producers can help: include the VCS URL **and exact commit** (SPDX `ExternalRef`
`SECURITY`/`OTHER` + `packageSourceInfo`, CycloneDX `externalReferences[type=vcs]` +
`pedigree.commits`), build metadata (Go version, build tags) and a stable product identifier.

### Cost visibility

Every run reports provider usage (calls, tokens, Copilot premium requests, model, cache hits)
per finding, per SBOM and cumulatively in the watch state file; see README "Cost tracking".

## 7. Using a GitHub Copilot subscription as LLM source

| Route | Programmatic? | Status |
|---|---|---|
| **GitHub Models** (`provider: github`) — `https://models.github.ai/inference`, OpenAI-compatible, auth `Bearer <GitHub token>`, header `X-GitHub-Api-Version` | yes (CI, CronJob) | **supported**; billed to the GitHub/Copilot plan; models like `openai/gpt-4.1`, `openai/o4-mini`, `meta/llama-…`. Token: fine-grained PAT with `models: read` or Actions `GITHUB_TOKEN` with `permissions: models: read`. |
| **Copilot CLI, non-interactive** (`provider: copilot`) — `copilot -p <prompt> -s --no-ask-user --deny-tool=shell/write/edit`; auth = the CLI's login (`/login`, `gh auth login`, `GH_TOKEN`/`COPILOT_GITHUB_TOKEN`) | yes (laptop, CI runner with a logged-in CLI) | **supported & verified**; ~15 s/finding; official scripting mode of the Copilot CLI, covered by the Copilot seat. `in_repo: true` lets it read the product checkout. |
| **Copilot as MCP host** — VS Code Copilot Chat / Copilot CLI / Copilot coding agent calls `vexviper mcp-serve` tools (`list_findings` → `get_repo_context` → model reasons → `draft_vex` → `upload_vex`) | interactive / agentic | supported today; the Copilot model does the assessment inside the host, human in the loop. |
| Copilot Chat internal API (`api.githubcopilot.com` via token exchange) | — | **not implemented**: undocumented, ToS restricts to Copilot clients, breaks without notice. |

GitHub Actions example:

```yaml
permissions: { contents: read, models: read }
steps:
  - run: vexviper generate --provider github --sbom ${{ github.event.repository.name }}-${{ github.ref_name }} --upload
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      BOMHORT_API_KEY: ${{ secrets.BOMHORT_API_KEY }}
      VEXVIPER_BOMHORT_URL: https://bomhort.example.com
```

## 8. Should the BOMHort Go client be its own module?

Yes, eventually — `internal/bomhort` is already stdlib-only, VEXViper-agnostic and ships a
fake server (`bomhorttest`), so it can be extracted mechanically as e.g.
`github.com/seebom-labs/bomhort-go`. It is kept in-tree for now because (a) the API is not
frozen before BOMHort 1.0 and a separate module would double every field change into a
two-repo release, and (b) the right owner is the `seebom-labs` org (official client, matches
their stdlib-only policy), which is a maintainer decision. Until then the package boundary is
kept clean so `git filter-repo --path internal/bomhort` yields the library with history.

## 9. Known limitations

* Repository resolution depends on SBOM quality: syft `dir:` SBOMs of Go repos resolve
  (VCS ref / main module); `pkg:generic/<name>@<ver>` roots without VCS refs need `--repo`
  or a `repo.sboms` pin in the config (matched by SBOM id / document name / source file).
* govulncheck covers Go only. Other ecosystems get version-based evidence and OSV context,
  so without an LLM they end as `under_investigation`.
* The heuristic provider never claims `affected` without govulncheck reachability.
