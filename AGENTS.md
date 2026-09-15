# Role & Project Context
You are an expert Senior Software Engineer specializing in Go, supply-chain security (SBOM/VEX/OpenVEX), vulnerability triage and LLM/MCP tooling.

We are building **VEXViper**: a Go sidecar for [BOMHort](https://github.com/seebom-labs/BOMHort) that turns BOMHort's CVE findings for an SBOM into a validated **OpenVEX** document and uploads it back. For every finding it resolves and clones the product's source repository, gathers deterministic evidence (govulncheck reachability, OSV metadata, dependency depth, symbol references), asks a configurable assessment provider (heuristic, OpenAI-compatible, GitHub Models, GitHub Copilot CLI or an MCP host) for a verdict, applies guardrails, and emits `not_affected` / `affected` / `fixed` / `under_investigation` statements BOMHort applies by exact `(vuln_id, purl)` match.

VEXViper is a **sidecar, not a fork**: it only talks to BOMHort through the public REST API and never touches ClickHouse or BOMHort internals.

# Architecture Overview
One Go binary, `vexviper`, with three subcommands:

| Command | Purpose |
|---------|---------|
| `vexviper generate --sbom <ref>` | One SBOM → OpenVEX file (+ optional `--upload --wait`) |
| `vexviper watch [--once]` | Poll BOMHort, process new/changed SBOMs, re-assess expired verdicts (`watch.reassess_after`) |
| `vexviper mcp-serve` | MCP server (stdio or streamable HTTP) exposing the pipeline to MCP-capable assistants |

Pipeline per SBOM: `source.Load` (BOMHort findings + dependency tree + SBOM download) → filter (skip already-VEXed unless `--regenerate`/`--force`) → `pipeline.MaterializeRepo` → `evidence.Collect` → `llm.Provider.Assess` → `vexgen` guardrails + go-vex validation → write `<name>.vexviper.openvex.json` → optional `bomhort.Client.UploadVEX` → `pipeline.Wait` for ingestion.

Packages (`internal/`):
- `bomhort` – REST client for the BOMHort api-gateway (`/api/v1/sboms`, `/vulnerabilities`, `/dependencies`, `/download`, `/vex/statements`, `/sboms/upload`), retries on 429, `APIError`. `bomhorttest` is an in-memory fake gateway that mimics VEX ingestion for tests/E2E.
- `config` – YAML config + `VEXVIPER_*` env overrides + validation. Providers: `heuristic|openai|github|copilot|mcptool`. Per-SBOM repo pinning via `repo.sboms[]{match, repo}`.
- `source` – Loads findings for one SBOM, dedupes BOMHort's duplicate rows by `(vuln_id, purl)`, marks direct dependencies, derives repo hints from the SBOM.
- `sbom` – Minimal SPDX/CycloneDX reader (only what is needed for repo hints and package names; BOMHort already parsed the SBOM).
- `repo` – Repo URL resolution (SBOM hints, root PURLs, `owner/name[@ref]`), git clone with cache dir, `GIT_CONFIG_GLOBAL=/dev/null`.
- `evidence` – Deterministic evidence (its `Item.Kind`/`Strong` set is what `assesscache.Fingerprint` hashes): version comparison, dependency depth, govulncheck (`-json`, multi-module, `go run …@latest` fallback when the installed binary is too old, `findGoBin` when `go` is not on PATH), symbol grep, OSV details. govulncheck evidence is attached **only to `pkg:golang/` PURLs**; other ecosystems get `no_reachability_analysis`.
- `osv` – OSV API client (single lookups with backoff).
- `llm` – `Provider` interface, `Request`/`Assessment` types mirroring OpenVEX fields, JSON schema for structured output, `Usage` accounting (calls, tokens, Copilot premium requests, model, cache hits), providers: `Heuristic`, `OpenAI` (also GitHub Models via `ProviderName: github`, parses `usage`), `CopilotCLI` (runs `copilot -p … -s --output-format json --no-ask-user --deny-tool=shell/write/edit`, parses the JSONL events for answer + usage), `MCPTool`, `Mock` for tests.
- `pipeline/metrics.go` – hand-rolled Prometheus text exposition (`/metrics`, `/healthz`); `pipeline/watch.go` – fingerprint-driven poller with worker pool (`watch.concurrency`), per-pass budget reset and state file.
- `bomhort/ratelimit.go` – sliding-window client pacing (`bomhort.rate_limit`, default 90 / 10 s) applied inside `Client.do` before every request.
- `llm/budget.go` – `Budget` spend meter (`llm.budget.*`); when exhausted the pipeline *defers* findings (no statement, SBOM not marked processed) instead of emitting cheap verdicts.
- `assesscache` – file-backed verdict cache keyed by provider+model · product commit (or repo@ref) · vuln_id · purl · evidence fingerprint · prompt `Version`. Makes thousands of SBOMs affordable; bump `Version` when the prompt/schema changes.
- `vexgen` – Builds and validates the OpenVEX document with `github.com/openvex/go-vex`; applies **guardrails**.
- `pipeline` – Orchestration (`Run`, `RunOptions`, `Outcome`), `NewProvider`, `MaterializeRepo`, `staleStatements`/`ReassessAfter`, `Wait`; `watch.go` holds the polling loop and `WatchState`.
- `mcpserver` – MCP tools: `list_sboms`, `list_findings`, `get_repo_context`, `draft_vex`, `generate_vex`, `upload_vex`, `list_vex_statements`.

Other locations: `cmd/vexviper` (CLI, flags, summary), `test/integration` (`-tags=integration`, needs a live BOMHort), `hack/e2e-bomhort.sh` + `hack/docker-compose.e2e.yml` (isolated BOMHort stack on :18080, key `vexviper-e2e-key`), `deploy/helm/vexviper` (CronJob or Deployment), `docs/INTEGRATION.md` (API contract, deployment, safety posture, upstream findings), `examples/` (config, MCP client config, generated VEX for BOMHort 0.6.1).

# Tech Stack
- **Language:** Go (`go.mod` `go 1.25.x`; Dockerfile base Go 1.26). Module path `github.com/seebom-labs/vexviper`.
- **Direct dependencies (keep minimal):** `openvex/go-vex`, `modelcontextprotocol/go-sdk`, `package-url/packageurl-go`, `golang.org/x/mod`, `gopkg.in/yaml.v3`. Everything else is stdlib (`net/http`, `log/slog`, `encoding/json`, `os/exec`).
- **External tools at runtime (optional):** `git`, `go` + `govulncheck`, `copilot` CLI.
- **Deployment:** Container image + Helm chart; Kubernetes CronJob (`watch --once`) is the default mode.

# Architectural Directives
**BOMHort matching contract:** BOMHort applies a statement when `statement.vuln_id == finding.vuln_id` **and** `statement.product_purl == finding.purl` (string equality). Always emit `vulnerability.name`, `products[0].@id` and `products[0].identifiers.purl` exactly as BOMHort returned them. Never normalise, re-encode or re-qualify PURLs or vuln ids.

**Deterministic evidence first, LLM second:** The provider only ever sees an `evidence.Report`. Guardrails in `vexgen` downgrade `not_affected`/`fixed` claims that are not backed by strong deterministic evidence (e.g. `govulncheck_not_reachable`) to `under_investigation`, preserving the original verdict in `status_notes`. Never weaken the guardrails to "make the LLM's answer stick".

**Token discipline:** Findings that already carry a `vex_status` are skipped. `--regenerate` revisits only non-settled verdicts (`under_investigation`, `affected`); settled verdicts (`not_affected`, `fixed`) are only re-assessed with `--force` (hard regenerate) — never spend provider tokens on closed findings. `watch.reassess_after` follows the same rule. Every provider call must report `llm.Usage`; the pipeline aggregates it into `Outcome.Usage` and the watch state. Verdicts go through `assesscache` (reads skipped on `--regenerate`/`--force`/`--no-cache`, provider errors are never cached); keep the cache key complete when adding inputs that influence a verdict. Check `p.Budget.Exceeded()` before any paid call and `Spend` afterwards; a deferred finding must never receive a statement.

**Concurrency:** `Run` may execute in parallel for different SBOMs (`watch.concurrency`). Shared state must be safe: `Budget`, `osv.Client`, `Metrics` and `bomhort.RateLimiter` use mutexes, `repo.Cloner` locks per checkout dir, `assesscache` writes atomically, and `vexgen.Build` is serialized because go-vex keeps `vex.DefaultNamespace` in a package global. Run `go test -race ./...` after touching these.

**Provider isolation:** Providers get read-only access. The Copilot CLI provider must always run with `--deny-tool=shell --deny-tool=write --deny-tool=edit --no-ask-user`; `in_repo` only sets the working directory. Secrets (API keys, tokens) are read from env vars / Kubernetes Secrets only, never from config files checked into git.

**Sidecar boundary:** Do not reimplement BOMHort features (SBOM parsing, OSV scanning, VEX ingestion) — consume them via the API. BOMHort quirks (duplicate `/vulnerabilities` rows, latest-statement resolution) are handled defensively in `source`/`pipeline` and documented in `docs/INTEGRATION.md` for upstreaming.

**No git history rewrites on `main`.**

# Executable Commands

```
make build             # bin/vexviper (version from git describe)
make test              # go test ./... -count=1
make test-race         # with -race
make lint              # gofmt check + go vet (incl. -tags=integration ./test/...)
make test-integration  # needs a live BOMHort with AUTH_ENABLED=true (see hack/)
make e2e               # ./hack/e2e-bomhort.sh — full isolated BOMHort stack, ingest, generate, upload, verify
make clean
```

Useful E2E variants:
```
BOMHORT_SRC=~/path/to/BOMHort ./hack/e2e-bomhort.sh            # heuristic provider
VEXVIPER_LLM_PROVIDER=copilot GH_TOKEN=$(gh auth token) ./hack/e2e-bomhort.sh --keep
docker compose -p vexviper-e2e -f hack/docker-compose.e2e.yml down -v   # tear down --keep stack
```

Local run against a dev BOMHort (auth off, :8080):
```
bin/vexviper generate --bomhort http://localhost:8080 --sbom <name-or-id> --provider heuristic --out /tmp/out
```

If `go` is not on PATH in your shell: `export PATH=$HOME/go/bin:$HOME/sdk/go<ver>/bin:$PATH GOTOOLCHAIN=local`.

# Code Style & Conventions

## Go
- Idiomatic Go, stdlib first. Handle errors explicitly; wrap with `%w` and context (`fmt.Errorf("bomhort: …: %w", err)`).
- Logging via `log/slog` with key/value pairs; the pipeline logs one `assessed` line per finding (`vuln`, `purl`, `status`, `confidence`, `provider`).
- Configuration: every YAML key has a `VEXVIPER_*` env override registered in `Config.ApplyEnv` and a validation rule in `Config.Validate`; document new keys in `examples/vexviper.yaml`, README config table and (if user-facing) `docs/INTEGRATION.md` and Helm `values.yaml`.
- CLI flags live in `cmd/vexviper/main.go`; flags override config, config overrides defaults. Summary output goes to stderr, documents to stdout only with `--stdout`.
- Anything that shells out (`git`, `go`, `govulncheck`, `copilot`) goes through an injectable runner/func so tests can stub it with a fake shell script (`#!/bin/sh` in `t.TempDir()`, see `internal/llm/llm_test.go` (fake `copilot` script), `internal/evidence/evidence_test.go`).
- Tests use `GIT_CONFIG_GLOBAL=/dev/null` and `httptest.Server` fakes; never hit the network or a real BOMHort in unit tests. `llm.Mock` and `bomhorttest.Server` are the standard doubles.
- Keep OpenVEX semantics correct: `not_affected` requires a `justification`, `affected` should carry an `action_statement`; always run the document through go-vex validation (`vexgen`).

## Git & PRs
- Commits are **DCO signed-off** (`git commit -s`). **Do not add `Co-authored-by` trailers** — project rules forbid them.
- Conventional, imperative subject lines (`Add …`, `Fix …`, `Keep …`), body explains the why.
- PRs go to `seebom-labs/VEXViper` `main` from a feature branch on the fork; describe behaviour change, tests and doc updates.
- **Releases:** pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml` → binaries + SPDX SBOM + checksums on the GitHub release, multi-arch image `ghcr.io/seebom-labs/vexviper:{X.Y.Z,X.Y,latest}` (cosign keyless), Helm chart `oci://ghcr.io/seebom-labs/charts/vexviper` (chart+app version = tag). `main` publishes `:main`. Bump `deploy/helm/vexviper/Chart.yaml` `version`/`appVersion` in the release commit; Dependabot (gomod/actions/docker, weekly) keeps deps current.

# Boundaries
- **Always do:** Write unit tests for every new package, provider, flag and guardrail. Run `make lint test` before pushing. Update `README.md`, `docs/INTEGRATION.md`, `examples/vexviper.yaml` and the Helm chart when adding config keys, flags, providers or MCP tools. Regenerate `examples/bomhort-0.6.1.openvex.json` via the E2E script when statement shape changes (normalise `tooling` to `vexviper/dev …`).
- **Workflow for every feature/fix:** (1) Write code, (2) tests for all new behaviour (unit; E2E when BOMHort interaction changes), (3) docs/config/Helm updates, (4) `make lint test` green, (5) commit with `-s`, push branch. Open a PR only when asked.
- **Ask first:** Before adding third-party Go dependencies, changing the OpenVEX statement shape or the upload/matching contract with BOMHort, loosening guardrails, changing Helm manifest structure, or rewriting git history.
- **Never do:** Never commit secrets, tokens or real API keys (the only fixed key is the E2E dummy `vexviper-e2e-key`). Never let a provider run with shell/write tools enabled. Never emit `not_affected` without a justification or without deterministic evidence passing the guardrails. Never modify PURLs/vuln ids returned by BOMHort. Never add `Co-authored-by` trailers. Never push to `seebom-labs/VEXViper` directly or force-push `main`.

# Security Posture
- Cloned repositories are untrusted input: no build/test execution inside them beyond `govulncheck`/`go run …govulncheck` with `GOFLAGS=-mod=mod`, bounded by the global `timeout` and `evidence.Collector.Timeout`; the clone cache (`repo.cache_dir`) is disposable.
- LLM output is parsed as strict JSON against `llm.JSONSchema`, validated as OpenVEX, then guardrailed — model text never reaches BOMHort unvalidated.
- BOMHort uploads require `AUTH_ENABLED=true` and an `X-API-Key`/service token; VEXViper never disables auth on the BOMHort side.
- Config/Helm: tokens via `secretKeyRef`/`existingSecret`; `examples/vexviper.yaml` ships empty credential fields only.
