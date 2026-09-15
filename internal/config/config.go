// Package config loads VEXViper configuration from a YAML file, environment
// variables (VEXVIPER_*) and explicit overrides, in that order of precedence
// (later wins).
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EnvPrefix is the prefix for all environment variable overrides.
const EnvPrefix = "VEXVIPER_"

// Provider names accepted in LLM.Provider.
const (
	ProviderHeuristic = "heuristic"
	ProviderOpenAI    = "openai"
	ProviderMCPTool   = "mcptool"
	// ProviderCopilot drives the GitHub Copilot CLI in non-interactive mode
	// (`copilot -p … -s`), using the user's Copilot subscription.
	ProviderCopilot = "copilot"
	// ProviderGitHub uses GitHub Models (OpenAI-compatible inference endpoint
	// billed to a GitHub / Copilot account, authenticated with a GitHub token).
	ProviderGitHub = "github"

	// GitHubModelsURL is the default GitHub Models inference endpoint.
	GitHubModelsURL = "https://models.github.ai/inference"
	// GitHubModelsAPIVersion is sent as X-GitHub-Api-Version.
	GitHubModelsAPIVersion = "2022-11-28"
)

// MCP transports accepted in MCP.Transport.
const (
	MCPTransportStdio = "stdio"
	MCPTransportHTTP  = "http"
)

// Config is the root configuration.
type Config struct {
	BOMHort BOMHort `yaml:"bomhort"`
	LLM     LLM     `yaml:"llm"`
	Repo    Repo    `yaml:"repo"`
	VEX     VEX     `yaml:"vex"`
	Watch   Watch   `yaml:"watch"`
	Cache   Cache   `yaml:"cache"`
	// Timeout for the whole generation of a single SBOM.
	Timeout time.Duration `yaml:"timeout"`
}

// Cache configures the assessment cache that lets identical questions
// (same provider, product commit, finding and evidence) reuse a verdict
// across SBOMs instead of paying for another provider call.
type Cache struct {
	// Enabled toggles the cache (default true).
	Enabled bool `yaml:"enabled"`
	// Dir holds the cache files (default "<repo.cache_dir>/assessments").
	Dir string `yaml:"dir"`
	// TTL expires entries; 0 keeps them until commit or evidence changes.
	TTL time.Duration `yaml:"ttl"`
}

// CacheDir returns the effective cache directory.
func (c Config) CacheDir() string {
	if c.Cache.Dir != "" {
		return c.Cache.Dir
	}
	return filepath.Join(c.Repo.CacheDir, "assessments")
}

// BOMHort holds connection settings for the BOMHort REST API.
type BOMHort struct {
	URL          string `yaml:"url"`
	APIKey       string `yaml:"api_key"`
	ServiceToken string `yaml:"service_token"`
	// APIKeyEnv names an environment variable holding the key (preferred over api_key in files).
	APIKeyEnv string `yaml:"api_key_env"`
}

// LLM selects and configures the assessment provider.
type LLM struct {
	Provider string `yaml:"provider"`
	// MinConfidence below which an assessment is downgraded to under_investigation.
	MinConfidence float64 `yaml:"min_confidence"`
	// AllowUnsupportedNotAffected lets an LLM emit not_affected without deterministic evidence.
	AllowUnsupportedNotAffected bool    `yaml:"allow_unsupported_not_affected"`
	OpenAI                      OpenAI  `yaml:"openai"`
	GitHub                      GitHub  `yaml:"github"`
	Copilot                     Copilot `yaml:"copilot"`
	MCP                         MCP     `yaml:"mcp"`
}

// Copilot configures the GitHub Copilot CLI provider. Authentication is the
// CLI's own (`copilot` → /login, `gh auth login`, COPILOT_GITHUB_TOKEN).
type Copilot struct {
	Command string        `yaml:"command"`
	Model   string        `yaml:"model"`
	Args    []string      `yaml:"args"`
	Timeout time.Duration `yaml:"timeout"`
	// InRepo runs the CLI inside the cloned product repository so the model
	// may read source files (tools shell/write/edit stay denied).
	InRepo bool `yaml:"in_repo"`
}

// OpenAI configures any OpenAI-compatible chat completions endpoint
// (OpenAI, Azure, GitHub Models, Ollama, vLLM, LiteLLM...).
type OpenAI struct {
	BaseURL   string        `yaml:"base_url"`
	Model     string        `yaml:"model"`
	APIKey    string        `yaml:"api_key"`
	APIKeyEnv string        `yaml:"api_key_env"`
	Timeout   time.Duration `yaml:"timeout"`
	// Temperature for the completion; 0 gives the most deterministic output.
	Temperature float64 `yaml:"temperature"`
}

// GitHub configures the GitHub Models provider. The token needs the
// `models:read` scope (fine-grained PAT) or is the GITHUB_TOKEN of a workflow
// with `models: read` permission.
type GitHub struct {
	BaseURL     string        `yaml:"base_url"`
	Model       string        `yaml:"model"`
	Token       string        `yaml:"token"`
	TokenEnv    string        `yaml:"token_env"`
	Timeout     time.Duration `yaml:"timeout"`
	Temperature float64       `yaml:"temperature"`
}

// MCP configures the MCP server VEXViper connects to as a client and the tool
// it calls for an assessment.
type MCP struct {
	Transport string            `yaml:"transport"`
	Command   string            `yaml:"command"`
	Args      []string          `yaml:"args"`
	Env       map[string]string `yaml:"env"`
	URL       string            `yaml:"url"`
	Headers   map[string]string `yaml:"headers"`
	Tool      string            `yaml:"tool"`
	Timeout   time.Duration     `yaml:"timeout"`
}

// Repo configures source repository resolution.
type Repo struct {
	CacheDir string `yaml:"cache_dir"`
	// Override forces the product repository (URL or owner/name).
	Override string `yaml:"override"`
	// Clone disables/enables cloning; when false only metadata is used.
	Clone bool `yaml:"clone"`
	// Govulncheck enables running govulncheck when the product is a Go module.
	Govulncheck bool `yaml:"govulncheck"`
	// SBOMs maps individual SBOMs to their source repository. The first
	// matching entry wins and takes precedence over hints from the SBOM
	// itself; Override (global) still wins over both.
	SBOMs []SBOMRepo `yaml:"sboms"`
}

// SBOMRepo pins the repository for SBOMs whose id, document name or source
// file matches Match (exact string or path.Match glob, e.g. "kubelb-*").
type SBOMRepo struct {
	Match string `yaml:"match"`
	// Repo is a URL or owner/name[@ref]. A ref of "{version}" is replaced by
	// the version derived from the SBOM name (e.g. kubelb-1.4.2 → v1.4.2).
	Repo string `yaml:"repo"`
}

// RepoFor returns the configured repository for an SBOM identified by any of
// the given names (id, document name, source file), or "" when none matches.
func (r Repo) RepoFor(names ...string) string {
	for _, e := range r.SBOMs {
		if e.Match == "" || e.Repo == "" {
			continue
		}
		for _, n := range names {
			if n == "" {
				continue
			}
			if n == e.Match {
				return e.Repo
			}
			if ok, err := path.Match(e.Match, n); err == nil && ok {
				return e.Repo
			}
		}
	}
	return ""
}

// VEX configures document metadata.
type VEX struct {
	Author     string `yaml:"author"`
	AuthorRole string `yaml:"author_role"`
	Supplier   string `yaml:"supplier"`
	Namespace  string `yaml:"namespace"`
	OutDir     string `yaml:"out_dir"`
	// Upload pushes the generated document to BOMHort.
	Upload bool `yaml:"upload"`
	// Regenerate also re-assesses vulns that already carry a vex_status,
	// except settled verdicts (not_affected, fixed). A hard regenerate is
	// only available via `vexviper generate --force`.
	Regenerate bool `yaml:"regenerate"`
}

// Watch configures the polling loop.
type Watch struct {
	Interval  time.Duration `yaml:"interval"`
	StateFile string        `yaml:"state_file"`
	// ReassessAfter periodically revisits under_investigation/affected
	// findings whose VEX statement is older than this (0 = disabled).
	ReassessAfter time.Duration `yaml:"reassess_after"`
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		BOMHort: BOMHort{URL: "http://localhost:8080", APIKeyEnv: "BOMHORT_API_KEY"},
		LLM: LLM{
			Provider:      ProviderHeuristic,
			MinConfidence: 0.6,
			OpenAI: OpenAI{
				BaseURL:   "https://api.openai.com/v1",
				Model:     "gpt-4o-mini",
				APIKeyEnv: "OPENAI_API_KEY",
				Timeout:   120 * time.Second,
			},
			GitHub: GitHub{
				BaseURL:  GitHubModelsURL,
				Model:    "openai/gpt-4.1-mini",
				TokenEnv: "GITHUB_TOKEN",
				Timeout:  120 * time.Second,
			},
			Copilot: Copilot{Command: "copilot", Timeout: 180 * time.Second},
			MCP:     MCP{Transport: MCPTransportStdio, Tool: "assess_vulnerability", Timeout: 120 * time.Second},
		},
		Repo:    Repo{CacheDir: ".vexviper-cache", Clone: true, Govulncheck: true},
		Cache:   Cache{Enabled: true},
		VEX:     VEX{Author: "VEXViper", AuthorRole: "automated triage (LLM-assisted)", Namespace: "https://vexviper.dev/docs", OutDir: "."},
		Watch:   Watch{Interval: 15 * time.Minute, StateFile: ".vexviper-cache/watch-state.json"},
		Timeout: 30 * time.Minute,
	}
}

// Load reads path (if non-empty), applies environment overrides and validates.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	cfg.ApplyEnv(os.LookupEnv)
	return cfg, cfg.Validate()
}

// ApplyEnv applies VEXVIPER_* overrides via lookup (usually os.LookupEnv) and
// resolves *_env indirections for secrets.
func (c *Config) ApplyEnv(lookup func(string) (string, bool)) {
	str := func(key string, dst *string) {
		if v, ok := lookup(EnvPrefix + key); ok {
			*dst = v
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := lookup(EnvPrefix + key); ok {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}
	dur := func(key string, dst *time.Duration) {
		if v, ok := lookup(EnvPrefix + key); ok {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}
	flt := func(key string, dst *float64) {
		if v, ok := lookup(EnvPrefix + key); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				*dst = f
			}
		}
	}

	str("BOMHORT_URL", &c.BOMHort.URL)
	str("BOMHORT_API_KEY", &c.BOMHort.APIKey)
	str("BOMHORT_SERVICE_TOKEN", &c.BOMHort.ServiceToken)
	str("LLM_PROVIDER", &c.LLM.Provider)
	flt("LLM_MIN_CONFIDENCE", &c.LLM.MinConfidence)
	boolean("LLM_ALLOW_UNSUPPORTED_NOT_AFFECTED", &c.LLM.AllowUnsupportedNotAffected)
	str("OPENAI_BASE_URL", &c.LLM.OpenAI.BaseURL)
	str("OPENAI_MODEL", &c.LLM.OpenAI.Model)
	str("OPENAI_API_KEY", &c.LLM.OpenAI.APIKey)
	dur("OPENAI_TIMEOUT", &c.LLM.OpenAI.Timeout)
	str("GITHUB_BASE_URL", &c.LLM.GitHub.BaseURL)
	str("GITHUB_MODEL", &c.LLM.GitHub.Model)
	str("GITHUB_TOKEN", &c.LLM.GitHub.Token)
	dur("GITHUB_TIMEOUT", &c.LLM.GitHub.Timeout)
	str("COPILOT_COMMAND", &c.LLM.Copilot.Command)
	str("COPILOT_MODEL", &c.LLM.Copilot.Model)
	dur("COPILOT_TIMEOUT", &c.LLM.Copilot.Timeout)
	boolean("COPILOT_IN_REPO", &c.LLM.Copilot.InRepo)
	str("MCP_TRANSPORT", &c.LLM.MCP.Transport)
	str("MCP_COMMAND", &c.LLM.MCP.Command)
	if v, ok := lookup(EnvPrefix + "MCP_ARGS"); ok {
		c.LLM.MCP.Args = strings.Fields(v)
	}
	str("MCP_URL", &c.LLM.MCP.URL)
	str("MCP_TOOL", &c.LLM.MCP.Tool)
	dur("MCP_TIMEOUT", &c.LLM.MCP.Timeout)
	str("REPO_CACHE_DIR", &c.Repo.CacheDir)
	boolean("CACHE_ENABLED", &c.Cache.Enabled)
	str("CACHE_DIR", &c.Cache.Dir)
	dur("CACHE_TTL", &c.Cache.TTL)
	str("REPO_OVERRIDE", &c.Repo.Override)
	boolean("REPO_CLONE", &c.Repo.Clone)
	boolean("REPO_GOVULNCHECK", &c.Repo.Govulncheck)
	str("VEX_AUTHOR", &c.VEX.Author)
	str("VEX_AUTHOR_ROLE", &c.VEX.AuthorRole)
	str("VEX_SUPPLIER", &c.VEX.Supplier)
	str("VEX_NAMESPACE", &c.VEX.Namespace)
	str("VEX_OUT_DIR", &c.VEX.OutDir)
	boolean("VEX_UPLOAD", &c.VEX.Upload)
	boolean("VEX_REGENERATE", &c.VEX.Regenerate)
	dur("WATCH_INTERVAL", &c.Watch.Interval)
	str("WATCH_STATE_FILE", &c.Watch.StateFile)
	dur("WATCH_REASSESS_AFTER", &c.Watch.ReassessAfter)
	dur("TIMEOUT", &c.Timeout)

	// Secret indirections: only fill when the direct value is empty.
	if c.BOMHort.APIKey == "" && c.BOMHort.APIKeyEnv != "" {
		if v, ok := lookup(c.BOMHort.APIKeyEnv); ok {
			c.BOMHort.APIKey = v
		}
	}
	if c.LLM.OpenAI.APIKey == "" && c.LLM.OpenAI.APIKeyEnv != "" {
		if v, ok := lookup(c.LLM.OpenAI.APIKeyEnv); ok {
			c.LLM.OpenAI.APIKey = v
		}
	}
	if c.LLM.GitHub.Token == "" && c.LLM.GitHub.TokenEnv != "" {
		if v, ok := lookup(c.LLM.GitHub.TokenEnv); ok {
			c.LLM.GitHub.Token = v
		}
	}
}

// Validate checks internal consistency.
func (c *Config) Validate() error {
	var errs []error
	switch c.LLM.Provider {
	case ProviderHeuristic, ProviderOpenAI, ProviderGitHub, ProviderCopilot, ProviderMCPTool:
	default:
		errs = append(errs, fmt.Errorf("llm.provider %q must be one of %s, %s, %s, %s, %s", c.LLM.Provider, ProviderHeuristic, ProviderOpenAI, ProviderGitHub, ProviderCopilot, ProviderMCPTool))
	}
	if c.LLM.MinConfidence < 0 || c.LLM.MinConfidence > 1 {
		errs = append(errs, fmt.Errorf("llm.min_confidence %v must be within [0,1]", c.LLM.MinConfidence))
	}
	if c.Cache.TTL < 0 {
		errs = append(errs, fmt.Errorf("cache.ttl must not be negative"))
	}
	for i, e := range c.Repo.SBOMs {
		if e.Match == "" || e.Repo == "" {
			errs = append(errs, fmt.Errorf("repo.sboms[%d]: match and repo are required", i))
		} else if _, err := path.Match(e.Match, ""); err != nil {
			errs = append(errs, fmt.Errorf("repo.sboms[%d]: invalid match pattern %q: %v", i, e.Match, err))
		}
	}
	if c.LLM.Provider == ProviderOpenAI {
		if c.LLM.OpenAI.BaseURL == "" || c.LLM.OpenAI.Model == "" {
			errs = append(errs, errors.New("llm.openai.base_url and llm.openai.model are required for provider openai"))
		}
	}
	if c.LLM.Provider == ProviderGitHub {
		if c.LLM.GitHub.BaseURL == "" || c.LLM.GitHub.Model == "" {
			errs = append(errs, errors.New("llm.github.base_url and llm.github.model are required for provider github"))
		}
		if c.LLM.GitHub.Token == "" {
			errs = append(errs, fmt.Errorf("llm.github.token is empty (set %s or llm.github.token_env)", nonEmpty(c.LLM.GitHub.TokenEnv, "VEXVIPER_GITHUB_TOKEN")))
		}
	}
	if c.LLM.Provider == ProviderCopilot && c.LLM.Copilot.Command == "" {
		errs = append(errs, errors.New("llm.copilot.command is required for provider copilot"))
	}
	if c.LLM.Provider == ProviderMCPTool {
		switch c.LLM.MCP.Transport {
		case MCPTransportStdio:
			if c.LLM.MCP.Command == "" {
				errs = append(errs, errors.New("llm.mcp.command is required for stdio transport"))
			}
		case MCPTransportHTTP:
			if c.LLM.MCP.URL == "" {
				errs = append(errs, errors.New("llm.mcp.url is required for http transport"))
			}
		default:
			errs = append(errs, fmt.Errorf("llm.mcp.transport %q must be stdio or http", c.LLM.MCP.Transport))
		}
		if c.LLM.MCP.Tool == "" {
			errs = append(errs, errors.New("llm.mcp.tool is required"))
		}
	}
	if c.Watch.Interval <= 0 {
		errs = append(errs, errors.New("watch.interval must be positive"))
	}
	return errors.Join(errs...)
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
