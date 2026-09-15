package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultValidates(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	if cfg.LLM.Provider != ProviderHeuristic {
		t.Fatalf("default provider = %q, want heuristic", cfg.LLM.Provider)
	}
}

func TestLoadYAMLAndEnvPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vexviper.yaml")
	yaml := `
bomhort:
  url: http://bomhort.internal:8080
  api_key_env: MY_KEY
llm:
  provider: openai
  min_confidence: 0.8
  openai:
    base_url: http://localhost:11434/v1
    model: llama3
vex:
  author: ACME Security
  upload: true
watch:
  interval: 5m
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MY_KEY", "secret-from-env")
	t.Setenv("VEXVIPER_OPENAI_MODEL", "mistral")
	t.Setenv("VEXVIPER_VEX_UPLOAD", "false")
	t.Setenv("VEXVIPER_TIMEOUT", "1h")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BOMHort.URL != "http://bomhort.internal:8080" {
		t.Errorf("url = %q", cfg.BOMHort.URL)
	}
	if cfg.BOMHort.APIKey != "secret-from-env" {
		t.Errorf("api key indirection failed: %q", cfg.BOMHort.APIKey)
	}
	if cfg.LLM.OpenAI.Model != "mistral" {
		t.Errorf("env should override yaml model, got %q", cfg.LLM.OpenAI.Model)
	}
	if cfg.LLM.OpenAI.BaseURL != "http://localhost:11434/v1" {
		t.Errorf("base url = %q", cfg.LLM.OpenAI.BaseURL)
	}
	if cfg.VEX.Upload {
		t.Error("env should override yaml upload=true")
	}
	if cfg.VEX.Author != "ACME Security" {
		t.Errorf("author = %q", cfg.VEX.Author)
	}
	if cfg.Watch.Interval != 5*time.Minute {
		t.Errorf("interval = %v", cfg.Watch.Interval)
	}
	if cfg.Timeout != time.Hour {
		t.Errorf("timeout = %v", cfg.Timeout)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/vexviper.yaml"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestApplyEnvMCPArgs(t *testing.T) {
	cfg := Default()
	env := map[string]string{
		"VEXVIPER_LLM_PROVIDER":   "mcptool",
		"VEXVIPER_MCP_COMMAND":    "npx",
		"VEXVIPER_MCP_ARGS":       "-y some-mcp-server --flag",
		"VEXVIPER_MCP_TOOL":       "triage",
		"VEXVIPER_REPO_CLONE":     "false",
		"VEXVIPER_WATCH_INTERVAL": "bogus", // ignored
	}
	cfg.ApplyEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if cfg.LLM.Provider != ProviderMCPTool || cfg.LLM.MCP.Command != "npx" || cfg.LLM.MCP.Tool != "triage" {
		t.Fatalf("mcp env not applied: %+v", cfg.LLM.MCP)
	}
	if got := strings.Join(cfg.LLM.MCP.Args, " "); got != "-y some-mcp-server --flag" {
		t.Fatalf("args = %q", got)
	}
	if cfg.Repo.Clone {
		t.Fatal("repo.clone should be false")
	}
	if cfg.Watch.Interval != 15*time.Minute {
		t.Fatalf("invalid duration should be ignored, got %v", cfg.Watch.Interval)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]func(*Config){
		"bad provider":       func(c *Config) { c.LLM.Provider = "magic" },
		"confidence range":   func(c *Config) { c.LLM.MinConfidence = 1.5 },
		"openai needs model": func(c *Config) { c.LLM.Provider = ProviderOpenAI; c.LLM.OpenAI.Model = "" },
		"github needs token": func(c *Config) { c.LLM.Provider = ProviderGitHub },
		"copilot command":    func(c *Config) { c.LLM.Provider = ProviderCopilot; c.LLM.Copilot.Command = "" },
		"github needs model": func(c *Config) { c.LLM.Provider = ProviderGitHub; c.LLM.GitHub.Token = "t"; c.LLM.GitHub.Model = "" },
		"mcp stdio command":  func(c *Config) { c.LLM.Provider = ProviderMCPTool },
		"mcp http url":       func(c *Config) { c.LLM.Provider = ProviderMCPTool; c.LLM.MCP.Transport = MCPTransportHTTP },
		"mcp bad transport":  func(c *Config) { c.LLM.Provider = ProviderMCPTool; c.LLM.MCP.Transport = "carrier-pigeon" },
		"mcp tool":           func(c *Config) { c.LLM.Provider = ProviderMCPTool; c.LLM.MCP.Command = "x"; c.LLM.MCP.Tool = "" },
		"watch interval":     func(c *Config) { c.Watch.Interval = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Default()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRepoFor(t *testing.T) {
	r := Repo{SBOMs: []SBOMRepo{
		{Match: "abc-123", Repo: "by/id"},
		{Match: "kubelb-*", Repo: "kubermatic/kubelb"},
		{Match: "*.cdx.json", Repo: "cdx/any"},
		{Match: "", Repo: "ignored"},
	}}
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"abc-123", "doc", "file"}, "by/id"},
		{[]string{"id", "kubelb", "kubelb-1.4.2.spdx.json"}, "kubermatic/kubelb"},
		{[]string{"id", "", "thing.cdx.json"}, "cdx/any"},
		{[]string{"id", "doc", "nothing"}, ""},
	}
	for _, c := range cases {
		if got := r.RepoFor(c.names...); got != c.want {
			t.Errorf("RepoFor(%v) = %q want %q", c.names, got, c.want)
		}
	}
}

func TestLoadRepoSBOMsAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.yaml")
	os.WriteFile(path, []byte("repo:\n  sboms:\n    - match: kubelb-*\n      repo: kubermatic/kubelb\n"), 0o644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Repo.RepoFor("kubelb-1.4.2"); got != "kubermatic/kubelb" {
		t.Fatalf("RepoFor = %q", got)
	}
	cfg.Repo.SBOMs = append(cfg.Repo.SBOMs, SBOMRepo{Match: "x"}, SBOMRepo{Match: "[", Repo: "a/b"})
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "repo.sboms[1]") || !strings.Contains(err.Error(), "repo.sboms[2]") {
		t.Fatalf("expected validation errors, got %v", err)
	}
}

func TestGitHubProviderEnv(t *testing.T) {
	cfg := Default()
	cfg.LLM.Provider = ProviderGitHub
	env := map[string]string{"GITHUB_TOKEN": "ghp_abc", "VEXVIPER_GITHUB_MODEL": "openai/gpt-4.1"}
	cfg.ApplyEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if cfg.LLM.GitHub.Token != "ghp_abc" || cfg.LLM.GitHub.Model != "openai/gpt-4.1" || cfg.LLM.GitHub.BaseURL != GitHubModelsURL {
		t.Fatalf("github cfg = %+v", cfg.LLM.GitHub)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCacheConfig(t *testing.T) {
	cfg := Default()
	if !cfg.Cache.Enabled || cfg.CacheDir() != filepath.Join(".vexviper-cache", "assessments") {
		t.Fatalf("default cache = %+v dir=%q", cfg.Cache, cfg.CacheDir())
	}
	env := map[string]string{"VEXVIPER_CACHE_ENABLED": "false", "VEXVIPER_CACHE_DIR": "/var/cache/vv", "VEXVIPER_CACHE_TTL": "720h"}
	cfg.ApplyEnv(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if cfg.Cache.Enabled || cfg.CacheDir() != "/var/cache/vv" || cfg.Cache.TTL != 720*time.Hour {
		t.Fatalf("cache env = %+v", cfg.Cache)
	}
	cfg.Cache.TTL = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cache.ttl") {
		t.Fatalf("negative ttl must fail validation: %v", err)
	}
}
