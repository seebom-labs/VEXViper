// Package repo resolves the source repository of a package or product and
// materializes it locally with a shallow git clone.
package repo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// wellKnownGoModules maps non-github.com Go module prefixes to their GitHub
// owner/repo (same table BOMHort uses in backend/internal/github/purl.go).
var wellKnownGoModules = map[string][2]string{
	"golang.org/x/crypto":  {"golang", "crypto"},
	"golang.org/x/net":     {"golang", "net"},
	"golang.org/x/sys":     {"golang", "sys"},
	"golang.org/x/text":    {"golang", "text"},
	"golang.org/x/sync":    {"golang", "sync"},
	"golang.org/x/tools":   {"golang", "tools"},
	"golang.org/x/mod":     {"golang", "mod"},
	"golang.org/x/oauth2":  {"golang", "oauth2"},
	"golang.org/x/term":    {"golang", "term"},
	"golang.org/x/time":    {"golang", "time"},
	"golang.org/x/exp":     {"golang", "exp"},
	"golang.org/x/image":   {"golang", "image"},
	"golang.org/x/xerrors": {"golang", "xerrors"},
	"golang.org/x/vuln":    {"golang", "vuln"},

	"gopkg.in/yaml.v2":                 {"go-yaml", "yaml"},
	"gopkg.in/yaml.v3":                 {"go-yaml", "yaml"},
	"go.yaml.in/yaml":                  {"go-yaml", "yaml"},
	"gopkg.in/inf.v0":                  {"go-inf", "inf"},
	"gopkg.in/check.v1":                {"go-check", "check"},
	"gopkg.in/natefinch/lumberjack.v2": {"natefinch", "lumberjack"},
	"gopkg.in/tomb.v1":                 {"go-tomb", "tomb"},
	"gopkg.in/square/go-jose.v2":       {"square", "go-jose"},

	"google.golang.org/grpc":            {"grpc", "grpc-go"},
	"google.golang.org/protobuf":        {"protocolbuffers", "protobuf-go"},
	"google.golang.org/genproto":        {"googleapis", "go-genproto"},
	"google.golang.org/api":             {"googleapis", "google-api-go-client"},
	"go.uber.org/zap":                   {"uber-go", "zap"},
	"go.uber.org/atomic":                {"uber-go", "atomic"},
	"go.uber.org/multierr":              {"uber-go", "multierr"},
	"go.uber.org/goleak":                {"uber-go", "goleak"},
	"go.etcd.io/etcd":                   {"etcd-io", "etcd"},
	"go.etcd.io/bbolt":                  {"etcd-io", "bbolt"},
	"go.opentelemetry.io/otel":          {"open-telemetry", "opentelemetry-go"},
	"k8s.io/api":                        {"kubernetes", "api"},
	"k8s.io/apimachinery":               {"kubernetes", "apimachinery"},
	"k8s.io/client-go":                  {"kubernetes", "client-go"},
	"k8s.io/klog":                       {"kubernetes", "klog"},
	"k8s.io/utils":                      {"kubernetes", "utils"},
	"sigs.k8s.io/yaml":                  {"kubernetes-sigs", "yaml"},
	"sigs.k8s.io/controller-runtime":    {"kubernetes-sigs", "controller-runtime"},
	"sigs.k8s.io/structured-merge-diff": {"kubernetes-sigs", "structured-merge-diff"},
	"oras.land/oras-go":                 {"oras-project", "oras-go"},
	"dario.cat/mergo":                   {"darccio", "mergo"},
}

// Location is a resolved repository.
type Location struct {
	URL string // canonical https URL without .git
	// Ref is an optional tag/branch/commit to check out (e.g. the package version).
	Ref string
	// How explains where the location came from (override, sbom, purl, osv).
	How string
}

// FromPURL derives a GitHub repository from a PURL using the same
// heuristics as BOMHort. ok is false when nothing sensible can be derived.
func FromPURL(purl string) (loc Location, ok bool) {
	p := purl
	version := ""
	if i := strings.Index(p, "@"); i > 0 {
		version = p[i+1:]
		p = p[:i]
		for _, sep := range []string{"?", "#"} {
			if j := strings.Index(version, sep); j >= 0 {
				version = version[:j]
			}
		}
	}
	for _, sep := range []string{"?", "#"} {
		if i := strings.Index(p, sep); i > 0 {
			p = p[:i]
		}
	}
	version, _ = url.PathUnescape(version)

	var owner, repo string
	switch {
	case strings.HasPrefix(p, "pkg:golang/github.com/"):
		owner, repo, ok = splitOwnerRepo(strings.TrimPrefix(p, "pkg:golang/github.com/"))
	case strings.HasPrefix(p, "pkg:github/"):
		owner, repo, ok = splitOwnerRepo(strings.TrimPrefix(p, "pkg:github/"))
	case strings.HasPrefix(p, "pkg:golang/"):
		mod := strings.TrimPrefix(p, "pkg:golang/")
		owner, repo, ok = lookupWellKnown(mod)
		if !ok {
			if stripped := stripGoVersionSuffix(mod); stripped != mod {
				owner, repo, ok = lookupWellKnown(stripped)
			}
		}
	}
	if !ok {
		return Location{}, false
	}
	return Location{URL: "https://github.com/" + owner + "/" + repo, Ref: version, How: "purl"}, true
}

func lookupWellKnown(mod string) (string, string, bool) {
	for prefix, or := range wellKnownGoModules {
		if mod == prefix || strings.HasPrefix(mod, prefix+"/") {
			return or[0], or[1], true
		}
	}
	return "", "", false
}

func splitOwnerRepo(rest string) (string, string, bool) {
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], strings.TrimSuffix(parts[1], ".git"), true
}

func stripGoVersionSuffix(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		last := parts[len(parts)-1]
		if len(last) >= 2 && last[0] == 'v' && last[1] >= '0' && last[1] <= '9' {
			return strings.Join(parts[:len(parts)-1], "/")
		}
	}
	return path
}

// FromOverride accepts "owner/repo", "github.com/owner/repo" or a full URL,
// optionally suffixed with "@ref".
func FromOverride(s string) (Location, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Location{}, false
	}
	ref := ""
	if i := strings.LastIndex(s, "@"); i > 0 && !strings.Contains(s[i:], "/") {
		ref = s[i+1:]
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".git")
	switch {
	case strings.HasPrefix(s, "http://"), strings.HasPrefix(s, "https://"):
	case strings.HasPrefix(s, "git@"):
		s = "https://" + strings.Replace(strings.TrimPrefix(s, "git@"), ":", "/", 1)
	case strings.Count(s, "/") == 1:
		s = "https://github.com/" + s
	default:
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || strings.Count(strings.Trim(u.Path, "/"), "/") < 1 {
		return Location{}, false
	}
	return Location{URL: strings.TrimRight(s, "/"), Ref: ref, How: "override"}, true
}

// FromOSVReferences picks a repository from OSV reference URLs (FIX/WEB/ADVISORY).
func FromOSVReferences(urls []string) (Location, bool) {
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host != "github.com" {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 || parts[0] == "advisories" {
			continue
		}
		loc := Location{URL: "https://github.com/" + parts[0] + "/" + parts[1], How: "osv"}
		if len(parts) >= 4 && parts[2] == "commit" {
			loc.Ref = parts[3]
		}
		return loc, true
	}
	return Location{}, false
}

// Cloner shallow-clones repositories into a cache directory.
type Cloner struct {
	CacheDir string
	// Git is the git binary (default "git").
	Git string
	// Timeout per git invocation.
	Timeout time.Duration
	// Depth for shallow clones (default 1).
	Depth int

	// locks serializes concurrent clones of the same checkout directory.
	locks sync.Map // dir → *sync.Mutex
}

// Path returns the cache path a location would be cloned to.
func (c *Cloner) Path(loc Location) string {
	sum := sha256.Sum256([]byte(loc.URL + "@" + loc.Ref))
	name := strings.NewReplacer("https://", "", "http://", "", "/", "_").Replace(loc.URL)
	return filepath.Join(c.CacheDir, name+"-"+hex.EncodeToString(sum[:6]))
}

// Clone materializes loc and returns the checkout path. An existing checkout
// is reused. If Ref cannot be checked out the default branch is kept and a
// warning is logged.
func (c *Cloner) Clone(ctx context.Context, loc Location) (string, error) {
	if loc.URL == "" {
		return "", fmt.Errorf("repo: empty location")
	}
	dir := c.Path(loc)
	mu, _ := c.locks.LoadOrStore(dir, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	defer mu.(*sync.Mutex).Unlock()
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return dir, nil
	}
	if err := os.MkdirAll(c.CacheDir, 0o755); err != nil {
		return "", err
	}
	depth := c.Depth
	if depth <= 0 {
		depth = 1
	}
	args := []string{"clone", "--quiet", "--depth", fmt.Sprint(depth), "--no-tags"}
	if loc.Ref != "" && !looksLikeCommit(loc.Ref) {
		args = append(args, "--branch", loc.Ref)
	}
	args = append(args, loc.URL+".git", dir)
	if err := c.run(ctx, "", args...); err != nil {
		if loc.Ref == "" || looksLikeCommit(loc.Ref) {
			return "", err
		}
		// Tag may not exist (e.g. pseudo-versions, "v0.6.1" vs "0.6.1"): retry default branch.
		slog.Warn("repo: ref not found, cloning default branch", "url", loc.URL, "ref", loc.Ref)
		_ = os.RemoveAll(dir)
		if err := c.run(ctx, "", "clone", "--quiet", "--depth", fmt.Sprint(depth), "--no-tags", loc.URL+".git", dir); err != nil {
			return "", err
		}
		return dir, nil
	}
	if loc.Ref != "" && looksLikeCommit(loc.Ref) {
		if err := c.run(ctx, dir, "fetch", "--quiet", "--depth", "1", "origin", loc.Ref); err == nil {
			_ = c.run(ctx, dir, "checkout", "--quiet", loc.Ref)
		} else {
			slog.Warn("repo: commit not fetchable, keeping default branch", "url", loc.URL, "ref", loc.Ref)
		}
	}
	return dir, nil
}

func (c *Cloner) run(ctx context.Context, dir string, args ...string) error {
	git := c.Git
	if git == "" {
		git = "git"
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("repo: git %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}

func looksLikeCommit(ref string) bool {
	if len(ref) < 7 || len(ref) > 40 {
		return false
	}
	for _, r := range ref {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// HeadCommit returns the full commit hash checked out in dir, or "" when dir
// is not a git checkout. It reads .git directly so it works without a git
// binary and on shallow clones.
func HeadCommit(dir string) string {
	gitDir := filepath.Join(dir, ".git")
	head, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return ""
	}
	ref := strings.TrimSpace(string(head))
	if !strings.HasPrefix(ref, "ref: ") {
		return ref
	}
	ref = strings.TrimPrefix(ref, "ref: ")
	if b, err := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(ref))); err == nil {
		return strings.TrimSpace(string(b))
	}
	packed, err := os.ReadFile(filepath.Join(gitDir, "packed-refs"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(packed), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == ref {
			return f[0]
		}
	}
	return ""
}
