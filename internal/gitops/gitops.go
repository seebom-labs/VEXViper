// Package gitops publishes generated OpenVEX documents to a git repository
// and proposes them as pull requests, so LLM drafts are reviewed by humans
// (and land in an auditable history) before BOMHort ingests them.
//
// It shells out to the git CLI (no go-git dependency) and talks to the GitHub
// REST API with net/http. Tokens never appear in argv: https credentials are
// passed through GIT_CONFIG_* environment variables.
package gitops

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/seebom-labs/vexviper/internal/config"
)

// Runner executes git in dir and returns combined output. Tests stub it.
type Runner func(ctx context.Context, dir string, env []string, args ...string) ([]byte, error)

// Publisher commits VEX documents to a repository.
type Publisher struct {
	Cfg config.Git
	// WorkDir caches the clone.
	WorkDir string
	// Git is the git binary (default "git").
	Git string
	// Run overrides the git runner (default exec).
	Run Runner
	// HTTP talks to the GitHub API (default client with 30 s timeout).
	HTTP *http.Client
	Log  *slog.Logger

	mu sync.Mutex
}

// Document is one file to publish.
type Document struct {
	// Filename inside Cfg.Path, e.g. bomhort-0.6.1.openvex.json.
	Filename string
	Content  []byte
	// Product identifies the SBOM/product for branch names and PR text.
	Product string
	// Summary is a short human description of the change (commit/PR body).
	Summary string
}

// Result reports what happened.
type Result struct {
	// Unchanged is true when the repository already had identical content.
	Unchanged bool
	Branch    string
	Commit    string
	Path      string
	PRURL     string
	PRNumber  int
	// PRUpdated is true when an existing open PR for the branch was reused.
	PRUpdated bool
}

// New builds a Publisher from config.
func New(cfg config.Git, workDir string, log *slog.Logger) *Publisher {
	if log == nil {
		log = slog.Default()
	}
	return &Publisher{Cfg: cfg, WorkDir: workDir, Log: log}
}

// Publish writes doc into the repository, commits, pushes and (optionally)
// opens or updates a pull request. Calls are serialized: the clone is shared.
func (p *Publisher) Publish(ctx context.Context, doc Document) (*Result, error) {
	if doc.Filename == "" || strings.ContainsAny(doc.Filename, `/\`) || strings.HasPrefix(doc.Filename, ".") {
		return nil, fmt.Errorf("gitops: invalid filename %q", doc.Filename)
	}
	if p.Cfg.Repo == "" {
		return nil, errors.New("gitops: repo is empty")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	base := nonEmpty(p.Cfg.Branch, "main")
	dir := filepath.Join(p.WorkDir, repoSlug(p.Cfg.Repo))
	if err := p.sync(ctx, dir, base); err != nil {
		return nil, err
	}

	branch := base
	if p.Cfg.BranchPrefix != "" {
		branch = p.Cfg.BranchPrefix + Slug(nonEmpty(doc.Product, strings.TrimSuffix(doc.Filename, ".openvex.json")))
		// Every review branch restarts from the current base so a stale
		// branch never resurrects old statements.
		if _, err := p.git(ctx, dir, "checkout", "-q", "-B", branch, "origin/"+base); err != nil {
			return nil, err
		}
	}

	rel := filepath.Join(filepath.FromSlash(strings.Trim(p.Cfg.Path, "/")), doc.Filename)
	abs := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return nil, err
	}
	if old, err := os.ReadFile(abs); err == nil && bytes.Equal(old, doc.Content) {
		return &Result{Unchanged: true, Branch: branch, Path: filepath.ToSlash(rel)}, nil
	}
	if err := os.WriteFile(abs, doc.Content, 0o644); err != nil {
		return nil, err
	}
	if _, err := p.git(ctx, dir, "add", "--", rel); err != nil {
		return nil, err
	}

	msg := p.commitMessage(doc, rel)
	args := []string{"-c", "user.name=" + nonEmpty(p.Cfg.AuthorName, "VEXViper"), "-c", "user.email=" + nonEmpty(p.Cfg.AuthorEmail, "vexviper@noreply.local"), "commit", "-q", "-m", msg}
	if p.Cfg.SignOff {
		args = append(args, "-s")
	}
	if _, err := p.git(ctx, dir, args...); err != nil {
		return nil, err
	}
	sha, err := p.git(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	if branch == base {
		if _, err := p.git(ctx, dir, "push", "-q", "origin", branch+":"+branch); err != nil {
			return nil, err
		}
	} else if _, err := p.git(ctx, dir, "push", "-q", "-f", "origin", branch+":"+branch); err != nil {
		// Review branches are bot-owned and rebuilt from base on every run,
		// so a forced update is the intended semantics.
		return nil, err
	}
	res := &Result{Branch: branch, Commit: strings.TrimSpace(string(sha)), Path: filepath.ToSlash(rel)}
	p.Log.Info("published VEX document to git", "repo", RedactURL(p.Cfg.Repo), "branch", branch, "path", res.Path, "commit", res.Commit[:min(12, len(res.Commit))])

	if p.Cfg.PR && branch != base {
		if err := p.ensurePR(ctx, base, branch, doc, res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// sync clones or updates the working copy and checks out origin/base.
func (p *Publisher) sync(ctx context.Context, dir, base string) error {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return err
		}
		_ = os.RemoveAll(dir)
		if _, err := p.git(ctx, filepath.Dir(dir), "clone", "-q", "--depth", "50", "--branch", base, "--single-branch", p.Cfg.Repo, dir); err != nil {
			return err
		}
	} else {
		// Credentials travel via env, so the URL can be kept in sync freely.
		if _, err := p.git(ctx, dir, "remote", "set-url", "origin", p.Cfg.Repo); err != nil {
			return err
		}
		if _, err := p.git(ctx, dir, "fetch", "-q", "--depth", "50", "origin", base+":refs/remotes/origin/"+base); err != nil {
			return err
		}
	}
	// Drop leftovers from an aborted run.
	for _, args := range [][]string{{"reset", "-q", "--hard"}, {"clean", "-qfd"}, {"checkout", "-q", "-B", base, "origin/" + base}} {
		if _, err := p.git(ctx, dir, args...); err != nil {
			return err
		}
	}
	return nil
}

func (p *Publisher) commitMessage(doc Document, rel string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vex: update %s\n\n", filepath.ToSlash(rel))
	if doc.Summary != "" {
		b.WriteString(strings.TrimSpace(doc.Summary))
		b.WriteString("\n\n")
	}
	b.WriteString("Generated by VEXViper; statements are drafts until this change is reviewed and merged.\n")
	return b.String()
}

// git runs the CLI with credentials in the environment.
func (p *Publisher) git(ctx context.Context, dir string, args ...string) ([]byte, error) {
	run := p.Run
	if run == nil {
		run = p.execGit
	}
	out, err := run(ctx, dir, p.gitEnv(), args...)
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", redactArgs(args), err, strings.TrimSpace(Redact(string(out), p.Cfg.Token)))
	}
	return out, nil
}

func (p *Publisher) execGit(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, nonEmpty(p.Git, "git"), args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

// gitEnv passes https credentials without exposing them on the command line
// and keeps git from prompting.
func (p *Publisher) gitEnv() []string {
	env := []string{"GIT_TERMINAL_PROMPT=0"}
	host := hostOf(p.Cfg.Repo)
	if p.Cfg.Token == "" || host == "" || !strings.HasPrefix(p.Cfg.Repo, "https://") {
		return env
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + p.Cfg.Token))
	return append(env,
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://"+host+"/.extraheader",
		"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic "+basic,
	)
}

// ---- GitHub pull requests ----

type pr struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	State   string `json:"state"`
}

func (p *Publisher) ensurePR(ctx context.Context, base, branch string, doc Document, res *Result) error {
	owner, repo, err := OwnerRepo(p.Cfg.Repo)
	if err != nil {
		return fmt.Errorf("gitops: pr: %w", err)
	}
	if p.Cfg.Token == "" {
		return errors.New("gitops: pr: token is empty")
	}
	api := strings.TrimRight(nonEmpty(p.Cfg.APIURL, "https://api.github.com"), "/")
	title := "vex: " + nonEmpty(doc.Product, doc.Filename)
	body := p.prBody(doc, res)

	// Reuse an open PR for the branch so reviewers keep their context.
	var existing []pr
	q := fmt.Sprintf("%s/repos/%s/%s/pulls?state=open&head=%s:%s", api, owner, repo, owner, branch)
	if err := p.apiJSON(ctx, http.MethodGet, q, nil, &existing); err != nil {
		return err
	}
	if len(existing) > 0 {
		var updated pr
		u := fmt.Sprintf("%s/repos/%s/%s/pulls/%d", api, owner, repo, existing[0].Number)
		if err := p.apiJSON(ctx, http.MethodPatch, u, map[string]any{"title": title, "body": body}, &updated); err != nil {
			return err
		}
		res.PRURL, res.PRNumber, res.PRUpdated = updated.HTMLURL, updated.Number, true
		p.Log.Info("updated review pull request", "url", res.PRURL)
		return nil
	}
	var created pr
	u := fmt.Sprintf("%s/repos/%s/%s/pulls", api, owner, repo)
	payload := map[string]any{"title": title, "body": body, "head": branch, "base": base, "maintainer_can_modify": true}
	if err := p.apiJSON(ctx, http.MethodPost, u, payload, &created); err != nil {
		return err
	}
	res.PRURL, res.PRNumber = created.HTMLURL, created.Number
	p.Log.Info("opened review pull request", "url", res.PRURL)
	return nil
}

func (p *Publisher) prBody(doc Document, res *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "VEXViper generated `%s` for **%s**.\n\n", res.Path, nonEmpty(doc.Product, doc.Filename))
	if doc.Summary != "" {
		b.WriteString(strings.TrimSpace(doc.Summary))
		b.WriteString("\n\n")
	}
	b.WriteString("Review checklist:\n")
	b.WriteString("- [ ] every `not_affected` cites strong evidence in `status_notes`\n")
	b.WriteString("- [ ] `affected` statements carry an actionable `action_statement`\n")
	b.WriteString("- [ ] product PURLs and vulnerability IDs match BOMHort's findings\n\n")
	b.WriteString("Merging does not upload anything by itself: have BOMHort's VEX ingestion (or a CI job running `vexviper generate --upload`) consume this repository.\n")
	return b.String()
}

func (p *Publisher) apiJSON(ctx context.Context, method, url string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+p.Cfg.Token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "vexviper")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := p.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gitops: %s %s: %w", method, RedactURL(url), err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("gitops: %s %s: HTTP %d: %s", method, RedactURL(url), resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// ---- helpers ----

var (
	// git@host:owner/repo.git, ssh://git@host[:port]/owner/repo.git
	sshURLRE   = regexp.MustCompile(`^(?:ssh://)?(?:[\w.-]+@)?([\w.-]+)(?::\d+)?[:/]([^/:]+)/([^/]+?)(?:\.git)?/?$`)
	nonSlugRE  = regexp.MustCompile(`[^a-z0-9._-]+`)
	multiDash  = regexp.MustCompile(`-{2,}`)
	credURLRE  = regexp.MustCompile(`://[^/@\s]+@`)
	maxSlugLen = 80
)

// OwnerRepo extracts owner and repository name from https or ssh clone URLs.
func OwnerRepo(remote string) (owner, repo string, err error) {
	r := strings.TrimSpace(remote)
	if strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://") {
		r = credURLRE.ReplaceAllString(r, "://")
		i := strings.Index(r, "://")
		parts := strings.Split(strings.Trim(r[i+3:], "/"), "/")
		if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
			return "", "", fmt.Errorf("cannot derive owner/repo from %q", RedactURL(remote))
		}
		return parts[1], strings.TrimSuffix(parts[2], ".git"), nil
	}
	if m := sshURLRE.FindStringSubmatch(r); m != nil {
		return m[2], m[3], nil
	}
	return "", "", fmt.Errorf("cannot derive owner/repo from %q", RedactURL(remote))
}

func hostOf(remote string) string {
	r := credURLRE.ReplaceAllString(remote, "://")
	i := strings.Index(r, "://")
	if i < 0 {
		return ""
	}
	rest := r[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// repoSlug names the clone directory for a remote.
func repoSlug(remote string) string {
	owner, repo, err := OwnerRepo(remote)
	if err != nil {
		return Slug(remote)
	}
	return Slug(owner + "-" + repo)
}

// Slug turns an arbitrary product/SBOM name into a safe git ref component.
func Slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = nonSlugRE.ReplaceAllString(s, "-")
	s = multiDash.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-.")
	if len(s) > maxSlugLen {
		s = strings.Trim(s[:maxSlugLen], "-.")
	}
	if s == "" {
		return "vex"
	}
	return s
}

// RedactURL strips userinfo from a URL for logs.
func RedactURL(u string) string { return credURLRE.ReplaceAllString(u, "://***@") }

// Redact masks token in s.
func Redact(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "***")
}

func redactArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, RedactURL(a))
	}
	return strings.Join(out, " ")
}

func nonEmpty(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
