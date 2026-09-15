package gitops

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seebom-labs/vexviper/internal/config"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newBareRepo creates a bare "remote" with one commit on main and returns its path.
func newBareRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "remote.git")
	run(t, root, "init", "-q", "--bare", "-b", "main", bare)
	seed := filepath.Join(root, "seed")
	run(t, root, "clone", "-q", bare, seed)
	if err := os.WriteFile(filepath.Join(seed, "README.md"), []byte("vex repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, seed, "add", ".")
	run(t, seed, "commit", "-q", "-m", "init")
	run(t, seed, "push", "-q", "origin", "HEAD:main")
	return bare
}

func fileAt(t *testing.T, bare, ref, path string) (string, bool) {
	t.Helper()
	cmd := exec.Command("git", "--git-dir", bare, "show", ref+":"+path)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

func newPublisher(t *testing.T, cfg config.Git) *Publisher {
	t.Helper()
	p := New(cfg, filepath.Join(t.TempDir(), "work"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	return p
}

func TestPublishReviewBranchAndDirect(t *testing.T) {
	requireGit(t)
	bare := newBareRepo(t)
	ctx := context.Background()

	t.Run("review branch, forced rebuild, unchanged detection", func(t *testing.T) {
		p := newPublisher(t, config.Git{Repo: bare, Branch: "main", Path: "vex", BranchPrefix: "vexviper/", SignOff: true, AuthorName: "Bot", AuthorEmail: "bot@example.com"})
		doc := Document{Filename: "demo.openvex.json", Content: []byte(`{"v":1}`), Product: "Demo Product v1.2", Summary: "3 statements"}
		res, err := p.Publish(ctx, doc)
		if err != nil {
			t.Fatal(err)
		}
		if res.Unchanged || res.Branch != "vexviper/demo-product-v1.2" || res.Path != "vex/demo.openvex.json" || len(res.Commit) != 40 {
			t.Fatalf("res = %+v", res)
		}
		if got, ok := fileAt(t, bare, res.Branch, "vex/demo.openvex.json"); !ok || got != `{"v":1}` {
			t.Fatalf("remote content = %q %v", got, ok)
		}
		if _, ok := fileAt(t, bare, "main", "vex/demo.openvex.json"); ok {
			t.Fatal("main must not be touched in review mode")
		}
		cmd := exec.Command("git", "--git-dir", bare, "log", "-1", "--format=%an <%ae>%n%B", res.Branch)
		out, _ := cmd.Output()
		if !strings.Contains(string(out), "Bot <bot@example.com>") || !strings.Contains(string(out), "Signed-off-by: Bot <bot@example.com>") || !strings.Contains(string(out), "3 statements") {
			t.Fatalf("commit = %s", out)
		}

		// Same content again on a fresh branch from base: base has no file, so
		// this is a change relative to base and is published again.
		res2, err := p.Publish(ctx, doc)
		if err != nil {
			t.Fatal(err)
		}
		if res2.Unchanged {
			t.Fatalf("review branch is rebuilt from base; res = %+v", res2)
		}

		// A different document replaces the branch content (forced push).
		doc.Content = []byte(`{"v":2}`)
		res3, err := p.Publish(ctx, doc)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := fileAt(t, bare, res3.Branch, "vex/demo.openvex.json"); got != `{"v":2}` {
			t.Fatalf("remote content = %q", got)
		}
		cmd = exec.Command("git", "--git-dir", bare, "rev-list", "--count", "main.."+res3.Branch)
		out, _ = cmd.Output()
		if strings.TrimSpace(string(out)) != "1" {
			t.Fatalf("review branch should be exactly one commit ahead of main, got %s", out)
		}
	})

	t.Run("direct commit to base and unchanged", func(t *testing.T) {
		p := newPublisher(t, config.Git{Repo: bare, Branch: "main", Path: "vex/nested", BranchPrefix: ""})
		doc := Document{Filename: "direct.openvex.json", Content: []byte(`{"d":1}`)}
		res, err := p.Publish(ctx, doc)
		if err != nil {
			t.Fatal(err)
		}
		if res.Branch != "main" || res.Unchanged {
			t.Fatalf("res = %+v", res)
		}
		if got, _ := fileAt(t, bare, "main", "vex/nested/direct.openvex.json"); got != `{"d":1}` {
			t.Fatalf("remote content = %q", got)
		}
		res, err = p.Publish(ctx, doc)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Unchanged {
			t.Fatalf("identical content must be a no-op: %+v", res)
		}
		// Second publisher with a fresh work dir sees the pushed state.
		p2 := newPublisher(t, p.Cfg)
		res, err = p2.Publish(ctx, doc)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Unchanged {
			t.Fatalf("fresh clone must see identical content: %+v", res)
		}
	})

	t.Run("recovers from dirty work tree", func(t *testing.T) {
		p := newPublisher(t, config.Git{Repo: bare, Branch: "main", Path: "vex"})
		if _, err := p.Publish(ctx, Document{Filename: "a.openvex.json", Content: []byte("a")}); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(p.WorkDir, repoSlug(bare))
		if err := os.WriteFile(filepath.Join(dir, "vex", "junk.json"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("modified"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Publish(ctx, Document{Filename: "a.openvex.json", Content: []byte("b")}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "vex", "junk.json")); !os.IsNotExist(err) {
			t.Fatal("junk should have been cleaned")
		}
		if got, _ := fileAt(t, bare, "main", "README.md"); got != "vex repo\n" {
			t.Fatalf("README must be untouched, got %q", got)
		}
	})
}

func TestPublishOpensAndUpdatesPR(t *testing.T) {
	requireGit(t)
	bare := newBareRepo(t)
	var (
		open   []map[string]any
		posts  int
		patchs int
		auth   string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/vex/pulls":
			if r.URL.Query().Get("head") != "acme:vexviper/demo" || r.URL.Query().Get("state") != "open" {
				t.Errorf("query = %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(open)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/vex/pulls":
			posts++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["head"] != "vexviper/demo" || body["base"] != "main" || !strings.Contains(body["body"].(string), "Review checklist") {
				t.Errorf("body = %v", body)
			}
			open = []map[string]any{{"number": 7, "html_url": "https://gh/acme/vex/pull/7", "state": "open"}}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(open[0])
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/vex/pulls/7":
			patchs++
			_ = json.NewEncoder(w).Encode(open[0])
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Repo is a local path for git, but PR resolution needs owner/repo: use a
	// runner that rewrites the https URL to the bare path.
	p := newPublisher(t, config.Git{Repo: "https://github.com/acme/vex.git", Branch: "main", Path: "vex", BranchPrefix: "vexviper/", PR: true, APIURL: srv.URL, Token: "tok-secret"})
	p.Run = func(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
		for i, a := range args {
			if a == p.Cfg.Repo {
				args[i] = bare
			}
		}
		for _, e := range env {
			if strings.Contains(e, "tok-secret") && !strings.HasPrefix(e, "GIT_CONFIG_VALUE_0=AUTHORIZATION: basic ") {
				t.Errorf("token leaked in plain env: %s", e)
			}
		}
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		return cmd.CombinedOutput()
	}
	doc := Document{Filename: "demo.openvex.json", Content: []byte("1"), Product: "demo"}
	res, err := p.Publish(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if res.PRNumber != 7 || res.PRURL == "" || res.PRUpdated || posts != 1 {
		t.Fatalf("res = %+v posts=%d", res, posts)
	}
	if auth != "Bearer tok-secret" {
		t.Fatalf("auth = %q", auth)
	}
	doc.Content = []byte("2")
	res, err = p.Publish(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if !res.PRUpdated || patchs != 1 || posts != 1 {
		t.Fatalf("res = %+v posts=%d patches=%d", res, posts, patchs)
	}
}

func TestPublishPRAPIError(t *testing.T) {
	requireGit(t)
	bare := newBareRepo(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible"}`))
	}))
	defer srv.Close()
	p := newPublisher(t, config.Git{Repo: "git@github.com:acme/vex.git", Branch: "main", BranchPrefix: "vexviper/", PR: true, APIURL: srv.URL, Token: "t"})
	p.Run = func(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
		for i, a := range args {
			if a == p.Cfg.Repo {
				args[i] = bare
			}
		}
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		return cmd.CombinedOutput()
	}
	res, err := p.Publish(context.Background(), Document{Filename: "x.openvex.json", Content: []byte("1")})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "Resource not accessible") {
		t.Fatalf("err = %v", err)
	}
	if res == nil || res.Commit == "" {
		t.Fatalf("push succeeded, result must be returned alongside the PR error: %+v", res)
	}
}

func TestPublishRejectsBadInput(t *testing.T) {
	p := newPublisher(t, config.Git{Repo: "x"})
	for _, name := range []string{"", "../x.json", "a/b.json", ".hidden"} {
		if _, err := p.Publish(context.Background(), Document{Filename: name}); err == nil {
			t.Errorf("filename %q accepted", name)
		}
	}
	p = newPublisher(t, config.Git{})
	if _, err := p.Publish(context.Background(), Document{Filename: "a.json"}); err == nil {
		t.Error("empty repo accepted")
	}
}

func TestGitErrorsAreRedacted(t *testing.T) {
	p := newPublisher(t, config.Git{Repo: "https://github.com/acme/vex.git", Token: "sekret"})
	p.Run = func(context.Context, string, []string, ...string) ([]byte, error) {
		return []byte("fatal: https://x:sekret@github.com/acme/vex.git rejected sekret"), os.ErrPermission
	}
	_, err := p.Publish(context.Background(), Document{Filename: "a.json", Content: []byte("1")})
	if err == nil || strings.Contains(err.Error(), "sekret") {
		t.Fatalf("err = %v", err)
	}
}

func TestGitEnv(t *testing.T) {
	p := newPublisher(t, config.Git{Repo: "https://ghe.example.com/org/repo.git", Token: "abc"})
	env := strings.Join(p.gitEnv(), "\n")
	if !strings.Contains(env, "GIT_CONFIG_KEY_0=http.https://ghe.example.com/.extraheader") || !strings.Contains(env, "AUTHORIZATION: basic ") || strings.Contains(env, "abc") {
		t.Fatalf("env = %s", env)
	}
	p = newPublisher(t, config.Git{Repo: "git@github.com:org/repo.git", Token: "abc"})
	if env := strings.Join(p.gitEnv(), "\n"); strings.Contains(env, "GIT_CONFIG") {
		t.Fatalf("ssh remotes must not get http headers: %s", env)
	}
	p = newPublisher(t, config.Git{Repo: "https://github.com/org/repo.git"})
	if env := strings.Join(p.gitEnv(), "\n"); strings.Contains(env, "GIT_CONFIG") {
		t.Fatalf("no token, no header: %s", env)
	}
}

func TestOwnerRepo(t *testing.T) {
	cases := map[string][2]string{
		"https://github.com/acme/vex.git":           {"acme", "vex"},
		"https://github.com/acme/vex":               {"acme", "vex"},
		"https://x:tok@github.com/acme/vex.git/":    {"acme", "vex"},
		"git@github.com:acme/vex.git":               {"acme", "vex"},
		"ssh://git@github.com/acme/vex.git":         {"acme", "vex"},
		"ssh://git@ghe.example.com:2222/acme/vex":   {"acme", "vex"},
		"https://ghe.example.com/acme/vex-docs.git": {"acme", "vex-docs"},
	}
	for in, want := range cases {
		o, r, err := OwnerRepo(in)
		if err != nil || o != want[0] || r != want[1] {
			t.Errorf("OwnerRepo(%q) = %q %q %v, want %v", in, o, r, err, want)
		}
	}
	for _, bad := range []string{"", "https://github.com/acme", "/tmp/repo.git", "nonsense"} {
		if _, _, err := OwnerRepo(bad); err == nil {
			t.Errorf("OwnerRepo(%q) should fail", bad)
		}
	}
}

func TestSlugAndRedact(t *testing.T) {
	cases := map[string]string{
		"Demo Product v1.2":               "demo-product-v1.2",
		"  pkg:golang/github.com/x/y@v1 ": "pkg-golang-github.com-x-y-v1",
		"":                                "vex",
		"---":                             "vex",
		strings.Repeat("a", 100):          strings.Repeat("a", 80),
	}
	for in, want := range cases {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
	if got := RedactURL("https://x-access-token:abc@github.com/a/b"); got != "https://***@github.com/a/b" {
		t.Fatalf("RedactURL = %q", got)
	}
	if got := Redact("token abc here", "abc"); got != "token *** here" {
		t.Fatalf("Redact = %q", got)
	}
	if got := Redact("x", ""); got != "x" {
		t.Fatalf("Redact empty = %q", got)
	}
}
