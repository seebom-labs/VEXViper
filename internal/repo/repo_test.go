package repo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFromPURL(t *testing.T) {
	cases := []struct {
		purl    string
		wantURL string
		wantRef string
		ok      bool
	}{
		{"pkg:golang/github.com/seebom-labs/bomhort/backend@v0.6.1", "https://github.com/seebom-labs/bomhort", "v0.6.1", true},
		{"pkg:golang/github.com/foo/bar", "https://github.com/foo/bar", "", true},
		{"pkg:golang/github.com/foo/bar/v2@v2.1.0?type=module#sub", "https://github.com/foo/bar", "v2.1.0", true},
		{"pkg:github/acme/tool@abcdef0", "https://github.com/acme/tool", "abcdef0", true},
		{"pkg:golang/golang.org/x/net@v0.17.0", "https://github.com/golang/net", "v0.17.0", true},
		{"pkg:golang/golang.org/x/net/http2@v0.17.0", "https://github.com/golang/net", "v0.17.0", true},
		{"pkg:golang/oras.land/oras-go/v2@v2.0.0", "https://github.com/oras-project/oras-go", "v2.0.0", true},
		{"pkg:golang/gopkg.in/yaml.v3@v3.0.1", "https://github.com/go-yaml/yaml", "v3.0.1", true},
		{"pkg:golang/example.com/private@v1", "", "", false},
		{"pkg:npm/%40angular/cdk@22.0.6", "", "", false},
		{"pkg:golang/github.com/onlyowner", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		loc, ok := FromPURL(tc.purl)
		if ok != tc.ok || loc.URL != tc.wantURL || loc.Ref != tc.wantRef {
			t.Errorf("FromPURL(%q) = %+v,%v; want %q %q %v", tc.purl, loc, ok, tc.wantURL, tc.wantRef, tc.ok)
		}
	}
}

func TestFromOverride(t *testing.T) {
	cases := map[string]Location{
		"acme/app":                            {URL: "https://github.com/acme/app"},
		"acme/app@v1.2.0":                     {URL: "https://github.com/acme/app", Ref: "v1.2.0"},
		"github.com/acme/app.git":             {URL: "https://github.com/acme/app"},
		"https://gitlab.com/grp/proj/":        {URL: "https://gitlab.com/grp/proj"},
		"git@github.com:acme/app.git@main":    {URL: "https://github.com/acme/app", Ref: "main"},
		"https://github.com/acme/app@release": {URL: "https://github.com/acme/app", Ref: "release"},
	}
	for in, want := range cases {
		got, ok := FromOverride(in)
		if !ok || got.URL != want.URL || got.Ref != want.Ref || got.How != "override" {
			t.Errorf("FromOverride(%q) = %+v,%v; want %+v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "justaname", "https://github.com/"} {
		if _, ok := FromOverride(bad); ok {
			t.Errorf("FromOverride(%q) should fail", bad)
		}
	}
}

func TestFromOSVReferences(t *testing.T) {
	loc, ok := FromOSVReferences([]string{
		"https://go.dev/cl/534215",
		"https://github.com/advisories/GHSA-xxxx",
		"https://github.com/golang/net/commit/88194ad8ab44a02ea952c169883c3f57bb3e5b47",
		"https://github.com/other/repo",
	})
	if !ok || loc.URL != "https://github.com/golang/net" || loc.Ref != "88194ad8ab44a02ea952c169883c3f57bb3e5b47" || loc.How != "osv" {
		t.Fatalf("got %+v %v", loc, ok)
	}
	if _, ok := FromOSVReferences([]string{"https://go.dev/issue/1", "::bad"}); ok {
		t.Fatal("expected no match")
	}
}

func TestLooksLikeCommit(t *testing.T) {
	if !looksLikeCommit("88194ad8ab44") || looksLikeCommit("v0.17.0") || looksLikeCommit("main") {
		t.Fatal("commit detection wrong")
	}
}

// TestClone uses a local bare repository as origin so no network is needed.
func TestClone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	work := t.TempDir()
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(dir string, args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git(src, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module example.com/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(src, "add", ".")
	git(src, "commit", "-q", "-m", "init")
	git(src, "tag", "v1.0.0")

	// Cloner appends ".git" to the URL; a bare repo named src.git satisfies that.
	bare := filepath.Join(work, "origin")
	git(work, "clone", "-q", "--bare", src, bare+".git")

	c := &Cloner{CacheDir: filepath.Join(work, "cache")}
	loc := Location{URL: "file://" + bare, Ref: "v1.0.0"}
	dir, err := c.Clone(ctx, loc)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("go.mod missing in clone: %v", err)
	}
	// HEAD resolves to the tagged commit (detached HEAD after --branch <tag>,
	// or via refs/heads / packed-refs).
	want, _ := exec.Command("git", "-C", src, "rev-parse", "v1.0.0").Output()
	if got := HeadCommit(dir); got != strings.TrimSpace(string(want)) || len(got) != 40 {
		t.Fatalf("HeadCommit = %q, want %q", got, want)
	}
	if HeadCommit(t.TempDir()) != "" {
		t.Fatal("HeadCommit on a non-repo must be empty")
	}
	// second call reuses cache
	dir2, err := c.Clone(ctx, loc)
	if err != nil || dir2 != dir {
		t.Fatalf("reuse failed: %v %v", dir2, err)
	}
	// missing tag falls back to default branch
	dir3, err := c.Clone(ctx, Location{URL: "file://" + bare, Ref: "v9.9.9"})
	if err != nil {
		t.Fatalf("fallback clone: %v", err)
	}
	if dir3 == dir {
		t.Fatal("different ref should use different cache path")
	}
	if _, err := c.Clone(ctx, Location{}); err == nil {
		t.Fatal("empty location should fail")
	}
	if _, err := c.Clone(ctx, Location{URL: "file:///nonexistent/repo"}); err == nil {
		t.Fatal("nonexistent origin should fail")
	}
}

func TestHeadCommitPackedRefs(t *testing.T) {
	dir := t.TempDir()
	git := filepath.Join(dir, ".git")
	if err := os.MkdirAll(git, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644)
	os.WriteFile(filepath.Join(git, "packed-refs"), []byte("# pack-refs with: peeled\nabc123 refs/heads/main\n^def\n"), 0o644)
	if got := HeadCommit(dir); got != "abc123" {
		t.Fatalf("packed-refs HeadCommit = %q", got)
	}
	os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: refs/heads/missing\n"), 0o644)
	if got := HeadCommit(dir); got != "" {
		t.Fatalf("unknown ref must be empty, got %q", got)
	}
	os.WriteFile(filepath.Join(git, "HEAD"), []byte("0123456789abcdef\n"), 0o644)
	if got := HeadCommit(dir); got != "0123456789abcdef" {
		t.Fatalf("detached HeadCommit = %q", got)
	}
}
