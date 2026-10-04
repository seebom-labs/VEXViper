package release_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var root string

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	root = filepath.Clean(filepath.Join(wd, "../.."))
	os.Exit(m.Run())
}

type releaseRepo struct {
	t        *testing.T
	dir      string
	upstream string
	fork     string
	work     string
	env      []string
	counter  int
}

func newReleaseRepo(t *testing.T) *releaseRepo {
	t.Helper()
	requireTool(t, "bash")
	requireTool(t, "git")

	base := t.TempDir()

	r := &releaseRepo{
		t:        t,
		dir:      base,
		upstream: filepath.Join(base, "seebom-labs", "vexviper.git"),
		fork:     filepath.Join(base, "mfahlandt", "vexviper.git"),
		work:     filepath.Join(base, "work"),
	}
	r.env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_TERMINAL_PROMPT=0",
		"REMOTE=upstream",
		"PUSH_REMOTE=origin",
		"YES=1",
		"HOME="+base,
	)
	for _, bare := range []string{r.upstream, r.fork} {
		if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
			t.Fatal(err)
		}
		r.gitIn(base, "init", "--quiet", "--bare", "-b", "main", bare)
	}
	r.gitIn(base, "init", "--quiet", "-b", "main", r.work)
	r.git("remote", "add", "upstream", r.upstream)
	r.git("remote", "add", "origin", r.fork)
	r.commit("initial")
	r.git("push", "--quiet", "upstream", "main")
	return r
}

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found", name)
	}
}

func (r *releaseRepo) git(args ...string) string {
	r.t.Helper()
	return r.gitIn(r.work, args...)
}

func (r *releaseRepo) gitIn(cwd string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = cwd
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *releaseRepo) commit(subject string, opts ...commitOpt) string {
	r.t.Helper()
	cfg := commitCfg{path: fmt.Sprintf("file%d.txt", r.counter+1), content: subject + "\n"}
	for _, opt := range opts {
		opt(&cfg)
	}
	r.counter++
	file := filepath.Join(r.work, cfg.path)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(cfg.content), 0o644); err != nil {
		r.t.Fatal(err)
	}
	r.git("add", cfg.path)
	args := []string{"commit", "--quiet", "-m", subject}
	if cfg.body != "" {
		args = append(args, "-m", cfg.body)
	}
	r.git(args...)
	return r.git("rev-parse", "HEAD")
}

type commitCfg struct{ path, content, body string }
type commitOpt func(*commitCfg)

func withPath(path string) commitOpt { return func(c *commitCfg) { c.path = path } }
func withContent(s string) commitOpt { return func(c *commitCfg) { c.content = s } }
func withBody(body string) commitOpt { return func(c *commitCfg) { c.body = body } }

func (r *releaseRepo) commitOn(branch, subject string, opts ...commitOpt) string {
	r.t.Helper()
	original := r.git("rev-parse", "--abbrev-ref", "HEAD")
	r.git("fetch", "--quiet", "upstream")
	r.git("checkout", "--quiet", "-B", "tmp-"+strings.ReplaceAll(branch, "/", "-"), "upstream/"+branch)
	sha := r.commit(subject, opts...)
	r.git("push", "--quiet", "upstream", "HEAD:refs/heads/"+branch)
	r.git("checkout", "--quiet", original)
	r.git("branch", "--quiet", "-D", "tmp-"+strings.ReplaceAll(branch, "/", "-"))
	return sha
}

func (r *releaseRepo) run(script string, args []string, extraEnv map[string]string) runResult {
	r.t.Helper()
	argv := append([]string{filepath.Join(root, script)}, args...)
	cmd := exec.Command("bash", argv...)
	cmd.Dir = r.work
	env := append([]string{}, r.env...)
	for k, v := range extraEnv {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			r.t.Fatalf("run %s: %v", script, err)
		}
	}
	return runResult{code: code, text: out.String()}
}

type runResult struct {
	code int
	text string
}

func (r runResult) ok(t *testing.T) string {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("expected success, got %d\n%s", r.code, r.text)
	}
	return r.text
}

func (r runResult) fails(t *testing.T, want string) {
	t.Helper()
	if r.code == 0 {
		t.Fatalf("expected failure containing %q, got success\n%s", want, r.text)
	}
	if !strings.Contains(r.text, want) {
		t.Fatalf("expected failure containing %q\n%s", want, r.text)
	}
}

func (r *releaseRepo) cut(kind, version string, env ...map[string]string) runResult {
	extra := map[string]string{}
	if len(env) > 0 {
		extra = env[0]
	}
	return r.run("hack/cut-release.sh", []string{kind, version}, extra)
}

func (r *releaseRepo) pick(what, branch string, env ...map[string]string) runResult {
	extra := map[string]string{}
	if len(env) > 0 {
		extra = env[0]
	}
	return r.run("hack/cherry-pick.sh", []string{what, branch}, extra)
}

func (r *releaseRepo) upstreamRef(ref string) string {
	r.t.Helper()
	cmd := exec.Command("git", "--git-dir", r.upstream, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	cmd.Env = r.env
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

func (r *releaseRepo) forkRef(ref string) string {
	r.t.Helper()
	cmd := exec.Command("git", "--git-dir", r.fork, "rev-parse", "--verify", "--quiet", ref)
	cmd.Env = r.env
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out))
}

func TestCutReleaseFirstRCCutsBranchFromRemoteMain(t *testing.T) {
	r := newReleaseRepo(t)
	head := r.commit("feat: something")
	r.git("push", "--quiet", "upstream", "main")

	out := r.cut("rc", "0.8.0").ok(t)

	if got := r.upstreamRef("refs/heads/release/v0.8"); got != head {
		t.Fatalf("release branch = %s, want %s", got, head)
	}
	if got := r.upstreamRef("refs/tags/v0.8.0-rc.1"); got != head {
		t.Fatalf("rc tag = %s, want %s", got, head)
	}
	if !strings.Contains(out, "release/v0.8 is cut") || !strings.Contains(out, "ghcr.io/seebom-labs/vexviper:0.8.0-rc.1") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestCutReleaseRCNumberingAndEmptyRefusal(t *testing.T) {
	r := newReleaseRepo(t)
	r.cut("rc", "0.8.0").ok(t)
	r.cut("rc", "0.8.0").fails(t, "already points at")
	r.git("tag", "v0.8.0-rc.9", "upstream/release/v0.8")
	r.git("push", "--quiet", "upstream", "v0.8.0-rc.9")
	fix := r.commitOn("release/v0.8", "fix: backported")

	r.cut("rc", "0.8.0").ok(t)

	if got := r.upstreamRef("refs/tags/v0.8.0-rc.10"); got != fix {
		t.Fatalf("rc.10 = %s, want %s", got, fix)
	}
}

func TestCutReleaseFinalWarnsAndRefMustBeOnBranch(t *testing.T) {
	r := newReleaseRepo(t)
	r.cut("rc", "0.8.0").ok(t)
	rc := r.upstreamRef("refs/tags/v0.8.0-rc.1")
	r.commitOn("release/v0.8", "fix: late")
	preview := r.cut("final", "0.8.0", map[string]string{"DRY_RUN": "1"}).ok(t)
	if !strings.Contains(preview, "nobody tested as an RC") {
		t.Fatalf("missing warning:\n%s", preview)
	}

	r.commit("feat: main only")
	r.git("push", "--quiet", "upstream", "main")
	r.cut("final", "0.8.0", map[string]string{"REF": "upstream/main"}).fails(t, "is not on release/v0.8")
	r.cut("final", "0.8.0", map[string]string{"REF": "v0.8.0-rc.1"}).ok(t)
	if got := r.upstreamRef("refs/tags/v0.8.0"); got != rc {
		t.Fatalf("final tag = %s, want rc %s", got, rc)
	}
}

func TestPatchBranchFromLatestFinalRequiresBackports(t *testing.T) {
	r := newReleaseRepo(t)
	r.git("tag", "-a", "v0.7.1", "-m", "v0.7.1")
	r.git("push", "--quiet", "upstream", "v0.7.1")
	v071 := r.git("rev-parse", "v0.7.1^{commit}")
	r.commit("feat: 0.8 work")
	r.git("push", "--quiet", "upstream", "main")

	r.cut("final", "0.7.2").fails(t, "make release-branch VERSION=0.7")
	r.cut("branch", "0.7").ok(t)
	if got := r.upstreamRef("refs/heads/release/v0.7"); got != v071 {
		t.Fatalf("branch = %s, want %s", got, v071)
	}
	r.cut("final", "0.7.2").fails(t, "nothing on release/v0.7 since v0.7.1")
	fix := r.commitOn("release/v0.7", "fix: backported")
	r.cut("final", "0.7.2").ok(t)
	if got := r.upstreamRef("refs/tags/v0.7.2"); got != fix {
		t.Fatalf("patch tag = %s, want %s", got, fix)
	}
}

func TestCherryPickSquashMergeWithOriginAndDuplicateDetection(t *testing.T) {
	r := newReleaseRepo(t)
	r.cut("branch", "0.8").ok(t)
	r.commit("feat: main only", withPath("feature.txt"))
	fix := r.commit("fix(api): handle nil (#42)", withPath("fix.txt"))
	r.git("push", "--quiet", "upstream", "main")

	out := r.pick("42", "0.8").ok(t)
	head := r.forkRef("refs/heads/cherry-pick/42-to-release-v0.8")
	if head == "" {
		t.Fatal("backport branch was not pushed")
	}
	message := r.git("log", "-1", "--format=%B", head)
	if !strings.Contains(message, "cherry picked from commit "+fix) {
		t.Fatalf("missing -x trailer:\n%s", message)
	}
	if parent := r.git("rev-parse", head+"^"); parent != r.git("rev-parse", "upstream/release/v0.8") {
		t.Fatalf("picked parent = %s", parent)
	}
	if tree := r.git("ls-tree", "-r", "--name-only", head); strings.Contains(tree, "feature.txt") {
		t.Fatalf("picked unrelated main content:\n%s", tree)
	}
	if !strings.Contains(out, "compare/release/v0.8...") {
		t.Fatalf("missing compare URL:\n%s", out)
	}

	r.git("push", "--quiet", "upstream", "cherry-pick/42-to-release-v0.8:refs/heads/release/v0.8")
	r.git("branch", "--quiet", "-D", "cherry-pick/42-to-release-v0.8")
	r.pick("42", "release/v0.8").fails(t, "already on release/v0.8")
}

func TestCherryPickRebaseMergedPRWithFakeGH(t *testing.T) {
	r := newReleaseRepo(t)
	r.cut("branch", "0.8").ok(t)
	first := r.commit("fix(api): handle nil", withPath("fix.txt"))
	second := r.commit("test(api): cover nil", withPath("fix_test.txt"))
	r.git("push", "--quiet", "upstream", "main")

	ghData := filepath.Join(r.dir, "gh-data")
	if err := os.MkdirAll(ghData, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ghData, "pr-50"), []byte("MERGED "+second+" 2 Handle nil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(ghData, "commit-"+sha), []byte("50\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fakeGH := filepath.Join(r.dir, "fake-gh")
	if err := os.WriteFile(fakeGH, []byte(`#!/usr/bin/env bash
case "$1" in
  --version) echo "gh version 0.0.0 (fake)" ;;
  pr) cat "$FAKE_GH_DATA/pr-$3" 2>/dev/null || { echo "no pull request $3" >&2; exit 1; } ;;
  api) sha="${2#*/commits/}"; cat "$FAKE_GH_DATA/commit-${sha%/pulls}" 2>/dev/null || true ;;
  *) echo "fake gh: unexpected $*" >&2; exit 1 ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}

	out := r.pick("50", "0.8", map[string]string{"GH": fakeGH, "FAKE_GH_DATA": ghData}).ok(t)

	head := r.forkRef("refs/heads/cherry-pick/50-to-release-v0.8")
	if head == "" {
		t.Fatal("backport branch was not pushed")
	}
	subjects := strings.Split(r.git("log", "--reverse", "--format=%s", head+"~2.."+head), "\n")
	if got, want := strings.Join(subjects, "|"), "fix(api): handle nil|test(api): cover nil"; got != want {
		t.Fatalf("picked subjects = %s, want %s", got, want)
	}
	body := r.git("log", "--format=%B", head+"~2.."+head)
	if !strings.Contains(body, "cherry picked from commit "+first) || !strings.Contains(body, "cherry picked from commit "+second) {
		t.Fatalf("missing cherry-pick origins:\n%s", body)
	}
	if !strings.Contains(out, "Title: [release/v0.8] Handle nil") {
		t.Fatalf("missing PR title:\n%s", out)
	}
}

func TestReleaseWorkflowContract(t *testing.T) {
	workflowPath := filepath.Join(root, ".github/workflows/release.yml")
	data, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)

	var wf struct {
		Jobs map[string]struct {
			Needs yaml.Node `yaml:"needs"`
			If    string    `yaml:"if"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	if _, ok := wf.Jobs["prepare"]; !ok {
		t.Fatal("release workflow has no prepare validation job")
	}
	for _, job := range []string{"image", "binaries", "chart", "github-release"} {
		j, ok := wf.Jobs[job]
		if !ok {
			t.Fatalf("missing publish job %s", job)
		}
		if !needsPrepare(j.Needs) {
			t.Fatalf("job %s does not depend on prepare", job)
		}
	}

	mustContain(t, text, "workflow_dispatch:")
	mustContain(t, text, "Manual runs publish pre-releases only")
	mustContain(t, text, "MINOR=\"${BASE%.*}\"")
	mustContain(t, text, "BRANCH=\"release/v$MINOR\"")
	mustContain(t, text, "git merge-base --is-ancestor \"$COMMIT\" \"refs/remotes/origin/$BRANCH\"")
	mustContain(t, strings.Split(text, "  test:")[0], "fetch-depth: 0")
	mustContain(t, text, "helm package deploy/helm/vexviper --version \"$VERSION\" --app-version \"$VERSION\"")
	mustContain(t, text, "grep -Ev -- '-'")
	mustContain(t, text, "previous_tag_name=$PREVIOUS")
	mustContain(t, text, "FLAGS+=(--prerelease)")
	if !regexp.MustCompile(`uses: docker/metadata-action@v\d+\n`).MatchString(text) {
		t.Fatal("release workflow must derive image tags and labels with docker/metadata-action")
	}
	mustContain(t, text, "labels: ${{ steps.meta.outputs.labels }}")
	mustContain(t, text, "flavor: latest=false")
	mustContain(t, text, "type=sha,format=short")
	mustContain(t, text, "type=raw,value=main,enable=${{ needs.prepare.outputs.release != 'true' }}")
	mustContain(t, text, "type=raw,value=${{ needs.prepare.outputs.version }},enable=${{ needs.prepare.outputs.release == 'true' }}")
	assertStableTagsGuarded(t, text)
	mustContain(t, text, `-o "dist/vexviper_${TAG}_${os}_${arch}"`)
	mustContain(t, text, "output-file: dist/vexviper_${{ env.TAG }}.spdx.json")
	mustContain(t, text, `"dist/vexviper_${TAG}.spdx.json"`)
	assertVersionRegex(t, text)
}

func needsPrepare(node yaml.Node) bool {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value == "prepare"
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Value == "prepare" {
				return true
			}
		}
	}
	return false
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("missing %q", needle)
	}
}

func assertStableTagsGuarded(t *testing.T, text string) {
	t.Helper()
	guards := []string{
		"type=raw,value=${{ needs.prepare.outputs.minor }},enable=${{ needs.prepare.outputs.release == 'true' && needs.prepare.outputs.prerelease != 'true' }}",
		"type=raw,value=latest,enable=${{ needs.prepare.outputs.release == 'true' && needs.prepare.outputs.prerelease != 'true' }}",
	}
	for _, guard := range guards {
		if !strings.Contains(text, guard) {
			t.Fatalf("stable tag missing final-release guard: %s", guard)
		}
	}
}

func assertVersionRegex(t *testing.T, text string) {
	t.Helper()
	re := regexp.MustCompile(`X\.Y\.Z or X\.Y\.Z-rc\.N`)
	if !re.MatchString(text) || !strings.Contains(text, "(rc|alpha|beta)\\.[1-9][0-9]*") {
		t.Fatal("release workflow does not document and enforce prerelease version validation")
	}
}

func TestCIAndE2ERunOnReleaseBranches(t *testing.T) {
	for _, file := range []string{"ci.yml", "e2e.yml"} {
		data, err := os.ReadFile(filepath.Join(root, ".github/workflows", file))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, event := range []string{"push", "pull_request"} {
			pattern := regexp.MustCompile(`(?m)^  ` + event + `:\n(?:    branches: \[(.*?)\])?`)
			match := pattern.FindStringSubmatch(text)
			if match == nil || !strings.Contains(match[0], "'release/**'") {
				t.Fatalf("%s: %s does not include release/**\n%s", file, event, text)
			}
		}
	}
}
