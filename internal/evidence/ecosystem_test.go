package evidence

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/seebom-labs/vexviper/internal/source"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func kindsOf(items []Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, string(it.Kind))
	}
	sort.Strings(out)
	return out
}

func hasKind(items []Item, k Kind) bool {
	for _, it := range items {
		if it.Kind == k {
			return true
		}
	}
	return false
}

func TestEcosystemEvidenceNPM(t *testing.T) {
	c := &Collector{}
	t.Run("runtime dependency imported", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"package.json":      `{"dependencies":{"lodash":"^4.17.0"},"devDependencies":{"jest":"29"}}`,
			"package-lock.json": `{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}`,
			"src/app.ts":        "import _ from 'lodash';\nexport const x = _.chunk([1,2,3], 2);\n",
			"src/app.test.ts":   "import _ from 'lodash';\n", // test path, must not count
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:npm/lodash@4.17.20"})
		if !hasKind(items, KindDirectDependency) || !hasKind(items, KindPackageImported) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
		if hasKind(items, KindDevDependency) {
			t.Fatalf("lodash is a runtime dependency: %v", kindsOf(items))
		}
		for _, it := range items {
			if it.Kind == KindPackageImported {
				if it.Details["count"] != 1 {
					t.Fatalf("count = %v, want 1 (test file excluded)", it.Details["count"])
				}
				if it.Strong {
					t.Fatal("ecosystem evidence must never be Strong")
				}
			}
		}
	})
	t.Run("dev-only dependency not imported", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"package.json": `{"dependencies":{},"devDependencies":{"jest":"29"}}`,
			"src/app.js":   "const x = require('express');\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:npm/jest@29.0.0"})
		want := []string{string(KindDevDependency), string(KindDirectDependency), string(KindImportNotFound)}
		if got := kindsOf(items); !reflect.DeepEqual(got, want) {
			t.Fatalf("kinds = %v, want %v", got, want)
		}
	})
	t.Run("scoped package via require and lockfile only", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"package.json": `{"dependencies":{"react":"18"}}`,
			"yarn.lock":    "\"@babel/core@^7.0.0\":\n  version \"7.20.0\"\n",
			"lib/x.cjs":    "const core = require(\"@babel/core/lib/index\");\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:npm/%40babel/core@7.20.0"})
		if !hasKind(items, KindTransitive) || !hasKind(items, KindPackageImported) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
	t.Run("not in any manifest", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"package.json": `{"dependencies":{"react":"18"}}`})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:npm/minimist@1.2.0"})
		if !hasKind(items, KindManifestNotFound) || !hasKind(items, KindImportNotFound) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
	t.Run("node_modules is skipped", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"package.json":                       `{"dependencies":{"a":"1"}}`,
			"node_modules/minimist/package.json": `{"name":"minimist","dependencies":{"minimist":"1"}}`,
			"node_modules/minimist/index.js":     "require('minimist')",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:npm/minimist@1.2.0"})
		if !hasKind(items, KindManifestNotFound) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
}

func TestEcosystemEvidencePyPI(t *testing.T) {
	c := &Collector{}
	t.Run("pyproject runtime dep with import name mapping", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"pyproject.toml":  "[project]\nname = \"demo\"\ndependencies = [\n  \"PyYAML>=6.0\",\n  \"requests\",\n]\n\n[tool.pytest.ini_options]\naddopts = \"-q\"\n",
			"demo/config.py":  "import yaml\n\ndef load(p):\n    return yaml.safe_load(open(p))\n",
			"tests/test_x.py": "import yaml\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:pypi/pyyaml@6.0"})
		if !hasKind(items, KindDirectDependency) || !hasKind(items, KindPackageImported) || hasKind(items, KindDevDependency) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
	t.Run("poetry dev group", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"pyproject.toml": "[tool.poetry.dependencies]\npython = \"^3.11\"\n\n[tool.poetry.group.dev.dependencies]\npytest = \"^8\"\nblack = \"*\"\n",
			"poetry.lock":    "[[package]]\nname = \"black\"\nversion = \"24.1.0\"\n",
			"demo/main.py":   "import sys\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:pypi/black@24.1.0"})
		if !hasKind(items, KindDevDependency) || !hasKind(items, KindImportNotFound) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
	t.Run("requirements-dev.txt counts as dev", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"requirements.txt":     "flask==3.0.0\n",
			"requirements-dev.txt": "Pytest-Cov==4.1\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:pypi/pytest-cov@4.1"})
		if !hasKind(items, KindDevDependency) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
		items = c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:pypi/flask@3.0.0"})
		if hasKind(items, KindDevDependency) || !hasKind(items, KindDirectDependency) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
	t.Run("PEP 503 normalisation", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"requirements.txt": "typing_extensions>=4\n"})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:pypi/typing-extensions@4.9.0"})
		if !hasKind(items, KindDirectDependency) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
}

func TestEcosystemEvidenceCargoGemComposerMaven(t *testing.T) {
	c := &Collector{}
	t.Run("cargo dev-dependency, used in src", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"Cargo.toml":  "[package]\nname = \"demo\"\n\n[dependencies]\nserde = \"1\"\n\n[dev-dependencies]\nproptest = \"1\"\n",
			"Cargo.lock":  "[[package]]\nname = \"proptest\"\nversion = \"1.0.0\"\n",
			"src/main.rs": "use serde::Serialize;\nfn main() {}\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:cargo/proptest@1.0.0"})
		if !hasKind(items, KindDevDependency) || !hasKind(items, KindImportNotFound) {
			t.Fatalf("proptest kinds = %v", kindsOf(items))
		}
		items = c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:cargo/serde@1.0.0"})
		if hasKind(items, KindDevDependency) || !hasKind(items, KindPackageImported) {
			t.Fatalf("serde kinds = %v", kindsOf(items))
		}
	})
	t.Run("cargo hyphenated crate imported with underscore", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"Cargo.toml": "[dependencies]\nserde-json = \"1\"\n",
			"src/lib.rs": "let v: serde_json::Value = serde_json::from_str(s)?;\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:cargo/serde-json@1.0.0"})
		if !hasKind(items, KindPackageImported) {
			t.Fatalf("kinds = %v", kindsOf(items))
		}
	})
	t.Run("gem", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"Gemfile":      "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem \"nokogiri\"\n",
			"Gemfile.lock": "GEM\n  specs:\n    nokogiri (1.16.0)\n    rack (3.0.0)\n",
			"app/x.rb":     "require 'nokogiri'\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:gem/nokogiri@1.16.0"})
		if !hasKind(items, KindDirectDependency) || !hasKind(items, KindPackageImported) {
			t.Fatalf("nokogiri kinds = %v", kindsOf(items))
		}
		items = c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:gem/rack@3.0.0"})
		if !hasKind(items, KindTransitive) || !hasKind(items, KindImportNotFound) {
			t.Fatalf("rack kinds = %v", kindsOf(items))
		}
	})
	t.Run("composer require-dev, no import scan", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"composer.json": `{"require":{"monolog/monolog":"^3"},"require-dev":{"phpunit/phpunit":"^10"}}`,
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:composer/phpunit/phpunit@10.0.0"})
		want := []string{string(KindDevDependency), string(KindDirectDependency)}
		if got := kindsOf(items); !reflect.DeepEqual(got, want) {
			t.Fatalf("kinds = %v, want %v", got, want)
		}
	})
	t.Run("maven pom and gradle", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"pom.xml":          "<project><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency></dependencies></project>",
			"app/build.gradle": "dependencies {\n  implementation 'org.apache.logging.log4j:log4j-core:2.17.1'\n}\n",
		})
		items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0"})
		if !hasKind(items, KindDirectDependency) {
			t.Fatalf("jackson kinds = %v", kindsOf(items))
		}
		items = c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"})
		if !hasKind(items, KindDirectDependency) {
			t.Fatalf("log4j kinds = %v", kindsOf(items))
		}
		items = c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:maven/org.example/absent@1.0"})
		if !hasKind(items, KindManifestNotFound) {
			t.Fatalf("absent kinds = %v", kindsOf(items))
		}
	})
}

func TestEcosystemEvidenceUnknownOrNoRepo(t *testing.T) {
	c := &Collector{}
	if got := c.ecosystemEvidence("", source.Finding{PURL: "pkg:npm/x@1"}); got != nil {
		t.Fatalf("empty repoDir: %v", got)
	}
	dir := writeTree(t, map[string]string{"README": ""})
	if got := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:golang/x@1"}); got != nil {
		t.Fatalf("golang is not handled here: %v", got)
	}
	if got := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:hex/foo@1"}); got != nil {
		t.Fatalf("unknown ecosystem: %v", got)
	}
}

func TestEcosystemEvidenceMaxFiles(t *testing.T) {
	files := map[string]string{"package.json": `{"dependencies":{"lodash":"1"}}`}
	for i := 0; i < 20; i++ {
		files[filepath.Join("src", string(rune('a'+i))+".js")] = "const _ = require('lodash');\n"
	}
	dir := writeTree(t, files)
	c := &Collector{MaxGrepFiles: 5}
	items := c.ecosystemEvidence(dir, source.Finding{PURL: "pkg:npm/lodash@1.0.0"})
	for _, it := range items {
		if it.Kind == KindPackageImported {
			if n := it.Details["count"].(int); n > 5 {
				t.Fatalf("scanned %d files, MaxGrepFiles=5", n)
			}
			return
		}
	}
	t.Fatalf("kinds = %v", kindsOf(items))
}

func TestPurlName(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/lodash@4.17.20":                            "lodash",
		"pkg:npm/%40babel/core@7.20.0":                      "@babel/core",
		"pkg:npm/@scope/name@1.0.0?arch=x#sub":              "@scope/name",
		"pkg:pypi/PyYAML@6.0":                               "PyYAML",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.1": "org.apache.logging.log4j/log4j-core",
		"pkg:cargo/serde":                                   "serde",
		"pkg:golang":                                        "",
	}
	for in, want := range cases {
		if got := purlName(in); got != want {
			t.Errorf("purlName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsTestPath(t *testing.T) {
	yes := []string{"tests/x.py", "src/__tests__/a.js", "spec/models/user_spec.rb", "e2e/flow.ts", "src/app.test.ts", "src/app.spec.js", "pkg/test_util.py", "lib/foo_test.rb"}
	no := []string{"src/app.ts", "lib/testing_helpers.js", "contest/x.py", "src/attest.go"}
	for _, p := range yes {
		if !isTestPath(filepath.FromSlash(p)) {
			t.Errorf("isTestPath(%q) = false", p)
		}
	}
	for _, p := range no {
		if isTestPath(filepath.FromSlash(p)) {
			t.Errorf("isTestPath(%q) = true", p)
		}
	}
}

func TestPythonModules(t *testing.T) {
	cases := map[string][]string{
		"PyYAML":            {"yaml"},
		"pillow":            {"PIL"},
		"python-dateutil":   {"dateutil"},
		"requests":          {"requests"},
		"typing-extensions": {"typing_extensions"},
		"python-multipart":  {"multipart", "python_multipart"},
		"pytz":              {"pytz", "tz"},
	}
	for in, want := range cases {
		if got := pythonModules(in); !reflect.DeepEqual(got, want) {
			t.Errorf("pythonModules(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCollectNonGoUsesEcosystemEvidence(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"package.json": `{"dependencies":{"lodash":"^4"}}`,
		"src/index.js": "const _ = require('lodash');\n",
	})
	c := &Collector{}
	t.Run("without dependency graph", func(t *testing.T) {
		r := c.Collect(context.Background(), source.Finding{VulnID: "GHSA-x", PURL: "pkg:npm/lodash@4.17.20"}, dir, nil)
		if !hasKind(r.Items, KindDirectDependency) || !hasKind(r.Items, KindPackageImported) || !hasKind(r.Items, KindNoReachabilityTool) {
			t.Fatalf("kinds = %v", kindsOf(r.Items))
		}
		for _, it := range r.Items {
			if it.Strong {
				t.Fatalf("non-Go evidence without a lockfile graph must not be Strong: %+v", it)
			}
		}
	})
	t.Run("BOMHort graph wins over manifest depth", func(t *testing.T) {
		r := c.Collect(context.Background(), source.Finding{VulnID: "GHSA-x", PURL: "pkg:npm/lodash@4.17.20", DirectKnown: true, Direct: false}, dir, nil)
		var direct int
		for _, it := range r.Items {
			if it.Kind == KindDirectDependency {
				direct++
			}
		}
		if direct != 0 || !hasKind(r.Items, KindTransitive) || !hasKind(r.Items, KindPackageImported) {
			t.Fatalf("kinds = %v", kindsOf(r.Items))
		}
	})
}
