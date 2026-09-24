package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/seebom-labs/vexviper/internal/source"
)

// Non-Go ecosystems have no govulncheck. What can still be established
// deterministically from the product checkout:
//
//   - is the package declared in a manifest (direct) or only in a lockfile
//     (transitive), and is it a development-only dependency?
//   - through which direct dependencies does the lockfile graph reach it, and
//     which other packages depend on it (is product code its only consumer)?
//   - does product source code import/require the package at all?
//
// Most of it narrows the question for the model and the reviewer instead of
// leaving every npm/pypi finding at "insufficient evidence". Two facts are
// Strong because they are exact, not lexical:
//
//   - dev_dependency when the package manager itself resolved the package
//     outside the runtime closure (npm `dev: true`, composer `packages-dev`,
//     poetry `category`/`groups`, Pipfile.lock `develop`, gradle test
//     configurations) or the lockfile carries the complete graph plus the
//     root's runtime/dev split so the closure can be computed exactly;
//   - import_not_found when the package is a direct dependency, the lockfile
//     graph shows no other package depends on it, the ecosystem's import
//     syntax names the package verbatim (npm module specifiers, Rust crate
//     paths, composer PSR namespaces), and no non-test source file imports it.
//     Product code is then the only possible caller and does not load it.
//
// Both are documented in docs/INTEGRATION.md ("Strong evidence").

// Additional evidence kinds produced by the ecosystem scan.
const (
	KindDevDependency    Kind = "dev_dependency"     // outside the runtime dependency closure
	KindPackageImported  Kind = "package_imported"   // product source imports/requires the package
	KindManifestNotFound Kind = "manifest_not_found" // package appears in no manifest or lockfile of the checkout
	KindDependencyPath   Kind = "dependency_path"    // lockfile graph: how the package is reached and who depends on it
)

// ecosystemSpec describes how to find a package in one ecosystem's checkout.
type ecosystemSpec struct {
	// manifests declare direct dependencies; manifestMatch extends the exact
	// base names with a predicate (e.g. *.csproj).
	manifests     []string
	manifestMatch func(base string) bool
	// lockfiles list the full dependency closure.
	lockfiles []string
	// sourceExts are scanned for imports.
	sourceExts []string
	// importPatterns builds regexes matching an import of the package name;
	// g is the lockfile graph when one was parsed (nil otherwise).
	importPatterns func(name string, g *depGraph) []*regexp.Regexp
	// manifestDecl reports whether name is declared in the manifest content and
	// whether it is dev-only.
	manifestDecl func(content []byte, name string) (declared, devOnly bool)
	// reliableImports: an import-scan miss means product code does not load
	// the package, because the import syntax names the package itself.
	// Prerequisite for a Strong import_not_found.
	reliableImports bool
}

var ecosystems = map[string]ecosystemSpec{
	"npm": {
		manifests:  []string{"package.json"},
		lockfiles:  []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"},
		sourceExts: []string{".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte"},
		importPatterns: func(name string, _ *depGraph) []*regexp.Regexp {
			q := regexp.QuoteMeta(name)
			// import x from 'name' | import 'name/sub' | require("name") | import("name")
			return []*regexp.Regexp{
				regexp.MustCompile(`(?m)\bfrom\s+['"]` + q + `(/[^'"]*)?['"]`),
				regexp.MustCompile(`(?m)\bimport\s*\(?\s*['"]` + q + `(/[^'"]*)?['"]`),
				regexp.MustCompile(`(?m)\brequire\s*\(\s*['"]` + q + `(/[^'"]*)?['"]`),
			}
		},
		manifestDecl:    npmManifestDecl,
		reliableImports: true,
	},
	"pypi": {
		manifests:  []string{"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements-dev.txt", "requirements_dev.txt", "dev-requirements.txt", "requirements/base.txt", "requirements/dev.txt", "requirements/test.txt", "Pipfile"},
		lockfiles:  []string{"poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.lock"},
		sourceExts: []string{".py", ".pyi"},
		importPatterns: func(name string, _ *depGraph) []*regexp.Regexp {
			var res []*regexp.Regexp
			for _, mod := range pythonModules(name) {
				q := regexp.QuoteMeta(mod)
				res = append(res,
					regexp.MustCompile(`(?m)^\s*import\s+`+q+`\b`),
					regexp.MustCompile(`(?m)^\s*from\s+`+q+`(\.|\s)`),
				)
			}
			return res
		},
		manifestDecl: pypiManifestDecl,
		// Distribution and import names differ (PyYAML → yaml) and frameworks
		// load packages from configuration strings (INSTALLED_APPS, entry
		// points), so a miss is not proof.
		reliableImports: false,
	},
	"cargo": {
		manifests:  []string{"Cargo.toml"},
		lockfiles:  []string{"Cargo.lock"},
		sourceExts: []string{".rs"},
		importPatterns: func(name string, _ *depGraph) []*regexp.Regexp {
			return cratePatterns(name)
		},
		manifestDecl:    tomlDepDecl,
		reliableImports: true,
	},
	"gem": {
		manifests:  []string{"Gemfile"},
		lockfiles:  []string{"Gemfile.lock"},
		sourceExts: []string{".rb"},
		importPatterns: func(name string, _ *depGraph) []*regexp.Regexp {
			q := regexp.QuoteMeta(name)
			return []*regexp.Regexp{regexp.MustCompile(`(?m)\brequire\s+['"]` + q + `(/[^'"]*)?['"]`)}
		},
		manifestDecl: func(content []byte, name string) (bool, bool) {
			re := regexp.MustCompile(`(?m)^\s*gem\s+['"]` + regexp.QuoteMeta(name) + `['"]`)
			return re.Match(content), false
		},
		// Bundler.require loads every gem of the group without a require
		// statement in product code.
		reliableImports: false,
	},
	"composer": {
		manifests:  []string{"composer.json"},
		lockfiles:  []string{"composer.lock"},
		sourceExts: []string{".php"},
		importPatterns: func(name string, g *depGraph) []*regexp.Regexp {
			// PHP namespaces do not map to package names; composer.lock records
			// each package's PSR-4/PSR-0 namespaces.
			if g == nil {
				return nil
			}
			var res []*regexp.Regexp
			for _, ns := range g.Namespaces[g.key(name)] {
				if ns == "" {
					continue
				}
				res = append(res, regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_])\\?`+regexp.QuoteMeta(ns)+`\\`))
			}
			return res
		},
		manifestDecl: func(content []byte, name string) (bool, bool) {
			var m struct {
				Require    map[string]string `json:"require"`
				RequireDev map[string]string `json:"require-dev"`
			}
			if json.Unmarshal(content, &m) != nil {
				return bytes.Contains(content, []byte(`"`+name+`"`)), false
			}
			_, prod := m.Require[name]
			_, dev := m.RequireDev[name]
			return prod || dev, dev && !prod
		},
		reliableImports: true,
	},
	"maven": {
		manifests:  []string{"pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml"},
		lockfiles:  []string{"gradle.lockfile"},
		sourceExts: []string{".java", ".kt", ".kts", ".scala", ".groovy"},
		importPatterns: func(name string, _ *depGraph) []*regexp.Regexp {
			group, artifact, _ := strings.Cut(name, "/")
			var res []*regexp.Regexp
			for _, pkg := range javaPackageCandidates(group, artifact) {
				res = append(res, regexp.MustCompile(`(?m)^\s*import\s+(static\s+)?`+regexp.QuoteMeta(pkg)+`\.`))
			}
			return res
		},
		manifestDecl: mavenManifestDecl,
		// Java package names are guessed from groupId/artifactId.
		reliableImports: false,
	},
	"nuget": {
		manifests:     []string{"Directory.Packages.props", "packages.config"},
		manifestMatch: func(base string) bool { return hasAnySuffix(base, ".csproj", ".fsproj", ".vbproj") },
		lockfiles:     []string{"packages.lock.json"},
		sourceExts:    []string{".cs", ".fs", ".vb", ".razor", ".cshtml"},
		importPatterns: func(name string, _ *depGraph) []*regexp.Regexp {
			q := regexp.QuoteMeta(name)
			return []*regexp.Regexp{
				regexp.MustCompile(`(?im)^\s*(global\s+)?using\s+(static\s+)?` + q + `(\.|\s*;)`),
				regexp.MustCompile(`(?im)^\s*@using\s+` + q + `(\.|\s|$)`),
				regexp.MustCompile(`(?im)^\s*open\s+` + q + `(\.|\s|$)`),
				regexp.MustCompile(`(?im)^\s*Imports\s+` + q + `(\.|\s|$)`),
			}
		},
		manifestDecl: nugetManifestDecl,
		// Root namespaces usually but not always equal the package id.
		reliableImports: false,
	},
	"pub": {
		manifests:  []string{"pubspec.yaml"},
		lockfiles:  []string{"pubspec.lock"},
		sourceExts: []string{".dart"},
		importPatterns: func(name string, _ *depGraph) []*regexp.Regexp {
			return []*regexp.Regexp{regexp.MustCompile(`(?m)\b(import|export)\s+['"]package:` + regexp.QuoteMeta(name) + `/`)}
		},
		manifestDecl:    pubManifestDecl,
		reliableImports: true,
	},
}

// ecoScan accumulates what the checkout walk found for one finding.
type ecoScan struct {
	eco, name string
	spec      ecosystemSpec
	graphName string // name as the lockfile graph keys it (maven: group:artifact)

	declaredIn, devIn, lockedIn []string
	graph                       *depGraph
	renamed                     bool // cargo: crate imported under another name
	inScripts                   bool // npm: invoked from package.json scripts

	sources     []string
	importFiles []string
	importCount int
}

// ecosystemEvidence scans repoDir for how the finding's package is declared,
// resolved and used. It returns nil for ecosystems it does not know.
func (c *Collector) ecosystemEvidence(repoDir string, f source.Finding) []Item {
	s := c.scanEcosystem(repoDir, f)
	if s == nil {
		return nil
	}
	return s.items(f)
}

func (c *Collector) scanEcosystem(repoDir string, f source.Finding) *ecoScan {
	if repoDir == "" {
		return nil
	}
	eco := ecosystem(f.PURL)
	spec, ok := ecosystems[eco]
	if !ok {
		return nil
	}
	name := purlName(f.PURL)
	if name == "" {
		return nil
	}
	s := &ecoScan{eco: eco, name: name, spec: spec, graphName: name}
	if eco == "maven" {
		s.graphName = strings.Replace(name, "/", ":", 1)
	}
	maxFiles := c.MaxGrepFiles
	if maxFiles <= 0 {
		maxFiles = 5000
	}

	manifests := map[string]bool{}
	for _, m := range spec.manifests {
		manifests[filepath.Base(m)] = true
	}
	lockfiles := map[string]bool{}
	for _, l := range spec.lockfiles {
		lockfiles[l] = true
	}
	exts := map[string]bool{}
	for _, e := range spec.sourceExts {
		exts[e] = true
	}
	isManifest := func(base string) bool {
		if manifests[base] || (spec.manifestMatch != nil && spec.manifestMatch(base)) {
			return true
		}
		return eco == "pypi" && strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
	}
	read := func(rel string) []byte {
		data, err := os.ReadFile(filepath.Join(repoDir, rel))
		if err != nil {
			return nil
		}
		return data
	}

	// Phase 1: manifests, lockfiles and the list of source files.
	var lockPaths []string
	files := 0
	_ = filepath.WalkDir(repoDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata", "dist", "build", ".venv", "venv", "site-packages", "target", "__pycache__", "bin", "obj", ".dart_tool":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(repoDir, path)
		base := d.Name()
		switch {
		case isManifest(base):
			data := read(rel)
			if data == nil {
				return nil
			}
			if declared, dev := spec.manifestDecl(data, name); declared {
				s.declaredIn = appendLimited(s.declaredIn, rel)
				if dev || isDevManifest(rel) {
					s.devIn = appendLimited(s.devIn, rel)
				}
			}
			switch {
			case eco == "cargo" && base == "Cargo.toml" && cargoRenameRE.MatchString(string(data)):
				for _, m := range cargoRenameRE.FindAllStringSubmatch(string(data), -1) {
					if crateKey(m[1]) == crateKey(name) {
						s.renamed = true
					}
				}
			case eco == "npm" && base == "package.json" && npmScriptsMention(data, name):
				s.inScripts = true
			}
		case lockfiles[base]:
			lockPaths = append(lockPaths, rel)
		case len(spec.sourceExts) > 0 && exts[filepath.Ext(base)]:
			if isTestPath(rel) {
				return nil
			}
			files++
			if files > maxFiles {
				return filepath.SkipAll
			}
			s.sources = append(s.sources, rel)
		}
		return nil
	})

	// Shallow lockfiles first so the graph of the product root wins over
	// nested examples/fixtures.
	sort.Slice(lockPaths, func(i, j int) bool {
		di, dj := strings.Count(lockPaths[i], string(filepath.Separator)), strings.Count(lockPaths[j], string(filepath.Separator))
		if di != dj {
			return di < dj
		}
		return lockPaths[i] < lockPaths[j]
	})
	for _, rel := range lockPaths {
		data := read(rel)
		if data == nil {
			continue
		}
		if lockfileContains(data, eco, name) {
			s.lockedIn = appendLimited(s.lockedIn, rel)
		}
		if s.graph != nil && s.graph.has(s.graphName) {
			continue
		}
		if g := loadGraph(rel, data, read); g != nil && (s.graph == nil || g.has(s.graphName)) {
			s.graph = g
		}
	}

	// Phase 2: import scan (composer needs the graph's namespaces first).
	var patterns []*regexp.Regexp
	if spec.importPatterns != nil {
		patterns = spec.importPatterns(name, s.graph)
	}
	if len(patterns) == 0 {
		s.sources = nil
		return s
	}
	for _, rel := range s.sources {
		data := read(rel)
		if data == nil {
			continue
		}
		for _, re := range patterns {
			if re.Match(data) {
				s.importFiles = appendLimited(s.importFiles, rel)
				s.importCount++
				break
			}
		}
	}
	return s
}

// direct reports whether the package is a direct dependency, preferring
// BOMHort's dependency graph over the checkout.
func (s *ecoScan) direct(f source.Finding) bool {
	if f.DirectKnown {
		return f.Direct
	}
	return len(s.declaredIn) > 0 || (s.graph != nil && s.graph.isRoot(s.graphName))
}

// soleConsumer reports whether the lockfile graph proves that no third-party
// package depends on the package, i.e. only product code can call it.
func (s *ecoScan) soleConsumer() bool {
	return s.graph != nil && s.graph.HasEdges && s.graph.has(s.graphName) && len(s.graph.dependents(s.graphName)) == 0
}

func (s *ecoScan) items(f source.Finding) []Item {
	name, eco := s.name, s.eco
	var items []Item

	devOnly, devKnown := false, false
	if s.graph != nil {
		devOnly, devKnown = s.graph.devOnly(s.graphName)
	}
	manifestDev := len(s.declaredIn) > 0 && len(s.devIn) == len(s.declaredIn)

	// Depth.
	switch {
	case devKnown && devOnly:
		items = append(items, Item{Kind: KindDevDependency, Strong: true, Summary: fmt.Sprintf("%s resolves %s outside the runtime dependency closure (development/test only); it is not part of the product's runtime dependency set", s.graph.File, name), Details: map[string]any{"lockfile": s.graph.File, "format": s.graph.Format, "manifests": s.devIn}})
		if len(s.declaredIn) > 0 {
			items = append(items, Item{Kind: KindDirectDependency, Summary: fmt.Sprintf("%s is declared in %s", name, strings.Join(s.declaredIn, ", ")), Details: map[string]any{"manifests": s.declaredIn}})
		} else {
			items = append(items, Item{Kind: KindTransitive, Summary: fmt.Sprintf("%s is a transitive dependency (%s)", name, s.graph.File), Details: map[string]any{"lockfiles": []string{s.graph.File}}})
		}
	case manifestDev && devKnown && !devOnly:
		// The manifest lists it under dev, but the lockfile pulls it into the
		// runtime closure through another dependency.
		items = append(items, Item{Kind: KindDirectDependency, Summary: fmt.Sprintf("%s is declared as a development dependency in %s but %s also resolves it inside the runtime dependency closure", name, strings.Join(s.declaredIn, ", "), s.graph.File), Details: map[string]any{"manifests": s.declaredIn, "lockfile": s.graph.File}})
	case manifestDev:
		items = append(items, Item{Kind: KindDevDependency, Summary: fmt.Sprintf("%s is declared only as a development/test dependency (%s); it is not part of the product's runtime dependency set", name, strings.Join(s.devIn, ", ")), Details: map[string]any{"manifests": s.devIn}})
		items = append(items, Item{Kind: KindDirectDependency, Summary: fmt.Sprintf("%s is declared in %s", name, strings.Join(s.declaredIn, ", ")), Details: map[string]any{"manifests": s.declaredIn}})
	case len(s.declaredIn) > 0:
		items = append(items, Item{Kind: KindDirectDependency, Summary: fmt.Sprintf("%s is a direct dependency declared in %s", name, strings.Join(s.declaredIn, ", ")), Details: map[string]any{"manifests": s.declaredIn}})
	case len(s.lockedIn) > 0:
		items = append(items, Item{Kind: KindTransitive, Summary: fmt.Sprintf("%s appears only in lockfile(s) %s, i.e. it is a transitive dependency", name, strings.Join(s.lockedIn, ", ")), Details: map[string]any{"lockfiles": s.lockedIn}})
	default:
		items = append(items, Item{Kind: KindManifestNotFound, Summary: fmt.Sprintf("%s is not declared in any %s manifest or lockfile of the checkout (bundled, vendored or from a different build context?)", name, eco)})
	}

	// Lockfile graph: path and dependents.
	if g := s.graph; g != nil && g.HasEdges && g.has(s.graphName) {
		dependents := g.dependents(s.graphName)
		paths := g.pathsTo(s.graphName, 3)
		det := map[string]any{"lockfile": g.File, "format": g.Format, "dependents": limit(dependents, 10), "dependent_count": len(dependents)}
		var b strings.Builder
		fmt.Fprintf(&b, "%s: ", g.File)
		if len(paths) > 0 {
			var ps []string
			for _, p := range paths {
				ps = append(ps, strings.Join(p, " → "))
			}
			det["paths"] = ps
			fmt.Fprintf(&b, "%s is reached via %s; ", name, strings.Join(ps, " | "))
		} else if g.isRoot(s.graphName) {
			fmt.Fprintf(&b, "%s is a direct dependency; ", name)
		} else {
			fmt.Fprintf(&b, "%s is in the dependency closure; ", name)
		}
		switch len(dependents) {
		case 0:
			b.WriteString("no other package depends on it, so product code is its only possible consumer")
		default:
			fmt.Fprintf(&b, "%d other package(s) depend on it (%s)", len(dependents), strings.Join(limit(dependents, 5), ", "))
		}
		items = append(items, Item{Kind: KindDependencyPath, Summary: b.String(), Details: det})
	}

	// Imports.
	if len(s.spec.sourceExts) > 0 {
		exts := strings.Join(s.spec.sourceExts, " ")
		switch {
		case s.importCount > 0:
			items = append(items, Item{Kind: KindPackageImported, Summary: fmt.Sprintf("product source imports %s in %d file(s), e.g. %s", name, s.importCount, strings.Join(s.importFiles, ", ")), Details: map[string]any{"files": s.importFiles, "count": s.importCount}})
		case s.sources == nil && s.spec.importPatterns != nil && eco == "composer":
			// No namespaces known for the package: nothing to scan for.
		case s.strongImportMiss(f):
			items = append(items, Item{Kind: KindImportNotFound, Strong: true, Summary: fmt.Sprintf("no non-test source file (%s) imports %s and %s shows no other package depends on it: product code is the only possible caller and does not load the package", exts, name, s.graph.File), Details: map[string]any{"lockfile": s.graph.File}})
		default:
			var why []string
			if !s.spec.reliableImports {
				why = append(why, "import names are inferred for "+eco)
			}
			if s.renamed {
				why = append(why, "crate is imported under a renamed package")
			}
			if s.inScripts {
				why = append(why, "package is invoked from package.json scripts")
			}
			if !s.direct(f) || !s.soleConsumer() {
				why = append(why, "transitive use still possible")
			}
			items = append(items, Item{Kind: KindImportNotFound, Summary: fmt.Sprintf("no product source file (%s) imports %s directly (%s)", exts, name, strings.Join(why, "; "))})
		}
	}
	return items
}

// strongImportMiss applies the "product code is the only caller and does not
// import it" rule.
func (s *ecoScan) strongImportMiss(f source.Finding) bool {
	return s.spec.reliableImports && !s.renamed && !s.inScripts && s.importCount == 0 && len(s.sources) > 0 &&
		s.direct(f) && s.soleConsumer()
}

func cratePatterns(name string) []*regexp.Regexp {
	q := regexp.QuoteMeta(strings.ReplaceAll(name, "-", "_"))
	return []*regexp.Regexp{
		regexp.MustCompile(`(?m)\buse\s+` + q + `(::|;|\s)`),
		regexp.MustCompile(`(?m)\bextern\s+crate\s+` + q + `\b`),
		regexp.MustCompile(`(?m)\b` + q + `::`),
	}
}

func npmScriptsMention(data []byte, name string) bool {
	var m struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	re := regexp.MustCompile(`(^|[\s"'&|;(])` + regexp.QuoteMeta(name) + `($|[\s"'&|;)])`)
	for _, v := range m.Scripts {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// javaPackageCandidates guesses Java package prefixes for a Maven coordinate:
// org.apache.commons:commons-text → org.apache.commons.text,
// com.fasterxml.jackson.core:jackson-databind → com.fasterxml.jackson.databind.
func javaPackageCandidates(group, artifact string) []string {
	if artifact == "" {
		return []string{group}
	}
	var out []string
	add := func(s string) { out = appendUnique(out, s) }
	segs := strings.Split(group, ".")
	last := segs[len(segs)-1]
	add(group + "." + strings.ReplaceAll(artifact, "-", "."))
	tok, rest, hyphen := strings.Cut(artifact, "-")
	switch {
	case hyphen && strings.HasPrefix(last, tok):
		// commons-text under org.apache.commons, spring-web under org.springframework
		add(group + "." + strings.ReplaceAll(rest, "-", "."))
		add(group)
	case artifact == last:
		add(group)
	}
	if len(segs) >= 2 && strings.HasPrefix(artifact, segs[len(segs)-2]+"-") {
		// jackson-databind under com.fasterxml.jackson.core
		add(strings.Join(segs[:len(segs)-1], ".") + "." + strings.ReplaceAll(strings.TrimPrefix(artifact, segs[len(segs)-2]+"-"), "-", "."))
	}
	if strings.HasSuffix(artifact, "-"+last) {
		add(strings.Join(segs[:len(segs)-1], ".") + "." + strings.ReplaceAll(artifact, "-", "."))
	}
	return out
}

var (
	pomDependencyRE = regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	gradleDepRE     = regexp.MustCompile(`(?m)^\s*(\w+)\s*\(?\s*['"]([^'":]+):([^'":]+)`)
)

func mavenManifestDecl(content []byte, name string) (declared, devOnly bool) {
	group, artifact, _ := strings.Cut(name, "/")
	if artifact == "" {
		artifact = group
	}
	dev := true
	for _, m := range pomDependencyRE.FindAllSubmatch(content, -1) {
		if bytes.Contains(m[1], []byte("<artifactId>"+artifact+"</artifactId>")) && bytes.Contains(m[1], []byte("<groupId>"+group+"</groupId>")) {
			declared = true
			if !bytes.Contains(m[1], []byte("<scope>test</scope>")) {
				dev = false
			}
		}
	}
	for _, m := range gradleDepRE.FindAllSubmatch(content, -1) {
		if string(m[2]) == group && string(m[3]) == artifact {
			declared = true
			if !isTestConfiguration(string(m[1])) {
				dev = false
			}
		}
	}
	if !declared && bytes.Contains(content, []byte(group+":"+artifact)) {
		// libs.versions.toml, dependency strings in variables.
		return true, false
	}
	return declared, declared && dev
}

var nugetRefRE = regexp.MustCompile(`(?is)<(PackageReference|PackageVersion|package)\b[^>]*\b(Include|Update|id)\s*=\s*"([^"]+)"[^>]*(/>|>.*?</(PackageReference|PackageVersion|package)>)`)

func nugetManifestDecl(content []byte, name string) (declared, devOnly bool) {
	dev := true
	for _, m := range nugetRefRE.FindAllSubmatch(content, -1) {
		if !strings.EqualFold(string(m[3]), name) {
			continue
		}
		declared = true
		if !bytes.Contains(bytes.ToLower(m[0]), []byte(`privateassets="all"`)) && !bytes.Contains(bytes.ToLower(m[0]), []byte(`developmentdependency="true"`)) {
			dev = false
		}
	}
	return declared, declared && dev
}

func pubManifestDecl(content []byte, name string) (declared, devOnly bool) {
	var m struct {
		Dependencies    map[string]any `yaml:"dependencies"`
		DevDependencies map[string]any `yaml:"dev_dependencies"`
	}
	if yaml.Unmarshal(content, &m) != nil {
		return false, false
	}
	_, prod := m.Dependencies[name]
	_, dev := m.DevDependencies[name]
	return prod || dev, dev && !prod
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func limit(list []string, n int) []string {
	if len(list) > n {
		return list[:n]
	}
	return list
}

// purlName extracts the ecosystem package name from a PURL:
// pkg:npm/%40scope/name@1.0.0 → @scope/name, pkg:maven/g/a@1 → g/a.
func purlName(purl string) string {
	s := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	} else {
		return ""
	}
	for _, sep := range []string{"?", "#"} {
		if j := strings.Index(s, sep); j >= 0 {
			s = s[:j]
		}
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		s = s[:i]
	}
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	return s
}

func isDevManifest(rel string) bool {
	b := strings.ToLower(filepath.Base(rel))
	return strings.Contains(b, "dev") || strings.Contains(b, "test")
}

func isTestPath(rel string) bool {
	l := strings.ToLower(rel)
	for _, seg := range strings.Split(l, string(filepath.Separator)) {
		switch seg {
		case "test", "tests", "__tests__", "spec", "specs", "e2e", "cypress":
			return true
		}
	}
	base := filepath.Base(l)
	return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.HasPrefix(base, "test_") || strings.HasSuffix(strings.TrimSuffix(base, filepath.Ext(base)), "_test")
}

func npmManifestDecl(content []byte, name string) (bool, bool) {
	var m struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal(content, &m) != nil {
		return bytes.Contains(content, []byte(`"`+name+`"`)), false
	}
	_, prod := m.Dependencies[name]
	_, peer := m.PeerDependencies[name]
	_, opt := m.OptionalDependencies[name]
	_, dev := m.DevDependencies[name]
	runtime := prod || peer || opt
	return runtime || dev, dev && !runtime
}

// pypiNameRE matches a requirement line / TOML dependency string for name.
func pypiDeclRE(name string) *regexp.Regexp {
	// PEP 503 normalisation: -, _ and . are interchangeable, case-insensitive.
	norm := regexp.MustCompile(`[-_.]+`).ReplaceAllString(regexp.QuoteMeta(name), `[-_.]+`)
	return regexp.MustCompile(`(?im)(^|["'\s=])` + norm + `\s*([<>=!~\[;@ ]|$|["'])`)
}

func pypiManifestDecl(content []byte, name string) (bool, bool) {
	re := pypiDeclRE(name)
	if !re.Match(content) {
		return false, false
	}
	// Dev-only when every match sits in a dev/test group of pyproject/Pipfile.
	dev := true
	section := ""
	for _, line := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		if re.MatchString(line) {
			if !isDevSection(section) {
				dev = false
			}
		}
	}
	return true, dev && section != ""
}

func isDevSection(section string) bool {
	return strings.Contains(section, "dev") || strings.Contains(section, "test") || strings.Contains(section, "lint") || strings.Contains(section, "docs")
}

func tomlDepDecl(content []byte, name string) (bool, bool) {
	re := regexp.MustCompile(`(?m)^\s*"?` + regexp.QuoteMeta(name) + `"?\s*=`)
	if !re.Match(content) {
		return false, false
	}
	dev, section := true, ""
	for _, line := range strings.Split(string(content), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(t)
			continue
		}
		if re.MatchString(line) && !(strings.Contains(section, "dev-dependencies") || strings.Contains(section, "build-dependencies")) {
			dev = false
		}
	}
	return true, dev && section != ""
}

func lockfileContains(data []byte, eco, name string) bool {
	switch eco {
	case "npm":
		return bytes.Contains(data, []byte(`"node_modules/`+name+`"`)) || // package-lock v2/v3
			bytes.Contains(data, []byte(`"`+name+`": {`)) || // package-lock v1
			bytes.Contains(data, []byte("\n"+name+"@")) || bytes.Contains(data, []byte(`"`+name+`@`)) || // yarn
			bytes.Contains(data, []byte("  /"+name+"@")) || bytes.Contains(data, []byte("  "+name+"@")) // pnpm
	case "pypi":
		return pypiDeclRE(name).Match(data)
	case "cargo":
		return bytes.Contains(data, []byte(`name = "`+name+`"`))
	case "gem":
		return regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(name) + ` \(`).Match(data)
	case "composer":
		return bytes.Contains(data, []byte(`"name": "`+name+`"`))
	case "nuget":
		return bytes.Contains(bytes.ToLower(data), bytes.ToLower([]byte(`"`+name+`"`)))
	case "pub":
		return regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(name) + `:`).Match(data)
	case "maven":
		return bytes.Contains(data, []byte(strings.Replace(name, "/", ":", 1)+":"))
	default:
		return bytes.Contains(data, []byte(name))
	}
}

// pythonModules maps a distribution name to the import names it provides.
func pythonModules(dist string) []string {
	l := strings.ToLower(dist)
	if mods, ok := pythonImportNames[l]; ok {
		return mods
	}
	mods := []string{strings.ReplaceAll(strings.ReplaceAll(l, "-", "_"), ".", "_")}
	if strings.HasPrefix(l, "python-") {
		mods = append(mods, strings.ReplaceAll(strings.TrimPrefix(l, "python-"), "-", "_"))
	}
	if strings.HasPrefix(l, "py") && len(l) > 2 {
		mods = append(mods, strings.ReplaceAll(l[2:], "-", "_"))
	}
	sort.Strings(mods)
	return mods
}

// Distribution → import name for common packages where they differ.
var pythonImportNames = map[string][]string{
	"pyyaml":                   {"yaml"},
	"pillow":                   {"PIL"},
	"beautifulsoup4":           {"bs4"},
	"scikit-learn":             {"sklearn"},
	"python-dateutil":          {"dateutil"},
	"opencv-python":            {"cv2"},
	"protobuf":                 {"google.protobuf"},
	"attrs":                    {"attr", "attrs"},
	"msgpack-python":           {"msgpack"},
	"pycryptodome":             {"Crypto"},
	"pycryptodomex":            {"Cryptodome"},
	"cryptography":             {"cryptography"},
	"pyjwt":                    {"jwt"},
	"python-jose":              {"jose"},
	"markupsafe":               {"markupsafe"},
	"jinja2":                   {"jinja2"},
	"pyopenssl":                {"OpenSSL"},
	"setuptools":               {"setuptools", "pkg_resources"},
	"gitpython":                {"git"},
	"django":                   {"django"},
	"psycopg2-binary":          {"psycopg2"},
	"mysqlclient":              {"MySQLdb"},
	"pymongo":                  {"pymongo", "bson", "gridfs"},
	"python-multipart":         {"multipart", "python_multipart"},
	"typing-extensions":        {"typing_extensions"},
	"importlib-metadata":       {"importlib_metadata"},
	"grpcio":                   {"grpc"},
	"google-api-python-client": {"googleapiclient"},
	"ruamel.yaml":              {"ruamel.yaml"},
	"zope.interface":           {"zope.interface"},
	"aiohttp":                  {"aiohttp"},
	"tornado":                  {"tornado"},
	"twisted":                  {"twisted"},
	"lxml":                     {"lxml"},
	"certifi":                  {"certifi"},
	"urllib3":                  {"urllib3"},
	"requests":                 {"requests"},
	"idna":                     {"idna"},
	"werkzeug":                 {"werkzeug"},
	"flask":                    {"flask"},
	"sqlalchemy":               {"sqlalchemy"},
	"paramiko":                 {"paramiko"},
	"ansible-core":             {"ansible"},
}
