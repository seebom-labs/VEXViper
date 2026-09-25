package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// depGraph is the resolved dependency closure of a product as recorded by a
// lockfile. It answers three questions the import scan alone cannot:
//
//   - through which direct dependencies does the vulnerable package enter the
//     product (dependency path)?
//   - which other packages depend on it (is product code its only consumer)?
//   - is it part of the runtime closure at all, or only pulled in by
//     development/test dependencies?
//
// The last answer is authoritative when the package manager wrote the flag
// itself (npm `dev: true`, composer `packages-dev`, poetry `category`/`groups`,
// Pipfile.lock `develop`) or when the lockfile carries the complete edge set
// and the root's runtime/dev split, so reachability can be computed exactly.
type depGraph struct {
	File   string // lockfile path relative to the checkout
	Format string // human readable format name

	// Edges maps a package to its (normalised) dependencies.
	Edges map[string][]string
	// Present lists every package of the closure.
	Present map[string]bool
	// HasEdges reports that Edges is complete for every package in Present.
	HasEdges bool

	// Root and RootDev are the product's direct runtime / dev-only dependencies.
	Root    []string
	RootDev []string
	// RootKnown reports that Root (and, if DevSplit, RootDev) were recovered.
	RootKnown bool
	// DevSplit reports that RootDev reliably separates dev-only direct deps.
	DevSplit bool

	// DevOnly holds package-manager written dev-only flags; DevFlags reports
	// that the lockfile carries such flags at all.
	DevOnly  map[string]bool
	DevFlags bool

	// Namespaces maps composer packages to their PSR-4/PSR-0 namespaces.
	Namespaces map[string][]string

	norm func(string) string
}

func newGraph(file, format string, norm func(string) string) *depGraph {
	if norm == nil {
		norm = func(s string) string { return s }
	}
	return &depGraph{File: file, Format: format, Edges: map[string][]string{}, Present: map[string]bool{}, DevOnly: map[string]bool{}, norm: norm}
}

func (g *depGraph) key(name string) string { return g.norm(name) }

func (g *depGraph) add(name string, deps ...string) {
	k := g.key(name)
	g.Present[k] = true
	for _, d := range deps {
		dk := g.key(d)
		if dk == "" || dk == k {
			continue
		}
		g.Edges[k] = appendUnique(g.Edges[k], dk)
	}
}

func (g *depGraph) has(name string) bool { return g != nil && g.Present[g.key(name)] }

func (g *depGraph) isRoot(name string) bool {
	k := g.key(name)
	return containsKey(g.Root, k) || containsKey(g.RootDev, k)
}

// dependents returns the packages (never the product itself) that depend on name.
func (g *depGraph) dependents(name string) []string {
	if !g.HasEdges {
		return nil
	}
	k := g.key(name)
	var out []string
	for p, deps := range g.Edges {
		if p != k && containsKey(deps, k) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// pathsTo returns up to max shortest paths from a direct dependency to name.
func (g *depGraph) pathsTo(name string, max int) [][]string {
	if !g.HasEdges || !g.RootKnown {
		return nil
	}
	k := g.key(name)
	var paths [][]string
	starts := append(append([]string{}, g.Root...), g.RootDev...)
	for _, s := range starts {
		if len(paths) >= max {
			break
		}
		if p := g.shortestPath(s, k); p != nil {
			paths = append(paths, p)
		}
	}
	return paths
}

func (g *depGraph) shortestPath(from, to string) []string {
	if from == to {
		return []string{from}
	}
	prev := map[string]string{from: ""}
	queue := []string{from}
	for len(queue) > 0 && len(prev) < 20000 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range g.Edges[cur] {
			if _, seen := prev[next]; seen {
				continue
			}
			prev[next] = cur
			if next == to {
				var path []string
				for n := to; n != ""; n = prev[n] {
					path = append([]string{n}, path...)
				}
				return path
			}
			queue = append(queue, next)
		}
	}
	return nil
}

// reachableFrom reports whether name is reachable from any of starts.
func (g *depGraph) reachableFrom(starts []string, name string) bool {
	k := g.key(name)
	seen := map[string]bool{}
	queue := append([]string{}, starts...)
	for len(queue) > 0 && len(seen) < 20000 {
		cur := queue[0]
		queue = queue[1:]
		if cur == k {
			return true
		}
		if seen[cur] {
			continue
		}
		seen[cur] = true
		queue = append(queue, g.Edges[cur]...)
	}
	return false
}

// devOnly reports whether name is outside the runtime closure. known is false
// when the lockfile cannot answer authoritatively.
func (g *depGraph) devOnly(name string) (dev, known bool) {
	if g == nil || !g.has(name) {
		return false, false
	}
	k := g.key(name)
	if g.DevFlags {
		return g.DevOnly[k], true
	}
	if g.HasEdges && g.RootKnown && g.DevSplit {
		if g.reachableFrom(g.Root, k) {
			return false, true
		}
		return g.reachableFrom(g.RootDev, k), true
	}
	return false, false
}

// loadGraph parses the lockfile at path (base name decides the format) and,
// where the lockfile lacks the root's dependency split, the sibling manifest.
func loadGraph(rel string, data []byte, read func(string) []byte) *depGraph {
	base := filepath.Base(rel)
	sibling := func(name string) []byte { return read(filepath.Join(filepath.Dir(rel), name)) }
	var g *depGraph
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json":
		g = parsePackageLock(rel, data)
		if g != nil && !g.RootKnown {
			npmRootFromManifest(g, sibling("package.json"))
		}
	case "yarn.lock":
		g = parseYarnLock(rel, data)
		npmRootFromManifest(g, sibling("package.json"))
	case "pnpm-lock.yaml":
		g = parsePnpmLock(rel, data)
	case "Cargo.lock":
		g = parseCargoLock(rel, data)
		cargoRootFromManifest(g, sibling("Cargo.toml"))
	case "poetry.lock":
		g = parsePoetryLock(rel, data)
		pyRootFromManifest(g, sibling("pyproject.toml"))
	case "uv.lock":
		g = parseUvLock(rel, data)
	case "Pipfile.lock":
		g = parsePipfileLock(rel, data)
		pipfileRoot(g, sibling("Pipfile"))
	case "Gemfile.lock":
		g = parseGemfileLock(rel, data)
		gemfileGroups(g, sibling("Gemfile"))
	case "composer.lock":
		g = parseComposerLock(rel, data)
		composerRootFromManifest(g, sibling("composer.json"))
	case "packages.lock.json":
		g = parseNugetLock(rel, data)
	case "pubspec.lock":
		g = parsePubspecLock(rel, data)
	case "gradle.lockfile":
		g = parseGradleLockfile(rel, data)
	}
	return g
}

// ---- npm ----

var pep503SepRE = regexp.MustCompile(`[-_.]+`)

func pep503(s string) string { return strings.ToLower(pep503SepRE.ReplaceAllString(s, "-")) }

func lower(s string) string { return strings.ToLower(s) }

func crateKey(s string) string { return strings.ToLower(strings.ReplaceAll(s, "-", "_")) }

type packageLockV1Dep struct {
	Dev          bool                        `json:"dev"`
	Requires     map[string]string           `json:"requires"`
	Dependencies map[string]packageLockV1Dep `json:"dependencies"`
}

func parsePackageLock(rel string, data []byte) *depGraph {
	var lf struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Name                 string            `json:"name"`
			Dev                  bool              `json:"dev"`
			Link                 bool              `json:"link"`
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		} `json:"packages"`
		Dependencies map[string]packageLockV1Dep `json:"dependencies"`
	}
	if json.Unmarshal(data, &lf) != nil {
		return nil
	}
	g := newGraph(rel, "package-lock.json", nil)
	g.HasEdges, g.DevFlags = true, true
	devCount, total := map[string]int{}, map[string]int{}
	if len(lf.Packages) > 0 {
		g.Format += " v" + strconv.Itoa(lf.LockfileVersion)
		g.RootKnown, g.DevSplit = true, true
		for key, p := range lf.Packages {
			if p.Link {
				continue
			}
			if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
				name := key[i+len("node_modules/"):]
				deps := append(keys(p.Dependencies), keys(p.OptionalDependencies)...)
				deps = append(deps, keys(p.PeerDependencies)...)
				g.add(name, deps...)
				total[name]++
				if p.Dev {
					devCount[name]++
				}
				continue
			}
			// "" is the root, other keys are workspace packages.
			g.Root = appendUniqueAll(g.Root, keys(p.Dependencies), keys(p.OptionalDependencies), keys(p.PeerDependencies))
			g.RootDev = appendUniqueAll(g.RootDev, keys(p.DevDependencies))
		}
	} else {
		g.Format += " v1"
		var walk func(map[string]packageLockV1Dep)
		walk = func(m map[string]packageLockV1Dep) {
			for name, d := range m {
				g.add(name, keys(d.Requires)...)
				total[name]++
				if d.Dev {
					devCount[name]++
				}
				walk(d.Dependencies)
			}
		}
		walk(lf.Dependencies)
	}
	for name, n := range total {
		g.DevOnly[g.key(name)] = devCount[name] == n
	}
	g.RootDev = minus(g.RootDev, g.Root)
	return g
}

func npmRootFromManifest(g *depGraph, data []byte) {
	if g == nil || data == nil {
		return
	}
	var m struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		Workspaces           any               `json:"workspaces"`
	}
	if json.Unmarshal(data, &m) != nil {
		return
	}
	g.Root = appendUniqueAll(nil, keys(m.Dependencies), keys(m.PeerDependencies), keys(m.OptionalDependencies))
	g.RootDev = minus(keys(m.DevDependencies), g.Root)
	// Workspace members declare their own dependencies; the root manifest
	// alone cannot split runtime from dev.
	g.RootKnown, g.DevSplit = true, m.Workspaces == nil
}

var yarnHeaderRE = regexp.MustCompile(`^[^\s#].*:\s*$`)

func parseYarnLock(rel string, data []byte) *depGraph {
	g := newGraph(rel, "yarn.lock", nil)
	g.HasEdges = true
	var current []string
	inDeps := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#"):
			continue
		case yarnHeaderRE.MatchString(line):
			current, inDeps = nil, false
			for _, k := range strings.Split(strings.TrimSuffix(strings.TrimSpace(line), ":"), ",") {
				k = strings.Trim(strings.TrimSpace(k), `"`)
				if name := npmSpecName(k); name != "" && name != "__metadata" {
					current = appendUnique(current, name)
				}
			}
			for _, n := range current {
				g.add(n)
			}
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    "):
			key := strings.TrimSpace(line)
			inDeps = key == "dependencies:" || key == "optionalDependencies:"
		case inDeps && strings.HasPrefix(line, "    "):
			dep := yarnDepName(strings.TrimSpace(line))
			if dep == "" {
				continue
			}
			for _, n := range current {
				g.add(n, dep)
			}
		}
	}
	return g
}

// npmSpecName returns the package name of "name@range" / "@scope/name@npm:range".
func npmSpecName(spec string) string {
	if spec == "" {
		return ""
	}
	off := 0
	if spec[0] == '@' {
		off = 1
	}
	i := strings.Index(spec[off:], "@")
	if i < 0 {
		return ""
	}
	return spec[:off+i]
}

func yarnDepName(line string) string {
	if strings.HasPrefix(line, `"`) {
		if j := strings.Index(line[1:], `"`); j >= 0 {
			return line[1 : j+1]
		}
		return ""
	}
	end := strings.IndexAny(line, " :")
	if end < 0 {
		return line
	}
	return line[:end]
}

func parsePnpmLock(rel string, data []byte) *depGraph {
	var lf struct {
		Dependencies         map[string]any `yaml:"dependencies"`
		DevDependencies      map[string]any `yaml:"devDependencies"`
		OptionalDependencies map[string]any `yaml:"optionalDependencies"`
		Importers            map[string]struct {
			Dependencies         map[string]any `yaml:"dependencies"`
			DevDependencies      map[string]any `yaml:"devDependencies"`
			OptionalDependencies map[string]any `yaml:"optionalDependencies"`
		} `yaml:"importers"`
		Packages map[string]struct {
			Dependencies         map[string]any `yaml:"dependencies"`
			OptionalDependencies map[string]any `yaml:"optionalDependencies"`
			Dev                  *bool          `yaml:"dev"`
		} `yaml:"packages"`
		Snapshots map[string]struct {
			Dependencies         map[string]any `yaml:"dependencies"`
			OptionalDependencies map[string]any `yaml:"optionalDependencies"`
		} `yaml:"snapshots"`
	}
	if yaml.Unmarshal(data, &lf) != nil {
		return nil
	}
	g := newGraph(rel, "pnpm-lock.yaml", nil)
	g.HasEdges, g.RootKnown, g.DevSplit = true, true, true
	g.Root = appendUniqueAll(nil, keys(lf.Dependencies), keys(lf.OptionalDependencies))
	g.RootDev = keys(lf.DevDependencies)
	for _, imp := range lf.Importers {
		g.Root = appendUniqueAll(g.Root, keys(imp.Dependencies), keys(imp.OptionalDependencies))
		g.RootDev = appendUniqueAll(g.RootDev, keys(imp.DevDependencies))
	}
	g.RootDev = minus(g.RootDev, g.Root)
	flags := 0
	for key, p := range lf.Packages {
		name := pnpmKeyName(key)
		g.add(name, append(keys(p.Dependencies), keys(p.OptionalDependencies)...)...)
		if p.Dev != nil {
			flags++
			k := g.key(name)
			prev, seen := g.DevOnly[k]
			g.DevOnly[k] = *p.Dev && (!seen || prev)
		}
	}
	for key, s := range lf.Snapshots {
		g.add(pnpmKeyName(key), append(keys(s.Dependencies), keys(s.OptionalDependencies)...)...)
	}
	g.DevFlags = flags > 0 && flags == len(lf.Packages)
	return g
}

// pnpmKeyName maps "/name/1.0.0", "/@s/n/1.0.0", "/name@1.0.0(peer)" and
// "name@1.0.0" to name.
func pnpmKeyName(key string) string {
	k := strings.TrimPrefix(key, "/")
	if i := strings.Index(k, "("); i >= 0 {
		k = k[:i]
	}
	off := 0
	if strings.HasPrefix(k, "@") {
		off = 1
	}
	// v5 keys put the version behind a slash (name/1.0.0, @s/n/1.0.0_peer@1),
	// v6+ behind an @ (name@1.0.0, @s/n@1.0.0).
	if strings.Count(k[off:], "/") > off {
		return k[:strings.LastIndex(k, "/")]
	}
	if at := strings.Index(k[off:], "@"); at >= 0 {
		return k[:off+at]
	}
	return k
}

// ---- cargo ----

func parseCargoLock(rel string, data []byte) *depGraph {
	g := newGraph(rel, "Cargo.lock", crateKey)
	g.HasEdges = true
	var (
		name     string
		hasSrc   bool
		deps     []string
		inDeps   bool
		members  []string
		memberOf = map[string][]string{}
	)
	flush := func() {
		if name == "" {
			return
		}
		g.add(name, deps...)
		if !hasSrc {
			members = append(members, g.key(name))
			memberOf[g.key(name)] = deps
		}
		name, hasSrc, deps, inDeps = "", false, nil, false
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush()
		case inDeps:
			if line == "]" {
				inDeps = false
				continue
			}
			if d := strings.Fields(strings.Trim(line, `",`)); len(d) > 0 {
				deps = append(deps, d[0])
			}
		case strings.HasPrefix(line, "name = "):
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		case strings.HasPrefix(line, "source = "):
			hasSrc = true
		case strings.HasPrefix(line, "dependencies = ["):
			rest := strings.TrimSuffix(strings.TrimPrefix(line, "dependencies = ["), "]")
			if strings.HasSuffix(line, "]") {
				for _, d := range strings.Split(rest, ",") {
					if f := strings.Fields(strings.Trim(strings.TrimSpace(d), `"`)); len(f) > 0 {
						deps = append(deps, f[0])
					}
				}
			} else {
				inDeps = true
			}
		}
	}
	flush()
	// Workspace members are the product: their edges become the root and they
	// never count as third-party dependents.
	for _, m := range members {
		g.Root = appendUniqueAll(g.Root, memberOf[m])
		delete(g.Edges, m)
		delete(g.Present, m)
	}
	g.Root = minus(g.Root, members)
	g.RootKnown = len(members) > 0
	return g
}

var cargoRenameRE = regexp.MustCompile(`package\s*=\s*"([^"]+)"`)

// cargoRootFromManifest splits dev/build-only direct dependencies off Root
// using Cargo.toml of a single-crate project.
func cargoRootFromManifest(g *depGraph, data []byte) {
	if g == nil || data == nil {
		return
	}
	var runtime, dev []string
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		if section == "[workspace]" && strings.HasPrefix(line, "members") {
			// Multi-crate workspaces: members declare their own dev split.
			return
		}
		key := strings.Trim(strings.TrimSpace(strings.SplitN(line, "=", 2)[0]), `"`)
		if m := cargoRenameRE.FindStringSubmatch(line); m != nil {
			key = m[1]
		}
		switch {
		case strings.HasSuffix(section, "dev-dependencies]"), strings.HasSuffix(section, "build-dependencies]"):
			dev = append(dev, key)
		case strings.HasSuffix(section, "dependencies]"):
			runtime = append(runtime, key)
		}
	}
	if len(runtime)+len(dev) == 0 {
		return
	}
	var root, rootDev []string
	for _, r := range g.Root {
		if containsKey(mapKeys(g, dev), r) && !containsKey(mapKeys(g, runtime), r) {
			rootDev = append(rootDev, r)
		} else {
			root = append(root, r)
		}
	}
	g.Root, g.RootDev, g.DevSplit = root, rootDev, true
}

func mapKeys(g *depGraph, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, g.key(n))
	}
	return out
}

// ---- python ----

var tomlNameRE = regexp.MustCompile(`name\s*=\s*"([^"]+)"`)

func parsePoetryLock(rel string, data []byte) *depGraph {
	g := newGraph(rel, "poetry.lock", pep503)
	g.HasEdges = true
	var (
		name    string
		deps    []string
		devFlag *bool
		section string
	)
	flush := func() {
		if name == "" {
			return
		}
		g.add(name, deps...)
		if devFlag != nil {
			g.DevFlags = true
			g.DevOnly[g.key(name)] = *devFlag
		}
		name, deps, devFlag, section = "", nil, nil, ""
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "[[package]]":
			flush()
		case strings.HasPrefix(line, "["):
			section = line
		case section == "" && strings.HasPrefix(line, "name = "):
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		case section == "" && strings.HasPrefix(line, "category = "):
			v := strings.Trim(strings.TrimPrefix(line, "category = "), `"`) == "dev"
			devFlag = &v
		case section == "" && strings.HasPrefix(line, "groups = "):
			v := !strings.Contains(line, `"main"`)
			devFlag = &v
		case section == "[package.dependencies]" && strings.Contains(line, "="):
			dep := strings.Trim(strings.TrimSpace(strings.SplitN(line, "=", 2)[0]), `"`)
			if dep != "" && dep != "python" {
				deps = append(deps, dep)
			}
		}
	}
	flush()
	return g
}

var reqNameRE = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

// pyRootFromManifest recovers the root split from pyproject.toml
// ([project], [tool.poetry], [dependency-groups]).
func pyRootFromManifest(g *depGraph, data []byte) {
	if g == nil || data == nil {
		return
	}
	var runtime, dev []string
	section, inArray := "", false
	addReq := func(s string, isDev bool) {
		s = strings.Trim(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ",")), `"'`)
		m := reqNameRE.FindStringSubmatch(s)
		if m == nil || strings.EqualFold(m[1], "python") {
			return
		}
		if isDev {
			dev = append(dev, m[1])
		} else {
			runtime = append(runtime, m[1])
		}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && !inArray {
			section = strings.ToLower(line)
			continue
		}
		switch {
		case section == "[tool.poetry.dependencies]" && strings.Contains(line, "="):
			addReq(strings.SplitN(line, "=", 2)[0], false)
		case section == "[tool.poetry.dev-dependencies]" && strings.Contains(line, "="):
			addReq(strings.SplitN(line, "=", 2)[0], true)
		case strings.HasPrefix(section, "[tool.poetry.group.") && strings.HasSuffix(section, ".dependencies]") && strings.Contains(line, "="):
			addReq(strings.SplitN(line, "=", 2)[0], isDevSection(section))
		case section == "[project]" || section == "[project.optional-dependencies]" || section == "[dependency-groups]":
			isDev := section == "[dependency-groups]"
			if inArray {
				if strings.HasPrefix(line, "]") {
					inArray = false
					continue
				}
				addReq(line, isDev)
				continue
			}
			key, val, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			if section == "[project]" && key != "dependencies" {
				continue
			}
			if section == "[dependency-groups]" && !isDevSection("["+key+"]") {
				isDev = false
			}
			val = strings.TrimSpace(val)
			if strings.HasPrefix(val, "[") {
				body := strings.TrimPrefix(val, "[")
				if strings.HasSuffix(body, "]") {
					for _, it := range strings.Split(strings.TrimSuffix(body, "]"), ",") {
						addReq(it, isDev)
					}
				} else {
					inArray = true
				}
			}
		}
	}
	if len(runtime)+len(dev) == 0 {
		return
	}
	g.Root = mapKeys(g, runtime)
	g.RootDev = minus(mapKeys(g, dev), g.Root)
	g.RootKnown, g.DevSplit = true, true
}

func parseUvLock(rel string, data []byte) *depGraph {
	g := newGraph(rel, "uv.lock", pep503)
	g.HasEdges = true
	var (
		name    string
		isRoot  bool
		deps    []string
		devDeps []string
		section string
		inArray string // "deps", "dev", "opt"
	)
	flush := func() {
		if name == "" {
			return
		}
		if isRoot {
			g.Root = appendUniqueAll(g.Root, mapKeys(g, deps))
			g.RootDev = appendUniqueAll(g.RootDev, mapKeys(g, devDeps))
			g.RootKnown, g.DevSplit = true, true
		} else {
			g.add(name, deps...)
		}
		name, isRoot, deps, devDeps, section, inArray = "", false, nil, nil, "", ""
	}
	collect := func(line string, into *[]string) {
		for _, m := range tomlNameRE.FindAllStringSubmatch(line, -1) {
			*into = append(*into, m[1])
		}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "[[package]]":
			flush()
		case inArray != "":
			target := &deps
			if inArray == "dev" {
				target = &devDeps
			}
			collect(line, target)
			if strings.HasPrefix(line, "]") || strings.HasSuffix(line, "]") {
				inArray = ""
			}
		case strings.HasPrefix(line, "["):
			section = line
		case section == "" && strings.HasPrefix(line, "name = "):
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		case section == "" && strings.HasPrefix(line, "source = ") && (strings.Contains(line, "editable") || strings.Contains(line, "virtual")):
			isRoot = true
		case section == "" && strings.HasPrefix(line, "dependencies = ["):
			collect(line, &deps)
			if !strings.HasSuffix(line, "]") {
				inArray = "deps"
			}
		case section == "[package.optional-dependencies]" && strings.Contains(line, "= ["):
			collect(line, &deps)
			if !strings.HasSuffix(line, "]") {
				inArray = "opt"
			}
		case section == "[package.dev-dependencies]" && strings.Contains(line, "= ["):
			collect(line, &devDeps)
			if !strings.HasSuffix(line, "]") {
				inArray = "dev"
			}
		}
	}
	flush()
	g.RootDev = minus(g.RootDev, g.Root)
	return g
}

func parsePipfileLock(rel string, data []byte) *depGraph {
	var lf struct {
		Default map[string]json.RawMessage `json:"default"`
		Develop map[string]json.RawMessage `json:"develop"`
	}
	if json.Unmarshal(data, &lf) != nil || (lf.Default == nil && lf.Develop == nil) {
		return nil
	}
	g := newGraph(rel, "Pipfile.lock", pep503)
	g.DevFlags = true
	for n := range lf.Default {
		g.add(n)
		g.DevOnly[g.key(n)] = false
	}
	for n := range lf.Develop {
		g.add(n)
		if _, runtime := lf.Default[n]; !runtime {
			g.DevOnly[g.key(n)] = true
		}
	}
	return g
}

func pipfileRoot(g *depGraph, data []byte) {
	if g == nil || data == nil {
		return
	}
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"`)
		switch section {
		case "[packages]":
			g.Root = appendUnique(g.Root, g.key(key))
		case "[dev-packages]":
			g.RootDev = appendUnique(g.RootDev, g.key(key))
		}
	}
	g.RootDev = minus(g.RootDev, g.Root)
	g.RootKnown, g.DevSplit = true, true
}

// ---- ruby ----

func parseGemfileLock(rel string, data []byte) *depGraph {
	g := newGraph(rel, "Gemfile.lock", nil)
	g.HasEdges = true
	section, current := "", ""
	for _, raw := range strings.Split(string(data), "\n") {
		if raw == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		line := strings.TrimSpace(raw)
		switch {
		case indent == 0:
			section, current = line, ""
		case section == "DEPENDENCIES" && indent == 2:
			g.Root = appendUnique(g.Root, gemName(line))
		case indent == 4 && strings.Contains(line, " ("):
			current = gemName(line)
			g.add(current)
		case indent == 6 && current != "":
			g.add(current, gemName(line))
		}
	}
	g.RootKnown = len(g.Root) > 0
	return g
}

func gemName(line string) string {
	name := line
	if i := strings.Index(name, " "); i >= 0 {
		name = name[:i]
	}
	return strings.TrimSuffix(name, "!")
}

var gemLineRE = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](.*)$`)
var groupLineRE = regexp.MustCompile(`^\s*group\s+(.+?)\s+do\b`)
var gemGroupOptRE = regexp.MustCompile(`groups?\s*(:|=>)\s*(\[[^\]]*\]|:\w+)`)
var gemSymbolRE = regexp.MustCompile(`:(\w+)`)

// gemfileGroups moves gems declared only in development/test groups to RootDev.
func gemfileGroups(g *depGraph, data []byte) {
	if g == nil || data == nil {
		return
	}
	var stack []bool // true = dev/test group
	devGems, runtimeGems := map[string]bool{}, map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "#"):
		case groupLineRE.MatchString(line):
			stack = append(stack, isDevGroupList(groupLineRE.FindStringSubmatch(line)[1]))
		case line == "end" && len(stack) > 0:
			stack = stack[:len(stack)-1]
		default:
			m := gemLineRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			inDev := len(stack) > 0 && stack[len(stack)-1]
			if gm := gemGroupOptRE.FindStringSubmatch(m[2]); gm != nil {
				inDev = isDevGroupList(gm[2])
			}
			if inDev {
				devGems[m[1]] = true
			} else {
				runtimeGems[m[1]] = true
			}
		}
	}
	var root, rootDev []string
	for _, r := range g.Root {
		if devGems[r] && !runtimeGems[r] {
			rootDev = append(rootDev, r)
		} else {
			root = append(root, r)
		}
	}
	g.Root, g.RootDev, g.DevSplit = root, rootDev, true
}

func isDevGroupList(s string) bool {
	all := true
	found := false
	for _, sym := range gemSymbolRE.FindAllStringSubmatch(s, -1) {
		found = true
		if !isDevSection(sym[1]) && sym[1] != "ci" {
			all = false
		}
	}
	return found && all
}

// ---- composer ----

type composerPackage struct {
	Name     string            `json:"name"`
	Require  map[string]string `json:"require"`
	Autoload struct {
		PSR4 map[string]any `json:"psr-4"`
		PSR0 map[string]any `json:"psr-0"`
	} `json:"autoload"`
}

func parseComposerLock(rel string, data []byte) *depGraph {
	var lf struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lf) != nil || (lf.Packages == nil && lf.PackagesDev == nil) {
		return nil
	}
	g := newGraph(rel, "composer.lock", lower)
	g.HasEdges, g.DevFlags = true, true
	g.Namespaces = map[string][]string{}
	addPkg := func(p composerPackage, dev bool) {
		var deps []string
		for r := range p.Require {
			if composerIsPackage(r) {
				deps = append(deps, r)
			}
		}
		g.add(p.Name, deps...)
		k := g.key(p.Name)
		if dev {
			if _, seen := g.DevOnly[k]; !seen {
				g.DevOnly[k] = true
			}
		} else {
			g.DevOnly[k] = false
		}
		for ns := range p.Autoload.PSR4 {
			g.Namespaces[k] = appendUnique(g.Namespaces[k], strings.TrimSuffix(ns, `\`))
		}
		for ns := range p.Autoload.PSR0 {
			g.Namespaces[k] = appendUnique(g.Namespaces[k], strings.TrimSuffix(ns, `\`))
		}
	}
	for _, p := range lf.Packages {
		addPkg(p, false)
	}
	for _, p := range lf.PackagesDev {
		addPkg(p, true)
	}
	return g
}

func composerIsPackage(name string) bool {
	return strings.Contains(name, "/") && !strings.HasPrefix(name, "composer-")
}

func composerRootFromManifest(g *depGraph, data []byte) {
	if g == nil || data == nil {
		return
	}
	var m struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(data, &m) != nil {
		return
	}
	for r := range m.Require {
		if composerIsPackage(r) {
			g.Root = appendUnique(g.Root, g.key(r))
		}
	}
	for r := range m.RequireDev {
		if composerIsPackage(r) && !containsKey(g.Root, g.key(r)) {
			g.RootDev = appendUnique(g.RootDev, g.key(r))
		}
	}
	g.RootKnown, g.DevSplit = true, true
}

// ---- nuget ----

func parseNugetLock(rel string, data []byte) *depGraph {
	var lf struct {
		Version      int `json:"version"`
		Dependencies map[string]map[string]struct {
			Type         string            `json:"type"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(data, &lf) != nil || lf.Dependencies == nil {
		return nil
	}
	g := newGraph(rel, "packages.lock.json", lower)
	g.HasEdges, g.RootKnown = true, true
	for _, tfm := range lf.Dependencies {
		for name, d := range tfm {
			switch d.Type {
			case "Project":
				g.Root = appendUniqueAll(g.Root, mapKeys(g, keys(d.Dependencies)))
			case "Direct":
				g.Root = appendUnique(g.Root, g.key(name))
				g.add(name, keys(d.Dependencies)...)
			default:
				g.add(name, keys(d.Dependencies)...)
			}
		}
	}
	return g
}

// ---- dart ----

func parsePubspecLock(rel string, data []byte) *depGraph {
	var lf struct {
		Packages map[string]struct {
			Dependency string `yaml:"dependency"`
		} `yaml:"packages"`
	}
	if yaml.Unmarshal(data, &lf) != nil || lf.Packages == nil {
		return nil
	}
	g := newGraph(rel, "pubspec.lock", nil)
	g.RootKnown = true
	for name, p := range lf.Packages {
		g.add(name)
		switch p.Dependency {
		case "direct main", "direct overridden":
			g.Root = appendUnique(g.Root, name)
		case "direct dev":
			g.RootDev = appendUnique(g.RootDev, name)
		}
	}
	return g
}

// ---- gradle ----

func parseGradleLockfile(rel string, data []byte) *depGraph {
	g := newGraph(rel, "gradle.lockfile", lower)
	runtimeConf := false
	confs := map[string][]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coord, cs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parts := strings.Split(coord, ":")
		if len(parts) < 2 {
			continue
		}
		name := parts[0] + ":" + parts[1]
		g.add(name)
		for _, c := range strings.Split(cs, ",") {
			c = strings.TrimSpace(c)
			confs[g.key(name)] = append(confs[g.key(name)], c)
			if !isTestConfiguration(c) {
				runtimeConf = true
			}
		}
	}
	if !runtimeConf {
		// Only test configurations are locked; nothing can be called dev-only.
		return g
	}
	g.DevFlags = true
	for k, cs := range confs {
		dev := true
		for _, c := range cs {
			if !isTestConfiguration(c) {
				dev = false
			}
		}
		g.DevOnly[k] = dev
	}
	return g
}

func isTestConfiguration(c string) bool {
	l := strings.ToLower(c)
	return strings.HasPrefix(l, "test") || strings.Contains(l, "test") || strings.HasPrefix(l, "annotationprocessor") || strings.HasPrefix(l, "kapt") || strings.HasPrefix(l, "ksp") || strings.HasPrefix(l, "checkstyle") || strings.HasPrefix(l, "pmd") || strings.HasPrefix(l, "spotbugs") || strings.HasPrefix(l, "detekt") || strings.HasPrefix(l, "jacoco")
}

// ---- helpers ----

func appendUnique(list []string, s string) []string {
	if s == "" || containsKey(list, s) {
		return list
	}
	return append(list, s)
}

func appendUniqueAll(list []string, more ...[]string) []string {
	for _, m := range more {
		for _, s := range m {
			list = appendUnique(list, s)
		}
	}
	return list
}

func minus(list, remove []string) []string {
	var out []string
	for _, s := range list {
		if !containsKey(remove, s) {
			out = append(out, s)
		}
	}
	return out
}

func containsKey(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
