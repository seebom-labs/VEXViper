package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/seebom-labs/vexviper/internal/osv"
	"github.com/seebom-labs/vexviper/internal/source"
)

// RustSec advisories name the vulnerable functions
// (ecosystem_specific.affects.functions, e.g. "smallvec::SmallVec::insert_many").
// There is no build-free call-graph tool for Rust — osv-scanner's
// --call-analysis needs `cargo build`, which would execute the checkout's
// build scripts — so the check is lexical, like the Go symbol grep: does a
// non-test source file that uses the crate mention one of the vulnerable
// function names (or the full path)?
//
// A miss is Strong only when product code is provably the only caller: the
// crate is a direct dependency and Cargo.lock shows no other crate depends on
// it. Macros and re-exports can still hide a call, which is why the
// heuristic provider grades it below govulncheck.

var rustIdentRE = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

func (c *Collector) rustSymbolEvidence(repoDir string, s *ecoScan, v *osv.Vulnerability, f source.Finding) []Item {
	funcs := v.VulnerableFunctions()
	if len(funcs) == 0 || s == nil {
		return nil
	}
	crate := strings.ReplaceAll(s.name, "-", "_")
	symbols := map[string]bool{}
	paths := map[string]bool{}
	for _, fn := range funcs {
		fn = strings.TrimSpace(fn)
		if fn == "" {
			continue
		}
		paths[fn] = true
		if i := strings.LastIndex(fn, "::"); i >= 0 {
			fn = fn[i+2:]
		}
		if fn != "" {
			symbols[fn] = true
		}
	}
	if len(symbols) == 0 {
		return nil
	}
	usePatterns := cratePatterns(crate)

	symbolHits := map[string][]string{}
	var usingFiles []string
	for _, rel := range s.sources {
		if isRustTestPath(rel) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(repoDir, rel))
		if err != nil {
			continue
		}
		uses := false
		for _, re := range usePatterns {
			if re.Match(data) {
				uses = true
				break
			}
		}
		if !uses {
			continue
		}
		usingFiles = appendLimited(usingFiles, rel)
		for p := range paths {
			if strings.Contains(string(data), p) {
				symbolHits[p] = appendLimited(symbolHits[p], rel)
			}
		}
		for _, m := range rustIdentRE.FindAll(data, -1) {
			if symbols[string(m)] {
				symbolHits[string(m)] = appendLimited(symbolHits[string(m)], rel)
			}
		}
	}

	if len(usingFiles) == 0 {
		// The import scan already reported import_not_found for the crate.
		return nil
	}
	if len(symbolHits) > 0 {
		return []Item{{Kind: KindSymbolReferenced, Summary: fmt.Sprintf("product code uses crate %s and references vulnerable function name(s) %s (RustSec affected functions: %s)", s.name, strings.Join(keys(symbolHits), ", "), strings.Join(funcs, ", ")), Details: map[string]any{"files": symbolHits, "functions": funcs}}}
	}
	strong := s.direct(f) && s.soleConsumer() && !s.renamed
	summary := fmt.Sprintf("product code uses crate %s but none of the %d file(s) referencing it mentions a vulnerable function (%s)", s.name, len(usingFiles), strings.Join(funcs, ", "))
	if strong {
		summary += fmt.Sprintf("; %s shows no other crate depends on %s, so product code is the only possible caller", s.graph.File, s.name)
	} else {
		summary += "; other crates may still call it"
	}
	return []Item{{Kind: KindSymbolNotReferenced, Strong: strong, Summary: summary, Details: map[string]any{"files": usingFiles, "functions": funcs}}}
}

func isRustTestPath(rel string) bool {
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		switch seg {
		case "tests", "benches", "examples":
			return true
		}
	}
	return false
}
