// Package assesscache stores provider verdicts so that identical questions
// are not sent to an LLM twice. With thousands of SBOMs the number of
// distinct (product commit, vulnerability, package) tuples is far smaller
// than the number of findings: many SBOMs describe the same product build in
// different clusters or environments.
//
// A cache key covers everything that could change the answer: the provider
// (incl. model), the product commit, the finding identity, a fingerprint of
// the deterministic evidence (kinds, strength, OSV modification time) and
// the prompt version. Entries are plain JSON files, one per key, so the
// cache can live on a PVC, be inspected with jq and be pruned with find.
package assesscache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/seebom-labs/vexviper/internal/evidence"
	"github.com/seebom-labs/vexviper/internal/llm"
)

// Version is mixed into every key; bump it when the prompt or schema changes
// in a way that should invalidate old verdicts.
const Version = "v1"

// Key identifies one assessment question.
type Key struct {
	Provider string `json:"provider"`
	// Commit is the product's checked-out commit ("" when no repo was used).
	Commit string `json:"commit,omitempty"`
	// Repo is the repository reference used when Commit is unknown.
	Repo   string `json:"repo,omitempty"`
	VulnID string `json:"vuln_id"`
	PURL   string `json:"purl"`
	// Evidence fingerprints the deterministic evidence the provider saw.
	Evidence string `json:"evidence"`
	Version  string `json:"version"`
}

// Entry is what gets persisted.
type Entry struct {
	Key        Key            `json:"key"`
	Assessment llm.Assessment `json:"assessment"`
	CreatedAt  time.Time      `json:"created_at"`
	// Product names the SBOM/product that first produced the verdict.
	Product string `json:"product,omitempty"`
}

// Store is a directory-backed cache. A nil or zero Store is disabled.
type Store struct {
	// Dir holds one <hash>.json per entry.
	Dir string
	// TTL expires entries (0 = never; keys already change with commit and
	// evidence, so expiry is only needed to force periodic re-evaluation).
	TTL time.Duration
	// Now is swappable for tests.
	Now func() time.Time

	mu sync.Mutex
}

// New returns a store rooted at dir.
func New(dir string, ttl time.Duration) *Store {
	return &Store{Dir: dir, TTL: ttl}
}

// Enabled reports whether the store persists anything.
func (s *Store) Enabled() bool { return s != nil && s.Dir != "" }

// KeyFor builds the key for one provider question.
func KeyFor(provider, commit, repo string, rep *evidence.Report) Key {
	k := Key{Provider: provider, Commit: commit, Version: Version}
	if commit == "" {
		k.Repo = repo
	}
	if rep != nil {
		k.VulnID, k.PURL = rep.Finding.VulnID, rep.Finding.PURL
		k.Evidence = Fingerprint(rep)
	}
	return k
}

// Fingerprint hashes the parts of a report that influence a verdict but are
// stable across SBOMs: evidence kinds with their strength, the OSV record's
// modification time and the package/fixed versions. Free-text summaries and
// paths are excluded so the same commit yields the same fingerprint
// regardless of where it was cloned to.
func Fingerprint(rep *evidence.Report) string {
	if rep == nil {
		return ""
	}
	parts := make([]string, 0, len(rep.Items)+3)
	for _, it := range rep.Items {
		parts = append(parts, fmt.Sprintf("%s:%t", it.Kind, it.Strong))
	}
	sort.Strings(parts)
	parts = append(parts, "version="+rep.Finding.PackageVersion, "fixed="+rep.Finding.FixedVersion)
	if rep.OSV != nil {
		parts = append(parts, "osv_modified="+rep.OSV.Modified)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:8])
}

func (k Key) hash() string {
	b, _ := json.Marshal(k)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Store) path(k Key) string {
	return filepath.Join(s.Dir, k.hash()+".json")
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Get returns the cached assessment for k, if present and not expired.
func (s *Store) Get(k Key) (llm.Assessment, bool) {
	if !s.Enabled() {
		return llm.Assessment{}, false
	}
	data, err := os.ReadFile(s.path(k))
	if err != nil {
		return llm.Assessment{}, false
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil || e.Key != k {
		return llm.Assessment{}, false
	}
	if s.TTL > 0 && s.now().Sub(e.CreatedAt) > s.TTL {
		return llm.Assessment{}, false
	}
	return e.Assessment, true
}

// Put stores a verdict. Usage is reset: a cache hit costs nothing, and the
// original cost was already accounted for in the run that produced it.
func (s *Store) Put(k Key, a llm.Assessment, product string) error {
	if !s.Enabled() {
		return nil
	}
	a.Usage = llm.Usage{}
	e := Entry{Key: k, Assessment: a, CreatedAt: s.now(), Product: product}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	tmp := s.path(k) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(k))
}

// Stats summarizes the cache directory.
type Stats struct {
	Entries int
	Bytes   int64
}

// Stats counts entries in Dir.
func (s *Store) Stats() (Stats, error) {
	var st Stats
	if !s.Enabled() {
		return st, nil
	}
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		st.Entries++
		if info, err := e.Info(); err == nil {
			st.Bytes += info.Size()
		}
	}
	return st, nil
}
