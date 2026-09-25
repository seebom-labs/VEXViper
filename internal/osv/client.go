// Package osv is a minimal client for https://api.osv.dev used to enrich
// BOMHort findings with details, aliases, references, affected ranges and
// vulnerable Go symbols.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the public OSV API.
const DefaultBaseURL = "https://api.osv.dev"

// Vulnerability is a subset of the OSV schema (https://ossf.github.io/osv-schema/).
type Vulnerability struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	Related          []string       `json:"related"`
	Published        string         `json:"published"`
	Modified         string         `json:"modified"`
	Affected         []Affected     `json:"affected"`
	References       []Reference    `json:"references"`
	Severity         []Severity     `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// Affected describes one affected package.
type Affected struct {
	Package           Package        `json:"package"`
	Ranges            []Range        `json:"ranges"`
	Versions          []string       `json:"versions"`
	EcosystemSpecific EcoSpecific    `json:"ecosystem_specific"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
}

// Package identifies a package.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

// Range is a version range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one range event.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// EcoSpecific carries ecosystem data: Go vulnerable imports/symbols and
// RustSec's affected functions.
type EcoSpecific struct {
	Imports []Import `json:"imports"`
	Affects struct {
		Functions []string `json:"functions"`
	} `json:"affects"`
}

// Import lists vulnerable symbols of a package path.
type Import struct {
	Path    string   `json:"path"`
	GOOS    []string `json:"goos"`
	GOARCH  []string `json:"goarch"`
	Symbols []string `json:"symbols"`
}

// Reference is a link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Severity is a scoring entry.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Client queries OSV.
type Client struct {
	baseURL string
	http    *http.Client

	mu    sync.Mutex
	cache map[string]*Vulnerability
}

// New returns a client; baseURL empty means DefaultBaseURL.
func New(baseURL string, hc *http.Client) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: hc, cache: map[string]*Vulnerability{}}
}

// Get fetches a vulnerability by ID (cached per client).
func (c *Client) Get(ctx context.Context, id string) (*Vulnerability, error) {
	c.mu.Lock()
	if v, ok := c.cache[id]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: get %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("osv: %s not found", id)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: get %s: HTTP %d", id, resp.StatusCode)
	}
	var v Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("osv: decode %s: %w", id, err)
	}
	c.mu.Lock()
	c.cache[id] = &v
	c.mu.Unlock()
	return &v, nil
}

// FixedVersions returns all "fixed" events across ranges of affected entries
// whose package matches purlBase (purl without version), or all when purlBase is empty.
func (v *Vulnerability) FixedVersions(purlBase string) []string {
	var fixed []string
	for _, a := range v.Affected {
		if purlBase != "" && a.Package.PURL != "" && !strings.EqualFold(a.Package.PURL, purlBase) {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixed = append(fixed, e.Fixed)
				}
			}
		}
	}
	return fixed
}

// VulnerableImports collects Go import paths + symbols from ecosystem_specific.
func (v *Vulnerability) VulnerableImports() []Import {
	var imports []Import
	for _, a := range v.Affected {
		imports = append(imports, a.EcosystemSpecific.Imports...)
	}
	return imports
}

// VulnerableFunctions collects RustSec's affected function paths
// (crate::module::function) from ecosystem_specific.affects.
func (v *Vulnerability) VulnerableFunctions() []string {
	var out []string
	for _, a := range v.Affected {
		out = append(out, a.EcosystemSpecific.Affects.Functions...)
	}
	return out
}

// ReferenceURLs returns references of the given types (e.g. "FIX", "ADVISORY"); empty types returns all.
func (v *Vulnerability) ReferenceURLs(types ...string) []string {
	var urls []string
	for _, r := range v.References {
		if len(types) == 0 {
			urls = append(urls, r.URL)
			continue
		}
		for _, t := range types {
			if strings.EqualFold(r.Type, t) {
				urls = append(urls, r.URL)
				break
			}
		}
	}
	return urls
}

// CVE returns the first CVE alias (or the ID if it is a CVE).
func (v *Vulnerability) CVE() string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return ""
}
