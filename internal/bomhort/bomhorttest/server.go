// Package bomhorttest provides an in-memory fake of the BOMHort REST API
// for tests of packages that talk to BOMHort end-to-end (CLI, MCP server).
package bomhorttest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"

	"github.com/seebom-labs/vexviper/internal/bomhort"
)

// Upload is one recorded POST /api/v1/sboms/upload.
type Upload struct {
	Filename string
	Body     []byte
}

// Server is a fake BOMHort.
type Server struct {
	*httptest.Server
	APIKey string

	mu         sync.Mutex
	SBOMs      []bomhort.SBOM
	Vulns      map[string][]bomhort.Vulnerability
	Deps       map[string][]bomhort.DependencyNode
	Raw        map[string][]byte
	Uploads    []Upload
	Statements []bomhort.VEXStatement
	// ApplyUploads turns uploaded OpenVEX documents into statements and
	// sets vex_status on matching vulnerabilities (mimics BOMHort's worker).
	ApplyUploads bool
}

// New starts the fake. apiKey "" disables auth.
func New(apiKey string) *Server {
	s := &Server{APIKey: apiKey, Vulns: map[string][]bomhort.Vulnerability{}, Deps: map[string][]bomhort.DependencyNode{}, Raw: map[string][]byte{}, ApplyUploads: true}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"status":"ok"}`) })
	mux.HandleFunc("GET /api/v1/sboms", s.auth(s.listSBOMs))
	mux.HandleFunc("GET /api/v1/sboms/{id}/vulnerabilities", s.auth(s.vulns))
	mux.HandleFunc("GET /api/v1/sboms/{id}/dependencies", s.auth(s.deps))
	mux.HandleFunc("GET /api/v1/sboms/{id}/download", s.auth(s.download))
	mux.HandleFunc("GET /api/v1/vex/statements", s.auth(s.statements))
	mux.HandleFunc("POST /api/v1/sboms/upload", s.auth(s.upload))
	s.Server = httptest.NewServer(mux)
	return s
}

// AddSBOM registers an SBOM with its vulnerabilities, dependency tree and raw document.
func (s *Server) AddSBOM(sb bomhort.SBOM, vulns []bomhort.Vulnerability, deps []bomhort.DependencyNode, raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sb.VulnCount = uint64(len(vulns))
	s.SBOMs = append(s.SBOMs, sb)
	s.Vulns[sb.ID] = vulns
	s.Deps[sb.ID] = deps
	s.Raw[sb.ID] = raw
}

// Snapshot returns copies of uploads and statements (thread-safe).
func (s *Server) Snapshot() ([]Upload, []bomhort.VEXStatement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Upload(nil), s.Uploads...), append([]bomhort.VEXStatement(nil), s.Statements...)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.APIKey != "" && r.Header.Get("X-API-Key") != s.APIKey {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func pageBounds(r *http.Request, n int) (start, end, page, size int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	size, _ = strconv.Atoi(r.URL.Query().Get("page_size"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	start = min((page-1)*size, n)
	end = min(start+size, n)
	return start, end, page, size
}

func (s *Server) listSBOMs(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start, end, page, size := pageBounds(r, len(s.SBOMs))
	data := s.SBOMs[start:end]
	if data == nil {
		data = []bomhort.SBOM{}
	}
	writeJSON(w, 200, bomhort.Paginated[bomhort.SBOM]{Data: data, Total: uint64(len(s.SBOMs)), Page: uint64(page), PageSize: uint64(size)})
}

func (s *Server) vulns(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.Vulns[r.PathValue("id")]
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "SBOM not found"})
		return
	}
	if v == nil {
		v = []bomhort.Vulnerability{}
	}
	writeJSON(w, 200, v)
}

func (s *Server) deps(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.Deps[r.PathValue("id")]
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "SBOM not found"})
		return
	}
	if d == nil {
		d = []bomhort.DependencyNode{}
	}
	writeJSON(w, 200, d)
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.Raw[r.PathValue("id")]
	if !ok || raw == nil {
		writeJSON(w, 404, map[string]string{"error": "SBOM file not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

func (s *Server) statements(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start, end, page, size := pageBounds(r, len(s.Statements))
	data := s.Statements[start:end]
	if data == nil {
		data = []bomhort.VEXStatement{}
	}
	writeJSON(w, 200, bomhort.Paginated[bomhort.VEXStatement]{Data: data, Total: uint64(len(s.Statements)), Page: uint64(page), PageSize: uint64(size)})
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	name := r.Header.Get("X-Filename")
	if name == "" {
		writeJSON(w, 400, map[string]string{"error": "X-Filename header is required"})
		return
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) == 0 {
		writeJSON(w, 400, map[string]string{"error": "empty body"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Uploads = append(s.Uploads, Upload{Filename: name, Body: body})
	if s.ApplyUploads {
		s.apply(body, name)
	}
	writeJSON(w, http.StatusAccepted, bomhort.UploadResult{Status: "pending", JobID: "job-" + strconv.Itoa(len(s.Uploads)), SHA256Hash: "fake", JobType: "vex"})
}

// apply mimics BOMHort's VEX ingestion: statements are stored and matched
// on exact (vuln_id, purl) equality.
func (s *Server) apply(body []byte, name string) {
	var doc struct {
		ID         string `json:"@id"`
		Timestamp  string `json:"timestamp"`
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Products []struct {
				ID          string `json:"@id"`
				Identifiers struct {
					PURL string `json:"purl"`
				} `json:"identifiers"`
			} `json:"products"`
			Status          string `json:"status"`
			Justification   string `json:"justification"`
			ImpactStatement string `json:"impact_statement"`
			ActionStatement string `json:"action_statement"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return
	}
	for _, st := range doc.Statements {
		for _, p := range st.Products {
			purl := p.Identifiers.PURL
			if purl == "" {
				purl = p.ID
			}
			s.Statements = append(s.Statements, bomhort.VEXStatement{DocumentID: doc.ID, SourceFile: name, ProductPURL: purl, VulnID: st.Vulnerability.Name, Status: st.Status, Justification: st.Justification, ImpactStatement: st.ImpactStatement, ActionStatement: st.ActionStatement, VEXTimestamp: doc.Timestamp})
			for id, vs := range s.Vulns {
				for i := range vs {
					if vs[i].VulnID == st.Vulnerability.Name && vs[i].PURL == purl {
						vs[i].VEXStatus = st.Status
					}
				}
				s.Vulns[id] = vs
			}
		}
	}
}
