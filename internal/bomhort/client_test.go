package bomhort

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeServer imitates the subset of the BOMHort API gateway VEXViper uses.
func fakeServer(t *testing.T, apiKey string) (*httptest.Server, *atomic.Int32, *atomic.Pointer[string]) {
	t.Helper()
	var uploads atomic.Int32
	var lastUploadScope atomic.Pointer[string]
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if apiKey != "" && r.Header.Get("X-API-Key") != apiKey {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"status":"ok"}`) })
	mux.HandleFunc("GET /api/v1/sboms", auth(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		resp := Paginated[SBOM]{Total: 2, PageSize: 1}
		switch page {
		case "", "1":
			resp.Page = 1
			resp.Data = []SBOM{{ID: "11111111-1111-1111-1111-111111111111", DocumentName: "bomhort", SourceFile: "bomhort-0.6.1.spdx.json", VulnCount: 2}}
		case "2":
			resp.Page = 2
			resp.Data = []SBOM{{ID: "22222222-2222-2222-2222-222222222222", DocumentName: "other", SourceFile: "other.cdx.json"}}
		default:
			resp.Data = nil
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	mux.HandleFunc("GET /api/v1/sboms/{id}/vulnerabilities", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "11111111-1111-1111-1111-111111111111" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"SBOM not found"}`)
			return
		}
		_ = json.NewEncoder(w).Encode([]Vulnerability{
			{VulnID: "GHSA-xyz", Severity: "HIGH", PURL: "pkg:golang/golang.org/x/net@v0.17.0", FixedVersion: "v0.23.0"},
			{VulnID: "GO-2025-0001", Severity: "MEDIUM", PURL: "pkg:golang/github.com/foo/bar@v1.0.0", VEXStatus: "not_affected"},
		})
	}))
	mux.HandleFunc("GET /api/v1/sboms/{id}/dependencies", auth(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]DependencyNode{
			{Index: 0, Name: "bomhort", PURL: "pkg:golang/github.com/seebom-labs/bomhort@v0.6.1", Children: []uint32{1}},
			{Index: 1, Name: "golang.org/x/net", PURL: "pkg:golang/golang.org/x/net@v0.17.0"},
		})
	}))
	mux.HandleFunc("GET /api/v1/sboms/{id}/download", auth(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Disposition", "attachment")
		_, _ = io.WriteString(w, `{"spdxVersion":"SPDX-2.3"}`)
	}))
	mux.HandleFunc("GET /api/v1/vex/statements", auth(func(w http.ResponseWriter, r *http.Request) {
		// Two statements across two pages regardless of page_size, to exercise AllVEXStatements.
		switch r.URL.Query().Get("page") {
		case "", "1":
			_ = json.NewEncoder(w).Encode(Paginated[VEXStatement]{Total: 2, Page: 1, Data: []VEXStatement{{VulnID: "GHSA-xyz", ProductPURL: "pkg:golang/golang.org/x/net@v0.17.0", Status: "not_affected"}}})
		default:
			_ = json.NewEncoder(w).Encode(Paginated[VEXStatement]{Total: 2, Page: 2, Data: []VEXStatement{{VulnID: "GHSA-abc", ProductPURL: "pkg:npm/x@1", Status: "affected"}}})
		}
	}))
	mux.HandleFunc("POST /api/v1/sboms/upload", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Filename") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"X-Filename header is required"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		uploads.Add(1)
		scope := r.URL.Query().Get("sbom_id")
		lastUploadScope.Store(&scope)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(UploadResult{Status: "pending", JobID: "job-1", SHA256Hash: "abc", JobType: "vex"})
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &uploads, &lastUploadScope
}

func TestClientHappyPath(t *testing.T) {
	srv, uploads, lastUploadScope := fakeServer(t, "k3y")
	c := New(srv.URL+"/", WithAPIKey("k3y"))
	ctx := context.Background()

	if err := c.Healthy(ctx); err != nil {
		t.Fatalf("Healthy: %v", err)
	}
	all, err := c.AllSBOMs(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("AllSBOMs = %v, %v", all, err)
	}
	s, err := c.FindSBOM(ctx, "bomhort-0.6.1.spdx.json")
	if err != nil || s.DocumentName != "bomhort" {
		t.Fatalf("FindSBOM = %+v, %v", s, err)
	}
	vulns, err := c.Vulnerabilities(ctx, s.ID)
	if err != nil || len(vulns) != 2 || vulns[1].VEXStatus != "not_affected" {
		t.Fatalf("Vulnerabilities = %+v, %v", vulns, err)
	}
	deps, err := c.Dependencies(ctx, s.ID)
	if err != nil || len(deps) != 2 || deps[0].Children[0] != 1 {
		t.Fatalf("Dependencies = %+v, %v", deps, err)
	}
	raw, err := c.DownloadSBOM(ctx, s.ID)
	if err != nil || string(raw) != `{"spdxVersion":"SPDX-2.3"}` {
		t.Fatalf("DownloadSBOM = %s, %v", raw, err)
	}
	st, err := c.VEXStatements(ctx, 1, 50)
	if err != nil || st.Total != 2 || len(st.Data) != 1 {
		t.Fatalf("VEXStatements = %+v, %v", st, err)
	}
	allSt, err := c.AllVEXStatements(ctx)
	if err != nil || len(allSt) != 2 || allSt[1].VulnID != "GHSA-abc" {
		t.Fatalf("AllVEXStatements = %+v, %v", allSt, err)
	}
	res, err := c.UploadVEX(ctx, "bomhort.openvex.json", []byte(`{"@context":"https://openvex.dev/ns/v0.2.0"}`), "sbom-1")
	if err != nil || res.Status != "pending" || res.JobType != "vex" {
		t.Fatalf("UploadVEX = %+v, %v", res, err)
	}
	if got := lastUploadScope.Load(); got == nil || *got != "sbom-1" {
		t.Fatalf("upload sbom_id scope = %v", got)
	}
	if uploads.Load() != 1 {
		t.Fatalf("uploads = %d", uploads.Load())
	}
}

func TestClientErrors(t *testing.T) {
	srv, _, _ := fakeServer(t, "k3y")
	ctx := context.Background()

	unauth := New(srv.URL)
	_, err := unauth.AllSBOMs(ctx)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized || apiErr.Message != "unauthorized" {
		t.Fatalf("expected 401 APIError, got %v", err)
	}

	c := New(srv.URL, WithAPIKey("k3y"))
	_, err = c.Vulnerabilities(ctx, "nope")
	if !IsNotFound(err) {
		t.Fatalf("expected not found, got %v", err)
	}
	if _, err := c.FindSBOM(ctx, "missing"); err == nil {
		t.Fatal("expected FindSBOM error")
	}
	if _, err := c.UploadVEX(ctx, "doc.txt", []byte("x"), ""); err == nil {
		t.Fatal("expected filename validation error")
	}
}

func TestClientRetriesOn429(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"rate limited"}`)
			return
		}
		_ = json.NewEncoder(w).Encode([]Vulnerability{{VulnID: "X"}})
	}))
	defer srv.Close()

	var slept []time.Duration
	c := New(srv.URL)
	c.sleep = func(d time.Duration) { slept = append(slept, d) }
	vulns, err := c.Vulnerabilities(context.Background(), "id")
	if err != nil || len(vulns) != 1 {
		t.Fatalf("got %v, %v", vulns, err)
	}
	if len(slept) != 2 || slept[0] != 10*time.Second {
		t.Fatalf("slept = %v", slept)
	}

	// exhaust retries
	hits.Store(-100)
	c.maxRetries = 1
	if _, err := c.Vulnerabilities(context.Background(), "id"); err == nil {
		t.Fatal("expected error after retries exhausted")
	}
}

func TestRetryAfterFallback(t *testing.T) {
	if d := retryAfter("", 2); d != 4*time.Second {
		t.Fatalf("exp backoff = %v", d)
	}
	if d := retryAfter("garbage", 0); d != time.Second {
		t.Fatalf("garbage header = %v", d)
	}
}

func TestClientOptionsAndAPIError(t *testing.T) {
	var gotAuth, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hc := &http.Client{Timeout: 5 * time.Second}
	c := New(srv.URL+"/", WithServiceToken("svc-token"), WithHTTPClient(hc), WithMaxRetries(0))
	if c.BaseURL() != srv.URL {
		t.Fatalf("BaseURL = %q (trailing slash must be trimmed)", c.BaseURL())
	}
	if c.http != hc || c.maxRetries != 0 {
		t.Fatalf("options not applied: http=%p retries=%d", c.http, c.maxRetries)
	}
	if err := c.Healthy(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer svc-token" || gotKey != "" {
		t.Fatalf("auth headers = %q / %q", gotAuth, gotKey)
	}

	e := &APIError{StatusCode: 503, Message: "down"}
	if e.Error() != "bomhort: HTTP 503: down" {
		t.Fatalf("Error() = %q", e.Error())
	}
}
