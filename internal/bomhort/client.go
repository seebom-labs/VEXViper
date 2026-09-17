// Package bomhort is a small client for the BOMHort REST API
// (https://docs.bomhort.dev/docs/api-reference/). It covers exactly the
// endpoints VEXViper needs: listing SBOMs, reading their vulnerabilities and
// dependency tree, downloading the raw SBOM, listing VEX statements and
// pushing an OpenVEX document through the upload endpoint.
package bomhort

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DTOs mirror backend/pkg/dto/api.go in BOMHort.

// SBOM is one entry of GET /api/v1/sboms.
type SBOM struct {
	ID           string `json:"sbom_id"`
	SourceFile   string `json:"source_file"`
	SPDXVersion  string `json:"spdx_version"`
	DocumentName string `json:"document_name"`
	PackageCount uint64 `json:"package_count"`
	VulnCount    uint64 `json:"vuln_count"`
	IngestedAt   string `json:"ingested_at"`
	// SourceRepo and SourceRef are the product's source repository and
	// commit/tag as first-class SBOM attributes (BOMHort #332); empty on
	// BOMHort <= 0.6.1 or when unknown.
	SourceRepo string `json:"source_repo,omitempty"`
	SourceRef  string `json:"source_ref,omitempty"`
}

// Paginated wraps list responses.
type Paginated[T any] struct {
	Data     []T    `json:"data"`
	Total    uint64 `json:"total"`
	Page     uint64 `json:"page"`
	PageSize uint64 `json:"page_size"`
}

// Vulnerability is one entry of GET /api/v1/sboms/{id}/vulnerabilities.
type Vulnerability struct {
	VulnID       string `json:"vuln_id"`
	Severity     string `json:"severity"`
	PURL         string `json:"purl"`
	Summary      string `json:"summary"`
	FixedVersion string `json:"fixed_version"`
	SourceFile   string `json:"source_file"`
	DiscoveredAt string `json:"discovered_at"`
	VEXStatus    string `json:"vex_status,omitempty"`
	// Effective VEX statement detail (BOMHort #335): the API returns exactly
	// one row per (vuln_id, purl); the statement with the newest
	// vex_timestamp wins. Empty on BOMHort <= 0.6.1.
	VEXJustification string `json:"vex_justification,omitempty"`
	VEXTimestamp     string `json:"vex_timestamp,omitempty"`
	VEXStatementID   string `json:"vex_statement_id,omitempty"`
	VEXAuthor        string `json:"vex_author,omitempty"`
	VEXTooling       string `json:"vex_tooling,omitempty"`
	// VEXScope is "sbom" when the winning statement is scoped to this SBOM,
	// "global" for unscoped legacy statements (BOMHort #350).
	VEXScope string `json:"vex_scope,omitempty"`
}

// DependencyNode is one entry of GET /api/v1/sboms/{id}/dependencies.
type DependencyNode struct {
	Index    uint32   `json:"index"`
	SPDXID   string   `json:"spdx_id"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl"`
	License  string   `json:"license"`
	Children []uint32 `json:"children"`
}

// VEXStatement is one entry of GET /api/v1/vex/statements.
type VEXStatement struct {
	VEXID      string `json:"vex_id"`
	DocumentID string `json:"document_id"`
	SourceFile string `json:"source_file"`
	// SBOMID scopes the statement to one SBOM (BOMHort #350); empty = global.
	SBOMID          string `json:"sbom_id,omitempty"`
	ProductPURL     string `json:"product_purl"`
	VulnID          string `json:"vuln_id"`
	Status          string `json:"status"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	VEXTimestamp    string `json:"vex_timestamp"`
	IngestedAt      string `json:"ingested_at"`
	// Provenance (BOMHort #334); empty when the source document has none.
	Author      string `json:"author,omitempty"`
	Role        string `json:"role,omitempty"`
	Tooling     string `json:"tooling,omitempty"`
	StatusNotes string `json:"status_notes,omitempty"`
}

// UploadResult is the response of POST /api/v1/sboms/upload.
type UploadResult struct {
	Status     string `json:"status"` // "pending" or "duplicate"
	JobID      string `json:"job_id,omitempty"`
	SHA256Hash string `json:"sha256_hash"`
	JobType    string `json:"job_type,omitempty"`
	Cluster    string `json:"cluster,omitempty"`
}

// APIError is returned for non-2xx responses.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("bomhort: HTTP %d: %s", e.StatusCode, e.Message)
}

// Client talks to one BOMHort API gateway.
type Client struct {
	baseURL      string
	apiKey       string
	serviceToken string
	http         *http.Client
	// maxRetries bounds retries on 429 responses.
	maxRetries int
	sleep      func(time.Duration)
	limiter    *RateLimiter
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey authenticates with X-API-Key.
func WithAPIKey(k string) Option { return func(c *Client) { c.apiKey = k } }

// WithServiceToken authenticates with a bearer token.
func WithServiceToken(t string) Option { return func(c *Client) { c.serviceToken = t } }

// WithHTTPClient replaces the underlying HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithRateLimit paces requests to at most limit per window (0 = off).
func WithRateLimit(limit int, window time.Duration) Option {
	return func(c *Client) { c.limiter = NewRateLimiter(limit, window) }
}

// WithMaxRetries bounds 429 retries (default 3).
func WithMaxRetries(n int) Option { return func(c *Client) { c.maxRetries = n } }

// New creates a client for baseURL (e.g. http://localhost:8080).
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		http:       &http.Client{Timeout: 60 * time.Second},
		maxRetries: 3,
		sleep:      time.Sleep,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// Healthy calls /healthz.
func (c *Client) Healthy(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/healthz", nil, nil)
	return err
}

// ListSBOMs returns one page of SBOMs. search may be empty.
func (c *Client) ListSBOMs(ctx context.Context, page, pageSize int, search string) (Paginated[SBOM], error) {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Set("page_size", strconv.Itoa(pageSize))
	}
	if search != "" {
		q.Set("search", search)
	}
	var out Paginated[SBOM]
	_, err := c.do(ctx, http.MethodGet, "/api/v1/sboms?"+q.Encode(), nil, &out)
	return out, err
}

// AllSBOMs walks all pages.
func (c *Client) AllSBOMs(ctx context.Context) ([]SBOM, error) {
	var all []SBOM
	for page := 1; ; page++ {
		p, err := c.ListSBOMs(ctx, page, 100, "")
		if err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		if len(p.Data) == 0 || uint64(len(all)) >= p.Total {
			return all, nil
		}
	}
}

// FindSBOM returns the SBOM whose ID, document name or source file equals ref.
func (c *Client) FindSBOM(ctx context.Context, ref string) (SBOM, error) {
	sboms, err := c.AllSBOMs(ctx)
	if err != nil {
		return SBOM{}, err
	}
	for _, s := range sboms {
		if s.ID == ref || s.DocumentName == ref || s.SourceFile == ref {
			return s, nil
		}
	}
	return SBOM{}, fmt.Errorf("bomhort: no SBOM matches %q", ref)
}

// Vulnerabilities returns all findings of an SBOM (the endpoint is not paginated).
func (c *Client) Vulnerabilities(ctx context.Context, sbomID string) ([]Vulnerability, error) {
	var out []Vulnerability
	_, err := c.do(ctx, http.MethodGet, "/api/v1/sboms/"+url.PathEscape(sbomID)+"/vulnerabilities", nil, &out)
	return out, err
}

// Dependencies returns the flat dependency node list of an SBOM.
func (c *Client) Dependencies(ctx context.Context, sbomID string) ([]DependencyNode, error) {
	var out []DependencyNode
	_, err := c.do(ctx, http.MethodGet, "/api/v1/sboms/"+url.PathEscape(sbomID)+"/dependencies", nil, &out)
	return out, err
}

// DownloadSBOM returns the raw original SBOM bytes.
func (c *Client) DownloadSBOM(ctx context.Context, sbomID string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, "/api/v1/sboms/"+url.PathEscape(sbomID)+"/download", nil, nil)
}

// VEXStatements returns one page of ingested VEX statements.
func (c *Client) VEXStatements(ctx context.Context, page, pageSize int) (Paginated[VEXStatement], error) {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Set("page_size", strconv.Itoa(pageSize))
	}
	var out Paginated[VEXStatement]
	_, err := c.do(ctx, http.MethodGet, "/api/v1/vex/statements?"+q.Encode(), nil, &out)
	return out, err
}

// AllVEXStatements walks all pages of /api/v1/vex/statements.
func (c *Client) AllVEXStatements(ctx context.Context) ([]VEXStatement, error) {
	var all []VEXStatement
	for page := 1; ; page++ {
		p, err := c.VEXStatements(ctx, page, 100)
		if err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		if len(p.Data) == 0 || uint64(len(all)) >= p.Total {
			return all, nil
		}
	}
}

// UploadVEX pushes an OpenVEX document. filename must end in .openvex.json
// (or .vex.json) so BOMHort classifies the job as VEX. A non-empty sbomID
// scopes every statement in the document to that SBOM (BOMHort #350,
// ?sbom_id=); "" leaves the mapping to BOMHort's product-@id resolution
// (global fallback on <= 0.6.1, which ignores the parameter).
func (c *Client) UploadVEX(ctx context.Context, filename string, doc []byte, sbomID string) (UploadResult, error) {
	if !strings.HasSuffix(filename, ".openvex.json") && !strings.HasSuffix(filename, ".vex.json") {
		return UploadResult{}, fmt.Errorf("bomhort: filename %q must end in .openvex.json or .vex.json", filename)
	}
	path := "/api/v1/sboms/upload"
	if sbomID != "" {
		path += "?sbom_id=" + url.QueryEscape(sbomID)
	}
	var out UploadResult
	_, err := c.do(ctx, http.MethodPost, path, &request{body: doc, headers: map[string]string{
		"Content-Type": "application/json",
		"X-Filename":   filename,
	}}, &out)
	return out, err
}

type request struct {
	body    []byte
	headers map[string]string
}

func (c *Client) do(ctx context.Context, method, path string, req *request, out any) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		var body io.Reader
		if req != nil && req.body != nil {
			body = bytes.NewReader(req.body)
		}
		httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Accept", "application/json")
		httpReq.Header.Set("User-Agent", "vexviper")
		if c.apiKey != "" {
			httpReq.Header.Set("X-API-Key", c.apiKey)
		}
		if c.serviceToken != "" {
			httpReq.Header.Set("Authorization", "Bearer "+c.serviceToken)
		}
		if req != nil {
			for k, v := range req.headers {
				httpReq.Header.Set(k, v)
			}
		}

		resp, err := c.http.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("bomhort: %s %s: %w", method, path, err)
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("bomhort: read response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = decodeError(resp.StatusCode, data)
			if attempt == c.maxRetries {
				break
			}
			c.sleep(retryAfter(resp.Header.Get("Retry-After"), attempt))
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, decodeError(resp.StatusCode, data)
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				return nil, fmt.Errorf("bomhort: decode %s: %w", path, err)
			}
		}
		return data, nil
	}
	return nil, lastErr
}

func decodeError(status int, data []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(data))
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return &APIError{StatusCode: status, Message: msg}
}

func retryAfter(header string, attempt int) time.Duration {
	if s, err := strconv.Atoi(header); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	return time.Duration(1<<attempt) * time.Second
}

// IsNotFound reports whether err is a 404 from BOMHort.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound
}
