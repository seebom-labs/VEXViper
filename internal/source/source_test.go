package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seebom-labs/vexviper/internal/bomhort"
)

type fakeAPI struct {
	sbom    bomhort.SBOM
	vulns   []bomhort.Vulnerability
	deps    []bomhort.DependencyNode
	depsErr error
	raw     []byte
	rawErr  error
}

func (f *fakeAPI) FindSBOM(_ context.Context, ref string) (bomhort.SBOM, error) {
	if ref != f.sbom.ID && ref != f.sbom.DocumentName {
		return bomhort.SBOM{}, errors.New("not found")
	}
	return f.sbom, nil
}
func (f *fakeAPI) Vulnerabilities(context.Context, string) ([]bomhort.Vulnerability, error) {
	return f.vulns, nil
}
func (f *fakeAPI) Dependencies(context.Context, string) ([]bomhort.DependencyNode, error) {
	return f.deps, f.depsErr
}
func (f *fakeAPI) DownloadSBOM(context.Context, string) ([]byte, error) { return f.raw, f.rawErr }

func TestLoadWithTreeAndSBOM(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bomhort-0.6.1.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{
		sbom: bomhort.SBOM{ID: "id-1", DocumentName: "bomhort", SourceFile: "bomhort-0.6.1.spdx.json", SourceRepo: "https://github.com/seebom-labs/bomhort", SourceRef: "v0.6.1"},
		vulns: []bomhort.Vulnerability{
			{VulnID: "GO-2023-2102", PURL: "pkg:golang/golang.org/x/net@v0.56.0", Severity: "HIGH", FixedVersion: "v0.17.0"},
			{VulnID: "GHSA-1", PURL: "pkg:golang/github.com/klauspost/compress@v1.18.6", VEXStatus: "not_affected"},
			{VulnID: "", PURL: "pkg:npm/x@1"},
		},
		deps: []bomhort.DependencyNode{
			{Index: 0, Name: "root", PURL: "", Children: []uint32{1}},
			{Index: 1, Name: "golang.org/x/net", Version: "v0.56.0", PURL: "pkg:golang/golang.org/x/net@v0.56.0", Children: []uint32{2}},
			{Index: 2, Name: "github.com/klauspost/compress", Version: "v1.18.6", PURL: "pkg:golang/github.com/klauspost/compress@v1.18.6"},
		},
		raw: raw,
	}
	res, err := Load(context.Background(), api, "bomhort")
	if err != nil {
		t.Fatal(err)
	}
	if res.Product.SBOMID != "id-1" || len(res.Product.RepoHints) == 0 || res.Product.RepoHints[0] != "https://github.com/seebom-labs/bomhort" {
		t.Fatalf("product = %+v", res.Product)
	}
	if res.Product.SourceRepo != "https://github.com/seebom-labs/bomhort" || res.Product.SourceRef != "v0.6.1" {
		t.Fatalf("source_repo/source_ref not propagated: %+v", res.Product)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d (empty vuln id should be dropped)", len(res.Findings))
	}
	xnet := res.Findings[0]
	if !xnet.Direct || !xnet.DirectKnown || xnet.PackageName != "golang.org/x/net" || xnet.PackageVersion != "v0.56.0" {
		t.Errorf("x/net = %+v", xnet)
	}
	if comp := res.Findings[1]; comp.Direct || comp.VEXStatus != "not_affected" {
		t.Errorf("compress = %+v", comp)
	}
}

func TestLoadDegradesGracefully(t *testing.T) {
	api := &fakeAPI{
		sbom:    bomhort.SBOM{ID: "id-2"},
		vulns:   []bomhort.Vulnerability{{VulnID: "CVE-1", PURL: "pkg:npm/a@1"}},
		depsErr: errors.New("boom"),
		rawErr:  errors.New("no storage"),
	}
	res, err := Load(context.Background(), api, "id-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].DirectKnown {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(res.Product.RepoHints) != 0 {
		t.Fatalf("hints = %v", res.Product.RepoHints)
	}
}

func TestLoadUnparsableSBOMAndNoEdges(t *testing.T) {
	api := &fakeAPI{
		sbom:  bomhort.SBOM{ID: "id-3"},
		vulns: []bomhort.Vulnerability{{VulnID: "CVE-1", PURL: "pkg:npm/a@1"}},
		deps:  []bomhort.DependencyNode{{Index: 0, PURL: "pkg:npm/a@1"}},
		raw:   []byte("garbage"),
	}
	res, err := Load(context.Background(), api, "id-3")
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings[0].DirectKnown {
		t.Fatal("no edges → DirectKnown must be false")
	}
}

func TestLoadNotFound(t *testing.T) {
	if _, err := Load(context.Background(), &fakeAPI{sbom: bomhort.SBOM{ID: "x"}}, "y"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadDeduplicatesFindings(t *testing.T) {
	api := &fakeAPI{
		sbom: bomhort.SBOM{ID: "id-3"},
		vulns: []bomhort.Vulnerability{
			{VulnID: "GHSA-1", PURL: "pkg:npm/a@1", SourceFile: "x.spdx.json"},
			{VulnID: "GHSA-1", PURL: "pkg:npm/a@1", SourceFile: "y.openvex.json", VEXStatus: "affected", VEXTimestamp: "2026-01-01T00:00:00Z"},
			{VulnID: "GHSA-1", PURL: "pkg:npm/b@1"},
			{VulnID: "GHSA-2", PURL: "pkg:npm/a@1"},
		},
		depsErr: errors.New("boom"),
		rawErr:  errors.New("no storage"),
	}
	res, err := Load(context.Background(), api, "id-3")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("expected 3 unique findings, got %d: %+v", len(res.Findings), res.Findings)
	}
	if res.Findings[0].VulnID != "GHSA-1" || res.Findings[0].PURL != "pkg:npm/a@1" || res.Findings[0].VEXStatus != "affected" {
		t.Fatalf("duplicate should keep vex_status: %+v", res.Findings[0])
	}
	if res.Findings[0].VEXTimestamp != "2026-01-01T00:00:00Z" {
		t.Fatalf("duplicate should carry the status row's vex_timestamp: %+v", res.Findings[0])
	}
}
