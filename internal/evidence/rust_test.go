package evidence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/seebom-labs/vexviper/internal/osv"
	"github.com/seebom-labs/vexviper/internal/source"
)

const rustsecOSV = `{"id":"RUSTSEC-2021-0003","summary":"Buffer overflow in SmallVec::insert_many","modified":"2021-01-08T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"smallvec"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.6.3"},{"fixed":"0.6.14"},{"introduced":"1.0.0"},{"fixed":"1.6.1"}]}],"ecosystem_specific":{"affects":{"arch":[],"os":[],"functions":["smallvec::SmallVec::insert_many"]}}}]}`

func rustRepo(main string) map[string]string {
	return map[string]string{
		"Cargo.toml":        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nsmallvec = \"1\"\nserde = \"1\"\n",
		"Cargo.lock":        "[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n \"smallvec\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\nsource = \"registry+x\"\n",
		"src/main.rs":       main,
		"tests/overflow.rs": "use smallvec::SmallVec;\nfn t() { let mut v: SmallVec<[u8; 4]> = SmallVec::new(); v.insert_many(0, [1u8]); }\n",
	}
}

func osvServer(t *testing.T, body string) *osv.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return osv.New(srv.URL, nil)
}

func TestRustSymbolEvidence(t *testing.T) {
	f := source.Finding{VulnID: "RUSTSEC-2021-0003", PURL: "pkg:cargo/smallvec@1.6.0", FixedVersion: "1.6.1", PackageName: "smallvec"}

	t.Run("vulnerable function referenced", func(t *testing.T) {
		dir := writeTree(t, rustRepo("use smallvec::SmallVec;\nfn main() { let mut v: SmallVec<[u8; 4]> = SmallVec::new(); v.insert_many(0, [1u8]); }\n"))
		c := &Collector{OSV: osvServer(t, rustsecOSV)}
		rep := c.Collect(context.Background(), f, dir, nil)
		if !rep.Has(KindSymbolReferenced) || rep.Has(KindSymbolNotReferenced) {
			t.Fatalf("kinds = %v", kindsOf(rep.Items))
		}
		if len(rep.StrongItems()) != 0 {
			t.Fatalf("strong = %+v", rep.StrongItems())
		}
	})
	t.Run("crate used, function not referenced, sole consumer → strong", func(t *testing.T) {
		dir := writeTree(t, rustRepo("use smallvec::SmallVec;\nfn main() { let v: SmallVec<[u8; 4]> = SmallVec::new(); let _ = v.len(); }\n"))
		c := &Collector{OSV: osvServer(t, rustsecOSV)}
		rep := c.Collect(context.Background(), f, dir, nil)
		if got := strongKinds(rep.Items); !reflect.DeepEqual(got, []string{string(KindSymbolNotReferenced)}) {
			t.Fatalf("strong = %v, all = %v", got, kindsOf(rep.Items))
		}
		if !rep.Has(KindPackageImported) || !rep.Has(KindDependencyPath) || !rep.Has(KindNoReachabilityTool) {
			t.Fatalf("kinds = %v", kindsOf(rep.Items))
		}
	})
	t.Run("another crate depends on it → not strong", func(t *testing.T) {
		files := rustRepo("use smallvec::SmallVec;\nfn main() { let v: SmallVec<[u8; 4]> = SmallVec::new(); let _ = v.len(); }\n")
		files["Cargo.lock"] = "[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n \"smallvec\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+x\"\ndependencies = [\n \"smallvec\",\n]\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\nsource = \"registry+x\"\n"
		dir := writeTree(t, files)
		c := &Collector{OSV: osvServer(t, rustsecOSV)}
		rep := c.Collect(context.Background(), f, dir, nil)
		if !rep.Has(KindSymbolNotReferenced) || len(rep.StrongItems()) != 0 {
			t.Fatalf("kinds = %v strong = %+v", kindsOf(rep.Items), rep.StrongItems())
		}
	})
	t.Run("BOMHort marks it transitive → not strong", func(t *testing.T) {
		dir := writeTree(t, rustRepo("use smallvec::SmallVec;\nfn main() { let v: SmallVec<[u8; 4]> = SmallVec::new(); let _ = v.len(); }\n"))
		c := &Collector{OSV: osvServer(t, rustsecOSV)}
		ft := f
		ft.DirectKnown, ft.Direct = true, false
		rep := c.Collect(context.Background(), ft, dir, nil)
		if len(rep.StrongItems()) != 0 {
			t.Fatalf("strong = %+v", rep.StrongItems())
		}
	})
	t.Run("crate not used at all → import_not_found strong, no symbol item", func(t *testing.T) {
		dir := writeTree(t, rustRepo("fn main() {}\n"))
		c := &Collector{OSV: osvServer(t, rustsecOSV)}
		rep := c.Collect(context.Background(), f, dir, nil)
		if rep.Has(KindSymbolNotReferenced) || rep.Has(KindSymbolReferenced) {
			t.Fatalf("kinds = %v", kindsOf(rep.Items))
		}
		if got := strongKinds(rep.Items); !reflect.DeepEqual(got, []string{string(KindImportNotFound)}) {
			t.Fatalf("strong = %v, all = %v", got, kindsOf(rep.Items))
		}
	})
	t.Run("renamed crate disables strong", func(t *testing.T) {
		files := rustRepo("use sv::SmallVec;\nfn main() { let v: SmallVec<[u8; 4]> = SmallVec::new(); }\n")
		files["Cargo.toml"] = "[package]\nname = \"demo\"\n\n[dependencies]\nsv = { package = \"smallvec\", version = \"1\" }\nserde = \"1\"\n"
		dir := writeTree(t, files)
		c := &Collector{OSV: osvServer(t, rustsecOSV)}
		rep := c.Collect(context.Background(), f, dir, nil)
		if len(rep.StrongItems()) != 0 {
			t.Fatalf("strong = %+v", rep.StrongItems())
		}
	})
	t.Run("advisory without functions → no symbol evidence", func(t *testing.T) {
		dir := writeTree(t, rustRepo("use smallvec::SmallVec;\n"))
		c := &Collector{OSV: osvServer(t, `{"id":"RUSTSEC-2021-0003","affected":[{"package":{"name":"smallvec"}}]}`)}
		rep := c.Collect(context.Background(), f, dir, nil)
		if rep.Has(KindSymbolNotReferenced) || rep.Has(KindSymbolReferenced) {
			t.Fatalf("kinds = %v", kindsOf(rep.Items))
		}
	})
}
