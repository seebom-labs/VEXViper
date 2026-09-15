// Command vexviper generates OpenVEX documents for SBOMs stored in BOMHort.
//
// Subcommands:
//
//	generate   one-shot: assess one SBOM and write/upload an OpenVEX document
//	watch      poll BOMHort and generate for new/changed SBOMs
//	mcp-serve  run VEXViper as an MCP server (stdio or streamable HTTP)
//	version    print the version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/config"
	"github.com/mfahlandt/vexviper/internal/mcpserver"
	"github.com/mfahlandt/vexviper/internal/pipeline"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `vexviper %s — LLM-assisted OpenVEX generation for BOMHort

Usage:
  vexviper generate  [flags]   assess one SBOM and write/upload an OpenVEX document
  vexviper watch     [flags]   poll BOMHort and generate for new/changed SBOMs
  vexviper mcp-serve [flags]   expose VEXViper as an MCP server
  vexviper version             print version

Run "vexviper <command> -h" for flags. Configuration: --config vexviper.yaml,
overridable with VEXVIPER_* environment variables (see examples/vexviper.yaml).
`, version)
}

func run(args []string, stdout, stderr io.Writer) int {
	pipeline.Version = version
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "generate":
		err = cmdGenerate(ctx, args[1:], stdout, stderr)
	case "watch":
		err = cmdWatch(ctx, args[1:], stderr)
	case "mcp-serve":
		err = cmdMCPServe(ctx, args[1:], stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "vexviper", version)
	case "help", "-h", "--help":
		usage(stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// commonFlags are shared by all subcommands.
type commonFlags struct {
	config   string
	logLevel string
	logJSON  bool
	bomhort  string
	provider string
}

func (c *commonFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.config, "config", envOr("VEXVIPER_CONFIG", ""), "path to vexviper.yaml")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug|info|warn|error")
	fs.BoolVar(&c.logJSON, "log-json", false, "emit JSON logs")
	fs.StringVar(&c.bomhort, "bomhort", "", "BOMHort base URL (overrides config)")
	fs.StringVar(&c.provider, "provider", "", "assessment provider: heuristic|openai|github|copilot|mcptool (overrides config)")
}

func (c *commonFlags) load(stderr io.Writer) (config.Config, *slog.Logger, error) {
	log := newLogger(stderr, c.logLevel, c.logJSON)
	slog.SetDefault(log)
	cfg, err := config.Load(c.config)
	if err != nil {
		return cfg, log, err
	}
	if c.bomhort != "" {
		cfg.BOMHort.URL = c.bomhort
	}
	if c.provider != "" {
		cfg.LLM.Provider = c.provider
	}
	if err := cfg.Validate(); err != nil {
		return cfg, log, err
	}
	return cfg, log, nil
}

func newLogger(w io.Writer, level string, asJSON bool) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if asJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

func cmdGenerate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.bind(fs)
	sbom := fs.String("sbom", "", "SBOM id, document name or source file in BOMHort (required)")
	repoURL := fs.String("repo", "", "product source repository (URL or owner/name[@ref]); overrides resolution from the SBOM")
	out := fs.String("out", "", "output directory for <name>.vexviper.openvex.json (default from config; \"-\" disables the file)")
	toStdout := fs.Bool("stdout", false, "also print the document to stdout")
	upload := fs.Bool("upload", false, "upload the document to BOMHort (needs api key)")
	regenerate := fs.Bool("regenerate", false, "also re-assess findings that already carry a vex_status, except settled ones (not_affected, fixed)")
	force := fs.Bool("force", false, "hard regenerate: re-assess every finding, including not_affected/fixed (implies --regenerate)")
	noCache := fs.Bool("no-cache", false, "do not reuse cached assessments (results are still written to the cache)")
	only := fs.String("only", "", "comma-separated vuln IDs to restrict to")
	wait := fs.Duration("wait", 0, "after --upload, wait up to this long for BOMHort to ingest the document")
	reassess := fs.Duration("reassess-after", -1, "re-assess under_investigation/affected findings whose statement is older than this (default from config watch.reassess_after; 0 disables)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sbom == "" {
		fs.Usage()
		return errors.New("--sbom is required")
	}
	cfg, log, err := cf.load(stderr)
	if err != nil {
		return err
	}
	p, err := pipeline.New(cfg, log)
	if err != nil {
		return err
	}
	outDir := cfg.VEX.OutDir
	if *out != "" {
		outDir = *out
	}
	if outDir == "-" {
		outDir = ""
	}
	opts := pipeline.RunOptions{
		SBOMRef:       *sbom,
		RepoOverride:  *repoURL,
		ReassessAfter: cfg.Watch.ReassessAfter,
		OutDir:        outDir,
		Upload:        *upload || cfg.VEX.Upload,
		Regenerate:    *regenerate || *force || cfg.VEX.Regenerate,
		Force:         *force,
		NoCache:       *noCache,
	}
	if *only != "" {
		opts.Only = strings.Split(*only, ",")
	}
	if *reassess >= 0 {
		opts.ReassessAfter = *reassess
	}
	res, err := p.Run(ctx, opts)
	if err != nil {
		return err
	}
	if *toStdout {
		fmt.Fprintln(stdout, string(res.Document))
	}
	printSummary(stderr, res)
	if *wait > 0 && res.Upload != nil {
		client := p.BOMHort.(*bomhort.Client)
		docID := documentID(res.Document)
		log.Info("waiting for BOMHort to ingest the document", "document", docID, "timeout", *wait)
		return p.Wait(ctx, docID, *wait, func(ctx context.Context) ([]bomhort.VEXStatement, error) {
			var all []bomhort.VEXStatement
			for page := 1; ; page++ {
				pg, err := client.VEXStatements(ctx, page, 100)
				if err != nil {
					return nil, err
				}
				all = append(all, pg.Data...)
				if len(pg.Data) < 100 {
					return all, nil
				}
			}
		})
	}
	return nil
}

func printSummary(w io.Writer, res *pipeline.Outcome) {
	fmt.Fprintf(w, "\nVEXViper summary for SBOM %s (%s)\n", res.Product.SBOMID, res.Product.DocumentName)
	fmt.Fprintf(w, "  findings assessed: %d (skipped: %d, re-assessed: %d)\n", res.Findings, res.Skipped, res.Reassessed)
	if res.Settled > 0 {
		fmt.Fprintf(w, "  settled verdicts kept: %d (not_affected/fixed; use --force to re-assess)\n", res.Settled)
	}
	fmt.Fprintf(w, "  provider usage:    %s\n", res.Usage.String())
	if res.RepoHow != "" {
		fmt.Fprintf(w, "  product repo:      %s", res.RepoHow)
		if res.RepoDir != "" {
			fmt.Fprintf(w, " → %s", res.RepoDir)
		}
		fmt.Fprintln(w)
	}
	for _, a := range res.Assessments {
		fmt.Fprintf(w, "  %-22s %-60s %s\n", a.VulnID, truncate(a.PURL, 60), a.Status)
	}
	if len(res.Guardrails) > 0 {
		fmt.Fprintf(w, "  guardrails applied: %d\n", len(res.Guardrails))
	}
	if res.Path != "" {
		fmt.Fprintf(w, "  written:           %s\n", res.Path)
	}
	if res.Upload != nil {
		fmt.Fprintf(w, "  uploaded:          status=%s job=%s sha256=%s\n", res.Upload.Status, res.Upload.JobID, res.Upload.SHA256Hash)
	}
}

func cmdWatch(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.bind(fs)
	interval := fs.Duration("interval", 0, "poll interval (default from config)")
	state := fs.String("state", "", "state file path (default from config)")
	out := fs.String("out", "", "output directory (default from config)")
	upload := fs.Bool("upload", false, "upload generated documents to BOMHort")
	once := fs.Bool("once", false, "run a single pass and exit (for CronJobs)")
	skipZero := fs.Bool("skip-zero", true, "ignore SBOMs without vulnerabilities")
	reassess := fs.Duration("reassess-after", -1, "re-run SBOMs and re-assess under_investigation/affected findings older than this (default from config watch.reassess_after; 0 disables)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, log, err := cf.load(stderr)
	if err != nil {
		return err
	}
	p, err := pipeline.New(cfg, log)
	if err != nil {
		return err
	}
	opts := pipeline.WatchOptions{
		Interval:      cfg.Watch.Interval,
		StateFile:     cfg.Watch.StateFile,
		OutDir:        cfg.VEX.OutDir,
		Upload:        *upload || cfg.VEX.Upload,
		Once:          *once,
		SkipZero:      *skipZero,
		ReassessAfter: cfg.Watch.ReassessAfter,
	}
	if *reassess >= 0 {
		opts.ReassessAfter = *reassess
	}
	if *interval > 0 {
		opts.Interval = *interval
	}
	if *state != "" {
		opts.StateFile = *state
	}
	if *out != "" {
		opts.OutDir = *out
	}
	log.Info("starting watch", "bomhort", cfg.BOMHort.URL, "interval", opts.Interval, "upload", opts.Upload, "once", opts.Once)
	err = p.Watch(ctx, p.BOMHort.(*bomhort.Client), opts)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func cmdMCPServe(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("mcp-serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf commonFlags
	cf.bind(fs)
	transport := fs.String("transport", "stdio", "stdio|http")
	addr := fs.String("addr", "127.0.0.1:8765", "listen address for --transport http")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, log, err := cf.load(stderr)
	if err != nil {
		return err
	}
	p, err := pipeline.New(cfg, log)
	if err != nil {
		return err
	}
	srv := &mcpserver.Server{Pipeline: p, Lister: p.BOMHort.(*bomhort.Client), Log: log, Version: version}
	switch *transport {
	case "stdio":
		log.Info("serving MCP over stdio", "bomhort", cfg.BOMHort.URL, "provider", cfg.LLM.Provider)
		return srv.New().Run(ctx, &mcp.StdioTransport{})
	case "http":
		hs := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = hs.Shutdown(shutdownCtx)
		}()
		log.Info("serving MCP over streamable HTTP", "addr", *addr, "bomhort", cfg.BOMHort.URL, "provider", cfg.LLM.Provider)
		if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown transport %q (stdio|http)", *transport)
	}
}

func documentID(doc []byte) string {
	// cheap extraction without a full decode
	const key = `"@id":`
	i := strings.Index(string(doc), key)
	if i < 0 {
		return ""
	}
	rest := doc[i+len(key):]
	start := strings.IndexByte(string(rest), '"')
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(string(rest[start+1:]), '"')
	if end < 0 {
		return ""
	}
	return string(rest[start+1 : start+1+end])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
