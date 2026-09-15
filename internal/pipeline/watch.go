package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/mfahlandt/vexviper/internal/bomhort"
	"github.com/mfahlandt/vexviper/internal/llm"
)

// SBOMLister lists SBOMs (bomhort.Client.AllSBOMs).
type SBOMLister interface {
	AllSBOMs(ctx context.Context) ([]bomhort.SBOM, error)
}

// WatchState remembers which SBOM versions were already processed so the
// watcher only reacts to new SBOMs or changed vulnerability counts.
type WatchState struct {
	// Processed maps sbom_id → fingerprint (vuln_count@ingested_at).
	Processed map[string]string `json:"processed"`
	// ProcessedAt maps sbom_id → time of the last successful run.
	ProcessedAt map[string]time.Time `json:"processed_at,omitempty"`
	LastRun     time.Time            `json:"last_run"`
	// Usage accumulates provider cost over the lifetime of the state file
	// (TokenOps: what did automated triage cost so far).
	Usage llm.Usage `json:"usage,omitempty"`
	// LastPassUsage is the cost of the most recent pass.
	LastPassUsage llm.Usage `json:"last_pass_usage,omitempty"`
}

// LoadWatchState reads the state file; a missing file yields an empty state.
func LoadWatchState(path string) (*WatchState, error) {
	st := &WatchState{Processed: map[string]string{}, ProcessedAt: map[string]time.Time{}}
	if path == "" {
		return st, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("parse watch state %s: %w", path, err)
	}
	if st.Processed == nil {
		st.Processed = map[string]string{}
	}
	if st.ProcessedAt == nil {
		st.ProcessedAt = map[string]time.Time{}
	}
	return st, nil
}

// Save persists the state atomically.
func (s *WatchState) Save(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fingerprint(s bomhort.SBOM) string {
	return fmt.Sprintf("%d@%s", s.VulnCount, s.IngestedAt)
}

// WatchOptions configures the polling loop.
type WatchOptions struct {
	Interval  time.Duration
	StateFile string
	OutDir    string
	Upload    bool
	// Once runs a single pass and returns (useful for CronJobs and tests).
	Once bool
	// SkipZero ignores SBOMs without vulnerabilities.
	SkipZero bool
	// ReassessAfter re-runs an SBOM even with an unchanged fingerprint once
	// this much time passed since its last run, and lets Run revisit
	// under_investigation/affected findings whose statements are that old.
	ReassessAfter time.Duration
}

// Watch polls BOMHort and runs the pipeline for every SBOM that is new or
// whose vulnerability count changed since the last pass. It returns when ctx
// is cancelled (or after one pass when Once is set).
func (p *Pipeline) Watch(ctx context.Context, lister SBOMLister, opts WatchOptions) error {
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	if opts.Interval <= 0 {
		opts.Interval = 15 * time.Minute
	}
	state, err := LoadWatchState(opts.StateFile)
	if err != nil {
		return err
	}
	for {
		n, err := p.watchPass(ctx, lister, state, opts)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Error("watch pass failed", "err", err)
		} else {
			log.Info("watch pass complete", "processed", n, "usage", state.LastPassUsage.String(), "usage_total", state.Usage.String())
		}
		state.LastRun = time.Now().UTC()
		if err := state.Save(opts.StateFile); err != nil {
			log.Error("save watch state", "err", err)
		}
		if opts.Once {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(opts.Interval):
		}
	}
}

func (p *Pipeline) watchPass(ctx context.Context, lister SBOMLister, state *WatchState, opts WatchOptions) (int, error) {
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	sboms, err := lister.AllSBOMs(ctx)
	if err != nil {
		return 0, fmt.Errorf("list sboms: %w", err)
	}
	var processed int
	var errs []error
	state.LastPassUsage = llm.Usage{}
	for _, s := range sboms {
		fp := fingerprint(s)
		due := opts.ReassessAfter > 0 && time.Since(state.ProcessedAt[s.ID]) >= opts.ReassessAfter
		if state.Processed[s.ID] == fp && !due {
			continue
		}
		if opts.SkipZero && s.VulnCount == 0 {
			state.Processed[s.ID] = fp
			state.ProcessedAt[s.ID] = time.Now().UTC()
			continue
		}
		log.Info("processing sbom", "sbom", s.ID, "name", s.DocumentName, "vulns", s.VulnCount, "changed", state.Processed[s.ID] != fp, "reassess", due)
		out, err := p.Run(ctx, RunOptions{SBOMRef: s.ID, OutDir: opts.OutDir, Upload: opts.Upload, ReassessAfter: opts.ReassessAfter})
		if err != nil {
			errs = append(errs, fmt.Errorf("sbom %s: %w", s.ID, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		processed++
		state.Processed[s.ID] = fp
		state.ProcessedAt[s.ID] = time.Now().UTC()
		state.Usage.Add(out.Usage)
		state.LastPassUsage.Add(out.Usage)
		log.Info("sbom processed", "sbom", s.ID, "findings", out.Findings, "reassessed", out.Reassessed, "skipped", out.Skipped, "counts", out.Counts, "usage", out.Usage.String())
	}
	return processed, errors.Join(errs...)
}
