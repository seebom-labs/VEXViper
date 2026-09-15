package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CopilotCLI assesses findings through GitHub Copilot CLI's non-interactive
// mode (`copilot -p <prompt> -s`). This uses the user's Copilot subscription
// via the official CLI: no API key is needed, authentication is whatever the
// CLI is logged in with (`copilot` → /login, `gh auth login`, or
// COPILOT_GITHUB_TOKEN / GH_TOKEN in the environment).
//
// Tools that could touch the machine (shell, write, edit) are denied and the
// model is told to answer with a single JSON object. The prompt is passed via
// stdin-free argv, so keep an eye on OS argument limits for huge reports.
type CopilotCLI struct {
	// Command is the executable (default "copilot").
	Command string
	// Model is passed as --model when set.
	Model string
	// Args are appended verbatim (e.g. --agent, --add-dir).
	Args []string
	// Dir is the working directory (empty = current directory).
	Dir string
	// InRepo runs in req.RepoDir when set so Copilot can read the product's
	// source (read-only tools such as view/grep remain allowed).
	InRepo bool
	// Timeout per assessment (default 3 minutes).
	Timeout time.Duration
	// Env adds environment variables (e.g. COPILOT_GITHUB_TOKEN).
	Env map[string]string
	// runner is swappable for tests.
	runner func(ctx context.Context, cmd *exec.Cmd) ([]byte, []byte, error)
}

// Name implements Provider.
func (c *CopilotCLI) Name() string {
	if c.Model != "" {
		return "copilot:" + c.Model
	}
	return "copilot"
}

// Assess implements Provider.
func (c *CopilotCLI) Assess(ctx context.Context, req Request) (Assessment, error) {
	if req.Report == nil {
		return Assessment{}, fmt.Errorf("copilot: nil report")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(ctx, c.command(), c.args(req)...)
	cmd.Dir = c.Dir
	if c.InRepo && req.RepoDir != "" {
		cmd.Dir = req.RepoDir
	}
	if len(c.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range c.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	run := c.runner
	if run == nil {
		run = defaultRunner
	}
	stdout, stderr, err := run(ctx, cmd)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		if strings.Contains(msg, "authenticate") || strings.Contains(msg, "/login") {
			return Assessment{}, fmt.Errorf("copilot: not logged in (run `copilot` and `/login`, `gh auth login`, or set COPILOT_GITHUB_TOKEN): %w", err)
		}
		return Assessment{}, fmt.Errorf("copilot: %w: %.400s", err, msg)
	}
	text, usage := parseCopilotOutput(stdout)
	a, err := ParseAssessment(text)
	if err != nil {
		return Assessment{}, fmt.Errorf("copilot: %w", err)
	}
	a.Provider = c.Name()
	usage.Calls = 1
	usage.Duration = time.Since(start)
	if usage.Model == "" {
		usage.Model = c.Model
	}
	a.Usage = usage
	return a, nil
}

// copilotEvent is the subset of Copilot CLI `--output-format json` (JSONL)
// events VEXViper reads: the final assistant message, the model in use and
// the billing summary in the trailing "result" event.
type copilotEvent struct {
	Type string `json:"type"`
	Data struct {
		Content      string `json:"content"`
		Model        string `json:"model"`
		OutputTokens int    `json:"outputTokens"`
		ToolRequests []any  `json:"toolRequests"`
	} `json:"data"`
	Usage struct {
		PremiumRequests    float64 `json:"premiumRequests"`
		TotalAPIDurationMs int64   `json:"totalApiDurationMs"`
	} `json:"usage"`
}

// parseCopilotOutput extracts the assistant's final answer and usage from
// JSONL output. Output that is not JSONL (older CLIs, or a CLI that ignored
// --output-format) is returned verbatim so ParseAssessment can still try.
func parseCopilotOutput(out []byte) (string, Usage) {
	var (
		u       Usage
		answer  string
		isJSONL bool
	)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev copilotEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Type == "" {
			continue
		}
		isJSONL = true
		switch ev.Type {
		case "assistant.message":
			// Tool-call turns also emit assistant.message; keep the last one
			// carrying text, which is the answer.
			if strings.TrimSpace(ev.Data.Content) != "" {
				answer = ev.Data.Content
			}
			u.CompletionTokens += ev.Data.OutputTokens
		case "assistant.reasoning":
			u.CompletionTokens += ev.Data.OutputTokens
		case "session.tools_updated", "session.model_changed":
			if ev.Data.Model != "" {
				u.Model = ev.Data.Model
			}
		case "result":
			u.PremiumRequests = ev.Usage.PremiumRequests
		}
	}
	if !isJSONL {
		return string(out), u
	}
	return answer, u
}

func (c *CopilotCLI) command() string {
	if c.Command != "" {
		return c.Command
	}
	return "copilot"
}

func (c *CopilotCLI) args(req Request) []string {
	schema, _ := json.Marshal(JSONSchema)
	prompt := SystemPrompt + "\n\nJSON schema of the required answer:\n" + string(schema) +
		"\n\n" + c.toolHint() + " Answer with the JSON object only.\n\n" +
		BuildUserPrompt(req)
	args := []string{"-p", prompt, "-s", "--output-format", "json", "--no-ask-user", "--no-auto-update", "--no-custom-instructions",
		"--deny-tool=shell", "--deny-tool=write", "--deny-tool=edit"}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	return append(args, c.Args...)
}

func (c *CopilotCLI) toolHint() string {
	if c.InRepo {
		return "The working directory is the product's source checkout; you may read files to verify whether the vulnerable code is used. Do not modify anything."
	}
	return "Do not use any tools; decide from the evidence given."
}

func defaultRunner(_ context.Context, cmd *exec.Cmd) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && stdout.Len() > 0 && stderr.Len() == 0 {
		// Some CLI versions exit non-zero after printing the answer; trust the payload.
		return stdout.Bytes(), nil, nil
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
