package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAI talks to any OpenAI-compatible /chat/completions endpoint.
type OpenAI struct {
	BaseURL     string
	Model       string
	APIKey      string
	Temperature float64
	HTTP        *http.Client
	// StructuredOutput requests response_format=json_schema (supported by
	// OpenAI, Azure and recent Ollama/vLLM). When the server rejects it, the
	// provider falls back to plain JSON mode automatically.
	StructuredOutput bool
	// ExtraHeaders are added to every request (e.g. Azure api-key).
	ExtraHeaders map[string]string
	// Name overrides the provider name prefix reported in VEX tooling metadata
	// (default "openai"), e.g. "github" for GitHub Models.
	ProviderName string
}

// Name implements Provider.
func (o *OpenAI) Name() string {
	if o.ProviderName != "" {
		return o.ProviderName + ":" + o.Model
	}
	return "openai:" + o.Model
}

type chatRequest struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float64       `json:"temperature"`
	ResponseFormat any           `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
	Model string `json:"model"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Assess implements Provider.
func (o *OpenAI) Assess(ctx context.Context, req Request) (Assessment, error) {
	if req.Report == nil {
		return Assessment{}, fmt.Errorf("openai: nil report")
	}
	messages := []chatMessage{
		{Role: "system", Content: SystemPrompt},
		{Role: "user", Content: BuildUserPrompt(req)},
	}
	var format any
	if o.StructuredOutput {
		format = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "vex_assessment",
				"strict": false,
				"schema": JSONSchema,
			},
		}
	} else {
		format = map[string]any{"type": "json_object"}
	}
	start := time.Now()
	var usage Usage
	text, err := o.complete(ctx, messages, format, &usage)
	if err != nil && o.StructuredOutput && isUnsupportedFormat(err) {
		text, err = o.complete(ctx, messages, map[string]any{"type": "json_object"}, &usage)
	}
	if err != nil && isUnsupportedFormat(err) {
		text, err = o.complete(ctx, messages, nil, &usage)
	}
	if err != nil {
		return Assessment{}, err
	}
	a, err := ParseAssessment(text)
	if err != nil {
		return Assessment{}, fmt.Errorf("openai: %w", err)
	}
	a.Provider = o.Name()
	usage.Duration = time.Since(start)
	a.Usage = usage
	return a, nil
}

// complete performs one chat completion and accumulates token usage into
// usage (every attempt counts, including format fallbacks that failed).
func (o *OpenAI) complete(ctx context.Context, messages []chatMessage, format any, usage *Usage) (string, error) {
	body, _ := json.Marshal(chatRequest{Model: o.Model, Messages: messages, Temperature: o.Temperature, ResponseFormat: format})
	url := strings.TrimRight(o.BaseURL, "/") + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)
	}
	for k, v := range o.ExtraHeaders {
		httpReq.Header.Set(k, v)
	}
	hc := o.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := hc.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("openai: request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var cr chatResponse
	_ = json.Unmarshal(data, &cr)
	usage.Add(Usage{Calls: 1, PromptTokens: cr.Usage.PromptTokens, CompletionTokens: cr.Usage.CompletionTokens, Model: cr.Model})
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(data))
		if cr.Error != nil {
			msg = cr.Error.Message
		}
		return "", &httpError{Status: resp.StatusCode, Message: msg}
	}
	if len(cr.Choices) == 0 {
		return "", fmt.Errorf("openai: empty choices in response")
	}
	return cr.Choices[0].Message.Content, nil
}

type httpError struct {
	Status  int
	Message string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("openai: HTTP %d: %.300s", e.Status, e.Message)
}

func isUnsupportedFormat(err error) bool {
	he, ok := err.(*httpError)
	if !ok || he.Status != http.StatusBadRequest {
		return false
	}
	m := strings.ToLower(he.Message)
	return strings.Contains(m, "response_format") || strings.Contains(m, "json_schema") || strings.Contains(m, "json_object")
}
