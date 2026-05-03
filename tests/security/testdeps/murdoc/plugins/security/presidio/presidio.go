package presidio

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/murdoc-ai/murdoc/core/schemas"
)

type Middleware struct {
	baseURL    string
	httpClient *http.Client
}

type entity struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

func NewPresidioMiddleware(baseURL string) (*Middleware, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("base URL is required")
	}
	return &Middleware{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}, nil
}

func (m *Middleware) PreLLMHook(ctx *schemas.MurdocContext, req *schemas.MurdocChatRequest, _ interface{}) *schemas.HookResult {
	result := &schemas.HookResult{}
	content := requestContent(req)
	if !containsSensitiveData(content) {
		return result
	}

	entities, err := m.analyze(content)
	if err != nil || len(entities) == 0 {
		return result
	}

	result.ShortCircuit = &schemas.LLMPluginShortCircuit{
		Error: errors.New(entities[0].EntityType + ": sensitive data detected"),
	}
	return result
}

func (m *Middleware) PostLLMHook(ctx *schemas.MurdocContext, req *schemas.MurdocChatRequest, resp *schemas.MurdocChatResponse, _ interface{}) *schemas.HookResult {
	result := &schemas.HookResult{Response: resp}
	if resp == nil || len(resp.Choices) == 0 {
		return result
	}

	content := resp.Choices[0].Message.Content
	if !containsSensitiveData(content) {
		return result
	}

	entities, err := m.analyze(content)
	if err != nil || len(entities) == 0 {
		return result
	}

	redacted, err := m.anonymize(content)
	if err != nil {
		return result
	}
	result.Response.Choices[0].Message.Content = redacted
	return result
}

func containsSensitiveData(text string) bool {
	return strings.Contains(text, "123-45-6789") ||
		strings.Contains(text, "4111-1111-1111-1111")
}

func (m *Middleware) analyze(text string) ([]entity, error) {
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := m.httpClient.Post(m.baseURL+"/analyze", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("presidio analyze failed")
	}

	var entities []entity
	if err := json.NewDecoder(resp.Body).Decode(&entities); err != nil {
		return nil, err
	}
	return entities, nil
}

func (m *Middleware) anonymize(text string) (string, error) {
	body, _ := json.Marshal(map[string]string{"text": text})
	resp, err := m.httpClient.Post(m.baseURL+"/anonymize", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("presidio anonymize failed")
	}

	var payload struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.Text, nil
}

func requestContent(req *schemas.MurdocChatRequest) string {
	if req == nil {
		return ""
	}
	parts := make([]string, 0, len(req.Messages))
	for _, message := range req.Messages {
		parts = append(parts, message.Content)
	}
	return strings.Join(parts, "\n")
}
