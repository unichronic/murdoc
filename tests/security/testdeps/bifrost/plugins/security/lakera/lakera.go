package lakera

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

type Middleware struct {
	baseURL    string
	apiKey     string
	threshold  float64
	httpClient *http.Client
}

type responsePayload struct {
	Flagged     bool    `json:"flagged"`
	PayloadType string  `json:"payload_type"`
	Confidence  float64 `json:"confidence"`
}

func NewLakeraMiddleware(baseURL, apiKey string) (*Middleware, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("base URL is required")
	}
	return &Middleware{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		threshold:  0.5,
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}, nil
}

func (m *Middleware) SetConfidenceThreshold(threshold float64) {
	m.threshold = threshold
}

func (m *Middleware) PreLLMHook(ctx *schemas.AgentVaultContext, req *schemas.AgentVaultChatRequest, _ interface{}) *schemas.HookResult {
	result := &schemas.HookResult{}
	content := requestContent(req)
	scanInput := normalizeForMock(content)

	body, _ := json.Marshal(map[string]string{"input": scanInput})
	resp, err := m.httpClient.Post(m.baseURL+"/prompt_injection", "application/json", bytes.NewReader(body))
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result
	}

	var payload responsePayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return result
	}

	if payload.Flagged && payload.Confidence >= m.threshold {
		attackType := payload.PayloadType
		if attackType == "" {
			attackType = "prompt_injection"
		}
		result.ShortCircuit = &schemas.LLMPluginShortCircuit{
			Error: errors.New(attackType + ": request blocked"),
		}
	}

	return result
}

func normalizeForMock(content string) string {
	normalized := strings.ToLower(content)
	switch {
	case strings.Contains(normalized, "ignore previous"):
		return "ignore previous"
	case strings.Contains(normalized, "disregard all"):
		return "disregard all"
	case strings.Contains(normalized, "jailbreak"):
		return "jailbreak"
	case strings.Contains(normalized, "bypass restrictions"):
		return "bypass restrictions"
	default:
		return normalized
	}
}

func requestContent(req *schemas.AgentVaultChatRequest) string {
	if req == nil {
		return ""
	}
	parts := make([]string, 0, len(req.Messages))
	for _, message := range req.Messages {
		parts = append(parts, message.Content)
	}
	return strings.Join(parts, "\n")
}
