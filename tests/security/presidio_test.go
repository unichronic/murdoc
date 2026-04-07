package security_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/plugins/security/presidio"
)

// Mock Presidio server for testing
func mockPresidioServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/analyze" {
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req)
			text := req["text"].(string)

			// Simulate PII detection
			results := []map[string]interface{}{}
			if containsPattern(text, `\d{3}-\d{2}-\d{4}`) {
				results = append(results, map[string]interface{}{
					"entity_type": "US_SSN",
					"start":       0,
					"end":         11,
					"score":       0.95,
				})
			}
			if containsPattern(text, `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`) {
				results = append(results, map[string]interface{}{
					"entity_type": "CREDIT_CARD",
					"start":       0,
					"end":         19,
					"score":       0.9,
				})
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(results)
		} else if r.URL.Path == "/anonymize" {
			var req map[string]interface{}
			json.NewDecoder(r.Body).Decode(&req)
			text := req["text"].(string)

			// Simulate redaction
			redacted := text
			if containsPattern(text, `\d{3}-\d{2}-\d{4}`) {
				redacted = "[REDACTED_SSN]"
			}
			if containsPattern(text, `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`) {
				redacted = "[REDACTED_CREDIT_CARD]"
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"text": redacted,
			})
		}
	}))
}

func containsPattern(text, pattern string) bool {
	// Simple pattern matching for mock
	return len(text) > 0 && (pattern == `\d{3}-\d{2}-\d{4}` && len(text) >= 11) ||
		(pattern == `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}` && len(text) >= 16)
}

func TestPresidioMiddleware_DetectPII(t *testing.T) {
	server := mockPresidioServer(t)
	defer server.Close()

	middleware, err := presidio.NewPresidioMiddleware(server.URL)
	if err != nil {
		t.Fatalf("Failed to create Presidio middleware: %v", err)
	}

	tests := []struct {
		name        string
		content     string
		expectBlock bool
		entityType  string
	}{
		{
			name:        "Clean text passes",
			content:     "Hello, how are you?",
			expectBlock: false,
		},
		{
			name:        "SSN detected",
			content:     "My SSN is 123-45-6789",
			expectBlock: true,
			entityType:  "US_SSN",
		},
		{
			name:        "Credit card detected",
			content:     "Card: 4111-1111-1111-1111",
			expectBlock: true,
			entityType:  "CREDIT_CARD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &schemas.BifrostChatRequest{
				Model: "gpt-4",
				Messages: []schemas.Message{{Role: "user", Content: tt.content}},
			}

			ctx := schemas.NewBifrostContext(context.Background(), 0)
			result := middleware.PreLLMHook(ctx, req, nil)

			if tt.expectBlock {
				if result.ShortCircuit == nil {
					t.Error("Expected PII to be detected and blocked")
				}
			} else {
				if result.ShortCircuit != nil {
					t.Errorf("Expected clean text to pass, got blocked: %v", result.ShortCircuit.Error)
				}
			}
		})
	}
}

func TestPresidioMiddleware_RedactOutput(t *testing.T) {
	server := mockPresidioServer(t)
	defer server.Close()

	middleware, err := presidio.NewPresidioMiddleware(server.URL)
	if err != nil {
		t.Fatalf("Failed to create Presidio middleware: %v", err)
	}

	tests := []struct {
		name           string
		response       string
		expectRedacted bool
	}{
		{
			name:           "Clean response unchanged",
			response:       "The weather is sunny today.",
			expectRedacted: false,
		},
		{
			name:           "SSN redacted in response",
			response:       "Your SSN is 123-45-6789",
			expectRedacted: true,
		},
		{
			name:           "Credit card redacted",
			response:       "Card number: 4111-1111-1111-1111",
			expectRedacted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &schemas.BifrostChatResponse{
				Choices: []schemas.Choice{
					{Message: schemas.Message{Content: tt.response}},
				},
			}

			ctx := schemas.NewBifrostContext(context.Background(), 0)
			result := middleware.PostLLMHook(ctx, nil, resp, nil)

			if tt.expectRedacted {
				if result.Response.Choices[0].Message.Content == tt.response {
					t.Error("Expected response to be redacted")
				}
				if result.Response.Choices[0].Message.Content != "[REDACTED_SSN]" &&
					result.Response.Choices[0].Message.Content != "[REDACTED_CREDIT_CARD]" {
					t.Errorf("Unexpected redaction result: %s", result.Response.Choices[0].Message.Content)
				}
			} else {
				if result.Response.Choices[0].Message.Content != tt.response {
					t.Error("Expected clean response to remain unchanged")
				}
			}
		})
	}
}

func TestPresidioMiddleware_ServiceUnavailable(t *testing.T) {
	// Point to non-existent service
	middleware, err := presidio.NewPresidioMiddleware("http://localhost:9999")
	if err != nil {
		t.Fatalf("Failed to create Presidio middleware: %v", err)
	}

	req := &schemas.BifrostChatRequest{
		Model: "gpt-4",
		Messages: []schemas.Message{{Role: "user", Content: "Test"}},
	}

	ctx := schemas.NewBifrostContext(context.Background(), 0)
	result := middleware.PreLLMHook(ctx, req, nil)

	// Should fail gracefully or allow request through (depending on implementation)
	if result.ShortCircuit != nil {
		t.Logf("Service unavailable handled: %v", result.ShortCircuit.Error)
	}
}
