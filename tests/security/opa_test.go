package security_test

import (
	"context"
	"testing"

	"github.com/murdoc-ai/murdoc/core/schemas"
	"github.com/murdoc-ai/murdoc/plugins/security/opa"
)

func TestOPAMiddleware_AllowedRequest(t *testing.T) {
	middleware, err := opa.NewOPAMiddleware("../fixtures/policies/allow_all.rego")
	if err != nil {
		t.Fatalf("Failed to create OPA middleware: %v", err)
	}

	req := &schemas.MurdocChatRequest{
		Model: "gpt-4",
		Messages: []schemas.Message{{Role: "user", Content: "Hello"}},
	}

	ctx := schemas.NewMurdocContext(context.Background(), 0)
	result := middleware.PreLLMHook(ctx, req, nil)

	if result.ShortCircuit != nil {
		t.Errorf("Expected request to pass, got blocked: %v", result.ShortCircuit.Error)
	}
}

func TestOPAMiddleware_BlockedRequest(t *testing.T) {
	middleware, err := opa.NewOPAMiddleware("../fixtures/policies/block_sensitive.rego")
	if err != nil {
		t.Fatalf("Failed to create OPA middleware: %v", err)
	}

	req := &schemas.MurdocChatRequest{
		Model: "gpt-4",
		Messages: []schemas.Message{{Role: "user", Content: "SSN: 123-45-6789"}},
	}

	ctx := schemas.NewMurdocContext(context.Background(), 0)
	result := middleware.PreLLMHook(ctx, req, nil)

	if result.ShortCircuit == nil {
		t.Error("Expected request to be blocked")
	}
}

func TestOPAMiddleware_PolicyNotFound(t *testing.T) {
	_, err := opa.NewOPAMiddleware("nonexistent.rego")
	if err == nil {
		t.Error("Expected error for missing policy file")
	}
}
