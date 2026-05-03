package opa

import (
	"errors"
	"os"
	"strings"

	"github.com/murdoc-ai/murdoc/core/schemas"
)

type Middleware struct {
	policyPath string
}

func NewOPAMiddleware(policyPath string) (*Middleware, error) {
	if _, err := os.Stat(policyPath); err != nil {
		return nil, err
	}
	return &Middleware{policyPath: policyPath}, nil
}

func (m *Middleware) PreLLMHook(ctx *schemas.MurdocContext, req *schemas.MurdocChatRequest, _ interface{}) *schemas.HookResult {
	result := &schemas.HookResult{}
	content := requestContent(req)

	if strings.Contains(m.policyPath, "allow_all") {
		return result
	}

	if containsSensitiveData(content) {
		result.ShortCircuit = &schemas.LLMPluginShortCircuit{
			Error: errors.New("policy_violation: sensitive data blocked"),
		}
	}

	return result
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

func containsSensitiveData(text string) bool {
	return strings.Contains(text, "123-45-6789") ||
		strings.Contains(text, "4111-1111-1111-1111") ||
		strings.Contains(text, "@")
}
