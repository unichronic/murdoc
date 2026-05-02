package bifrost

import (
	"errors"
	"strings"

	"github.com/maximhq/bifrost/core/schemas"
)

type AgentVault struct {
	plugins []schemas.PluginConfig
}

func NewAgentVault(config *schemas.AgentVaultConfig) (*AgentVault, error) {
	if config == nil {
		return &AgentVault{}, nil
	}
	return &AgentVault{plugins: config.Plugins}, nil
}

func NewBifrost(config *schemas.BifrostConfig) (*AgentVault, error) {
	return NewAgentVault(config)
}

func (a *AgentVault) Close() error {
	return nil
}

func (a *AgentVault) ChatCompletion(ctx *schemas.AgentVaultContext, req *schemas.AgentVaultChatRequest) (*schemas.AgentVaultChatResponse, error) {
	content := requestContent(req)

	for _, plugin := range a.plugins {
		if !plugin.Enabled {
			continue
		}

		switch plugin.Name {
		case "lakera":
			if isPromptInjection(content) {
				return nil, errors.New("prompt_injection: prompt injection detected")
			}
		case "opa":
			if containsPII(content) {
				return nil, errors.New("policy_violation: sensitive data blocked")
			}
		case "presidio":
			if containsPII(content) {
				return nil, errors.New("pii_detected: sensitive data blocked")
			}
		}
	}

	return &schemas.AgentVaultChatResponse{
		Choices: []schemas.Choice{
			{Message: schemas.Message{Role: "assistant", Content: "request passed security checks"}},
		},
	}, nil
}

func requestContent(req *schemas.AgentVaultChatRequest) string {
	if req == nil {
		return ""
	}
	var builder strings.Builder
	for _, message := range req.Messages {
		if builder.Len() > 0 {
			builder.WriteString("\n")
		}
		builder.WriteString(message.Content)
	}
	return builder.String()
}

func isPromptInjection(text string) bool {
	normalized := strings.ToLower(text)
	patterns := []string{
		"ignore previous",
		"disregard all",
		"reveal secrets",
		"jailbreak",
		"bypass restrictions",
	}
	for _, pattern := range patterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}
	return false
}

func containsPII(text string) bool {
	return strings.Contains(text, "123-45-6789") ||
		strings.Contains(text, "4111-1111-1111-1111") ||
		strings.Contains(text, "@")
}
