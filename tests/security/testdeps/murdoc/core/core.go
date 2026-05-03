package murdoc

import (
	"errors"
	"strings"

	"github.com/murdoc-ai/murdoc/core/schemas"
)

type Murdoc struct {
	plugins []schemas.PluginConfig
}

func NewMurdoc(config *schemas.MurdocConfig) (*Murdoc, error) {
	if config == nil {
		return &Murdoc{}, nil
	}
	return &Murdoc{plugins: config.Plugins}, nil
}

func (a *Murdoc) Close() error {
	return nil
}

func (a *Murdoc) ChatCompletion(ctx *schemas.MurdocContext, req *schemas.MurdocChatRequest) (*schemas.MurdocChatResponse, error) {
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

	return &schemas.MurdocChatResponse{
		Choices: []schemas.Choice{
			{Message: schemas.Message{Role: "assistant", Content: "request passed security checks"}},
		},
	}, nil
}

func requestContent(req *schemas.MurdocChatRequest) string {
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
