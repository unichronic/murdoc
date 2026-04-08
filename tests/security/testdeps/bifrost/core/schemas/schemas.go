package schemas

import "context"

type Message struct {
	Role    string
	Content string
}

type Choice struct {
	Message Message
}

type AgentVaultChatRequest struct {
	Model    string
	Messages []Message
}

type AgentVaultChatResponse struct {
	Choices []Choice
}

type PluginConfig struct {
	Name    string
	Enabled bool
	Config  map[string]interface{}
}

type AgentVaultConfig struct {
	Plugins []PluginConfig
}

type AgentVaultContext struct {
	context.Context
	Index int
}

func NewAgentVaultContext(ctx context.Context, index int) *AgentVaultContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &AgentVaultContext{Context: ctx, Index: index}
}

type LLMPluginShortCircuit struct {
	Error error
}

type HookResult struct {
	ShortCircuit *LLMPluginShortCircuit
	Response     *AgentVaultChatResponse
}
