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

type BifrostChatRequest = AgentVaultChatRequest

type AgentVaultChatResponse struct {
	Choices []Choice
}

type BifrostChatResponse = AgentVaultChatResponse

type PluginConfig struct {
	Name    string
	Enabled bool
	Config  map[string]interface{}
}

type AgentVaultConfig struct {
	Plugins []PluginConfig
}

type BifrostConfig = AgentVaultConfig

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

func NewBifrostContext(ctx context.Context, index int) *AgentVaultContext {
	return NewAgentVaultContext(ctx, index)
}

type LLMPluginShortCircuit struct {
	Error error
}

type HookResult struct {
	ShortCircuit *LLMPluginShortCircuit
	Response     *AgentVaultChatResponse
}
