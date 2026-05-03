package schemas

import "context"

type Message struct {
	Role    string
	Content string
}

type Choice struct {
	Message Message
}

type MurdocChatRequest struct {
	Model    string
	Messages []Message
}

type MurdocChatResponse struct {
	Choices []Choice
}

type PluginConfig struct {
	Name    string
	Enabled bool
	Config  map[string]interface{}
}

type MurdocConfig struct {
	Plugins []PluginConfig
}

type MurdocContext struct {
	context.Context
	Index int
}

func NewMurdocContext(ctx context.Context, index int) *MurdocContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &MurdocContext{Context: ctx, Index: index}
}

type LLMPluginShortCircuit struct {
	Error error
}

type HookResult struct {
	ShortCircuit *LLMPluginShortCircuit
	Response     *MurdocChatResponse
}
