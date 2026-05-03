import './HowItWorks.css'

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="section section-alt">
      <div className="container">
        <header className="section-header">
          <h2>How it fits into your agent stack</h2>
          <p>
            Put Murdoc on the path agents already use to reach models, tools,
            and MCP servers. No retraining or model changes required.
          </p>
        </header>
        <div className="flow">
          <div className="flow-step">
            <span className="flow-badge">01</span>
            <h3>Connect</h3>
            <p>Agents connect through OpenAI-compatible, HTTP proxy, or MCP gateway modes.</p>
          </div>
          <div className="flow-step">
            <span className="flow-badge">02</span>
            <h3>Inspect</h3>
            <p>Prompts, context, tool calls, and tool output are normalized for shared security checks.</p>
          </div>
          <div className="flow-step">
            <span className="flow-badge">03</span>
            <h3>Decide</h3>
            <p>Route profiles, guardrails, redaction, and policy decide what is allowed, modified, or blocked.</p>
          </div>
          <div className="flow-step">
            <span className="flow-badge">04</span>
            <h3>Audit</h3>
            <p>Decisions are recorded for review, usage tracking, alerting, and regression testing.</p>
          </div>
        </div>
      </div>
    </section>
  )
}
