import './Solution.css'

export default function Solution() {
  return (
    <section id="solution" className="section">
      <div className="container">
        <header className="section-header">
          <h2>One gateway for agent security decisions.</h2>
          <p>
            Murdoc sits between agents, models, MCP servers, and internal tools.
            It keeps policy enforcement out of fragile prompts and applies the
            same security runtime across the traffic paths production agents
            already use.
          </p>
        </header>
        <div className="cards">
          <article className="card card-accent">
            <h3>1. Route through standard paths</h3>
            <p>
              Point OpenAI-compatible clients, HTTP tool calls, and MCP sessions
              at Murdoc. Agent frameworks keep their normal integration model
              while traffic moves through one security boundary.
            </p>
          </article>
          <article className="card card-accent">
            <h3>2. Enforce before action</h3>
            <p>
              Apply prompt-injection checks, PII redaction, guardrail modes,
              route profiles, and policy decisions before risky content reaches
              the model or a tool call reaches an upstream system.
            </p>
          </article>
          <article className="card card-accent">
            <h3>3. Preserve evidence</h3>
            <p>
              Record decisions, usage, security layers, and audit summaries
              without storing raw prompts, raw secrets, or raw responses in the
              decision ledger.
            </p>
          </article>
        </div>
      </div>
    </section>
  )
}
