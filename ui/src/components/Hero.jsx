import './Hero.css'

export default function Hero({ setCurrentView }) {
  return (
    <section className="hero">
      <div className="container hero-inner">
        <p className="hero-pill">AI Agent Security Gateway</p>
        <h1 className="hero-title">
          <span className="accent">Secure every agent</span>
          <br />
          before it acts.
        </h1>
        <p className="hero-lead">
          Murdoc routes LLM calls, HTTP tools, and MCP sessions through one
          self-hosted policy runtime with prompt-injection checks, PII
          redaction, guardrail orchestration, and audit records.
        </p>
        <div className="hero-actions">
          <button
            type="button"
            onClick={() => setCurrentView('console')}
            className="hero-action"
          >
            Open Admin Console
          </button>
        </div>
      </div>
    </section>
  )
}
