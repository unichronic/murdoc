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
        <div className="hero-actions" style={{ marginTop: '2rem' }}>
          <button
            type="button"
            onClick={() => setCurrentView('demo')}
            style={{
              padding: '0.8rem 2rem',
              fontSize: '1.1rem',
              fontWeight: 'bold',
              cursor: 'pointer',
              background: 'linear-gradient(135deg, var(--accent), #e74c3c)',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              transition: 'transform 0.2s',
              boxShadow: '0 4px 14px rgba(255, 60, 60, 0.3)'
            }}
            onMouseOver={(e) => e.target.style.transform = 'translateY(-2px)'}
            onMouseOut={(e) => e.target.style.transform = 'translateY(0)'}
          >
            Launch Interactive Demo
          </button>
        </div>
      </div>
    </section>
  )
}
