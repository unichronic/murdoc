import './Hero.css'

export default function Hero({ setCurrentView }) {
  return (
    <section className="hero">
      <div className="container hero-inner">
        <p className="hero-pill">Enterprise AI Security & Governance</p>
        <h1 className="hero-title">
          <span className="accent">Agentic Risks.</span>
          <br />
          Neutralized.
        </h1>
        <p className="hero-lead">
          Secure your autonomous AI deployments against the 2026 threat landscape.
          AgentVault provides continuous Asset Discovery, extreme-latency Runtime Guardrails,
          and Automated Red Teaming to ensure your AI acts safely within Zero-Trust boundaries.
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
