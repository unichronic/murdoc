import './HowItWorks.css'

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="section section-alt">
      <div className="container">
        <header className="section-header">
          <h2>How it fits into your agent stack</h2>
          <p>
            Drop the Security Proxy Layer between your orchestrator and the outside world. No
            retraining. No model changes. No lock-in.
          </p>
        </header>
        <div className="flow">
          <div className="flow-step">
            <span className="flow-badge">01</span>
            <h3>Ingest</h3>
            <p>Data from users, systems, and third-party sources flows into the proxy.</p>
          </div>
          <div className="flow-step">
            <span className="flow-badge">02</span>
            <h3>Inspect</h3>
            <p>Content is scanned for malicious patterns, injection attempts, and poisoning.</p>
          </div>
          <div className="flow-step">
            <span className="flow-badge">03</span>
            <h3>Decide</h3>
            <p>Policies decide what is allowed, modified, or blocked for context and tool calls.</p>
          </div>
          <div className="flow-step">
            <span className="flow-badge">04</span>
            <h3>Monitor</h3>
            <p>Interactions are scored, logged, and fed into continuous testing.</p>
          </div>
        </div>
      </div>
    </section>
  )
}
