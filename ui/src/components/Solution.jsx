import './Solution.css'

export default function Solution() {
  return (
    <section id="solution" className="section">
      <div className="container">
        <header className="section-header">
          <h2>Our solution: a Security Proxy Layer</h2>
          <p>
            Instead of simply trusting the AI to always follow instructions correctly, we place a
            protective shield between the AI and the outside world. This layer constantly monitors
            what the AI reads, what it remembers, and what actions it tries to perform.
          </p>
        </header>
        <div className="cards">
          <article className="card card-accent">
            <h3>1. Scan incoming data</h3>
            <p>
              We scan all incoming data — emails, PDFs, logs — for hidden malicious instructions and
              remove them before the AI can process them. Our system acts as a security proxy for AI
              agents and removes threats before the AI can process them.
            </p>
          </article>
          <article className="card card-accent">
            <h3>2. Behavioral guardrails</h3>
            <p>
              We enforce real-time behavioral guardrails, blocking any attempt to misuse tools or
              leak sensitive data — even if the AI is tricked.
            </p>
          </article>
          <article className="card card-accent">
            <h3>3. Canary markers</h3>
            <p>
              We embed invisible &quot;canary&quot; markers in sensitive data. If any protected
              information is leaked, the system detects it immediately and triggers alerts or
              shutdowns.
            </p>
          </article>
        </div>
      </div>
    </section>
  )
}
