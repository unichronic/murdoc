import './Problem.css'

export default function Problem() {
  return (
    <section id="problem" className="section section-alt">
      <div className="container">
        <header className="section-header">
          <h2>AI agents are powerful. They are also dangerously obedient.</h2>
          <p>
            These incidents represent the &quot;Agent Goal Hijacking&quot; and &quot;Tool Misuse&quot;
            vulnerabilities now prioritized in the OWASP Top 10 for Agentic Applications 2026. Without
            a security proxy, an agent&apos;s autonomy becomes a direct, high-speed conduit for
            corporate espionage.
          </p>
        </header>
        <div className="cards">
          <article className="card">
            <h3>Goal hijacking &amp; prompt injection</h3>
            <p>Hidden instructions in emails, PDFs, and logs override system goals and leak secrets.</p>
          </article>
          <article className="card">
            <h3>Context &amp; memory poisoning</h3>
            <p>Long-horizon attacks poison what the agent remembers and trusts over time.</p>
          </article>
          <article className="card">
            <h3>Tool misuse &amp; privilege abuse</h3>
            <p>Agents are tricked into misusing tools or escalating to admin identities.</p>
          </article>
        </div>
      </div>
    </section>
  )
}
