import './Problem.css'

export default function Problem() {
  return (
    <section id="problem" className="section section-alt">
      <div className="container">
        <header className="section-header">
          <h2>Agents need a security boundary outside the model.</h2>
          <p>
            Prompt injection is only the visible part of the problem. Production
            agents also read untrusted context, call internal APIs, receive MCP
            tool output, and make decisions with credentials your organization
            must govern.
          </p>
        </header>
        <div className="cards">
          <article className="card">
            <h3>Indirect prompt injection</h3>
            <p>Malicious instructions hidden in tickets, pages, files, or tool responses can enter the model as trusted context.</p>
          </article>
          <article className="card">
            <h3>Tool misuse</h3>
            <p>A manipulated agent can call write APIs, update records, or expose internal data unless tool actions are checked at the gateway.</p>
          </article>
          <article className="card">
            <h3>Audit gaps</h3>
            <p>Without a shared gateway layer, every framework and agent leaves different evidence for what was allowed, blocked, or redacted.</p>
          </article>
        </div>
      </div>
    </section>
  )
}
