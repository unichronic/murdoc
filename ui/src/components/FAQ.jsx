import { useState } from 'react'
import './FAQ.css'

const ITEMS = [
  {
    q: 'What is the Security Proxy Layer?',
    a: 'A protective layer that sits between your AI agents and the world. It scans incoming data for hidden malicious instructions, enforces behavioral guardrails on tool use, and embeds canary markers to detect data leaks in real time.',
  },
  {
    q: 'How does it protect against prompt injection and goal hijacking?',
    a: 'All incoming content — emails, PDFs, logs, tickets — is inspected before the agent sees it. Prompt-injection patterns and hidden goals are detected and stripped. Tool calls are evaluated against policy regardless of what the model decided.',
  },
  {
    q: 'What are canary markers?',
    a: 'Invisible markers embedded in sensitive data. If that data is ever leaked through an agent (e.g. in a response or log), the system detects the canary and can trigger alerts, shutdowns, or incident timelines.',
  },
  {
    q: 'Do I need to change my AI models or orchestrator?',
    a: 'No. The proxy sits in front of your existing stack. You route traffic through it; no retraining or model changes required. It works with LangChain, LlamaIndex, custom orchestrators, and more.',
  },
  {
    q: 'Is this aligned with OWASP and agent security standards?',
    a: 'Yes. We align with OWASP Top 10 for Agentic Applications 2026, including Agent Goal Hijacking, Tool Misuse, and context/memory poisoning. The proxy is designed for security teams and builders alike.',
  },
]

export default function FAQ() {
  const [openIndex, setOpenIndex] = useState(null)

  return (
    <section id="faq" className="section faq-section">
      <div className="container">
        <header className="section-header faq-header">
          <h2>All your questions answered</h2>
          <p>Common questions about the Security Proxy Layer and how it keeps your AI agents protected.</p>
        </header>
        <div className="faq-list">
          {ITEMS.map((item, i) => (
            <div
              key={i}
              className={`faq-item ${openIndex === i ? 'open' : ''}`}
              onClick={() => setOpenIndex(openIndex === i ? null : i)}
            >
              <h3 className="faq-question">{item.q}</h3>
              <div className="faq-answer">
                <p>{item.a}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
