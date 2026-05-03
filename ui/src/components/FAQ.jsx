import { useState } from 'react'
import './FAQ.css'

const ITEMS = [
  {
    q: 'What is Murdoc?',
    a: 'Murdoc is an AI security gateway for agents, tools, and MCP traffic. It sits between agent runtimes and the systems they call so teams can inspect, redact, authorize, and audit risky agent traffic in one place.',
  },
  {
    q: 'How does it protect against prompt injection?',
    a: 'Murdoc checks prompts, context, and tool output before they continue through the agent workflow. Tool calls are also evaluated against route policy, so a manipulated model does not become the security boundary.',
  },
  {
    q: 'Where does it sit?',
    a: 'Murdoc can sit in front of OpenAI-compatible LLM calls, HTTP tool/API calls, and MCP sessions. The goal is to give platform teams one gateway layer instead of custom wrappers inside every agent.',
  },
  {
    q: 'Do I need to change my AI models or orchestrator?',
    a: 'No model changes are required. Agents route traffic through Murdoc using standard integration modes such as an OpenAI-compatible base URL, an HTTP proxy route, or an MCP gateway.',
  },
  {
    q: 'Is Murdoc open source?',
    a: 'Yes. Murdoc is open source and self-hosted so prompt traffic, tool output, policies, and audit records can stay inside the organization running it.',
  },
]

export default function FAQ() {
  const [openIndex, setOpenIndex] = useState(null)

  return (
    <section id="faq" className="section faq-section">
      <div className="container">
        <header className="section-header faq-header">
          <h2>All your questions answered</h2>
          <p>Common questions about deploying an AI security gateway for agent traffic.</p>
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
