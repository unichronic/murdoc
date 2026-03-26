import { useState } from 'react'
import './PromptGenerator.css'

export default function PromptGenerator({ placeholder, onChangeScenario }) {
  const [prompt, setPrompt] = useState('')

  return (
    <section className="prompt-section">
      <div className="container prompt-inner">
        <label className="prompt-label" htmlFor="agent-prompt">
          AI agent prompt
        </label>
        <textarea
          id="agent-prompt"
          className="prompt-input"
          placeholder={placeholder}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          rows={4}
        />
        <div className="prompt-actions">
          <button type="button" className="btn-change-scenario" onClick={onChangeScenario}>
            Change scenarios
          </button>
        </div>
      </div>
    </section>
  )
}
