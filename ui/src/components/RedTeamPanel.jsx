import { useState } from 'react'
import './RedTeamPanel.css'

const VECTOR_ICONS = {
    'LLM01': 'INJ',
    'LLM02': 'EXEC',
    'LLM06': 'EXFIL',
    'LLM04': 'CTX',
    'Baseline': 'OK',
}

function vectorIcon(vector) {
    const key = Object.keys(VECTOR_ICONS).find(k => vector.includes(k))
    return key ? VECTOR_ICONS[key] : 'RISK'
}

function StatusBadge({ result }) {
    if (result.should_pass) {
        return result.blocked
            ? <span className="rt-badge rt-badge-fp">False Positive</span>
            : <span className="rt-badge rt-badge-pass">Passed</span>
    }
    if (result.blocked) {
        return <span className="rt-badge rt-badge-blocked">Blocked</span>
    }
    return <span className="rt-badge rt-badge-bypass">Bypassed</span>
}

export default function RedTeamPanel() {
    const [running, setRunning] = useState(false)
    const [done, setDone] = useState(false)
    const [results, setResults] = useState([])
    const [summary, setSummary] = useState(null)
    const [expanded, setExpanded] = useState(null)

    const runFuzzer = async () => {
        setRunning(true)
        setDone(false)
        setResults([])
        setSummary(null)

        try {
            const resp = await fetch('/api/fuzz', { method: 'POST' })
            const data = await resp.json()
            setResults(data.results || [])
            setSummary(data.summary || null)
            setDone(true)
        } catch (err) {
            setResults([{ id: 'ERR', vector: 'Error', description: `Connection failed: ${err.message}`, error: true }])
            setDone(true)
        } finally {
            setRunning(false)
        }
    }

    return (
        <section className="red-team-panel" id="red-team">
            <div className="container">
                <header className="rt-header">
                    <div className="rt-title-row">
                        <h2>Automated Red Teaming</h2>
                        <span className="rt-badge-label">OWASP LLM Top 10</span>
                    </div>
                    <p>
                        Fire 11 adversarial payloads across 4 attack vectors through the Murdoc Gateway.
                        Each payload is marked <strong>Blocked</strong> (gateway stopped it) or <strong>Bypassed</strong> (slipped through).
                    </p>
                </header>

                <div className="rt-controls">
                    <button
                        className={`rt-run-btn ${running ? 'rt-run-btn-busy' : ''}`}
                        onClick={runFuzzer}
                        disabled={running}
                    >
                        {running ? (
                            <span className="rt-spinner">Running fuzzer...</span>
                        ) : (
                            'Run Red Team Scan'
                        )}
                    </button>
                </div>

                {summary && (
                    <div className={`rt-summary ${summary.owasp_pass ? 'rt-summary-pass' : 'rt-summary-fail'}`}>
                        <div className="rt-summary-stat">
                            <span className="rt-summary-value">{summary.prevention_rate}%</span>
                            <span className="rt-summary-label">Prevention Rate</span>
                        </div>
                        <div className="rt-summary-stat">
                            <span className="rt-summary-value">{summary.blocked}/{summary.adversarial}</span>
                            <span className="rt-summary-label">Attacks Blocked</span>
                        </div>
                        <div className="rt-summary-stat">
                            <span className="rt-summary-value">{summary.total - summary.adversarial}</span>
                            <span className="rt-summary-label">Benign Passed</span>
                        </div>
                        <div className="rt-summary-compliance">
                            {summary.owasp_pass
                                ? 'OWASP LLM threshold met (95%+ prevention)'
                                : 'Below OWASP threshold - tighten policies'}
                        </div>
                    </div>
                )}

                {results.length > 0 && (
                    <div className="rt-results">
                        {results.map(r => (
                            <div
                                key={r.id}
                                className={`rt-row ${expanded === r.id ? 'rt-row-open' : ''}`}
                                onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                            >
                                <div className="rt-row-main">
                                    <span className="rt-row-icon">{vectorIcon(r.vector)}</span>
                                    <span className="rt-row-id">{r.id}</span>
                                    <span className="rt-row-desc">{r.description}</span>
                                    <StatusBadge result={r} />
                                </div>
                                {expanded === r.id && (
                                    <div className="rt-row-detail">
                                        <div className="rt-detail-row">
                                            <span className="rt-detail-label">Vector</span>
                                            <span className="rt-detail-value">{r.vector}</span>
                                        </div>
                                        {r.blocked_by && (
                                            <div className="rt-detail-row">
                                                <span className="rt-detail-label">Blocked by</span>
                                                <span className="rt-detail-value rt-blocked-by">{r.blocked_by}</span>
                                            </div>
                                        )}
                                        {r.policy_action && r.policy_action !== 'error' && (
                                            <div className="rt-detail-row">
                                                <span className="rt-detail-label">Policy Decision</span>
                                                <span className="rt-detail-value">{r.policy_action} (Risk: {r.policy_risk})</span>
                                            </div>
                                        )}
                                        {r.pii_scrubbed && (
                                            <div className="rt-detail-row">
                                                <span className="rt-detail-label">PII</span>
                                                <span className="rt-detail-value rt-pii">Scrubbed by Presidio</span>
                                            </div>
                                        )}
                                        <div className="rt-detail-row">
                                            <span className="rt-detail-label">Payload preview</span>
                                            <code className="rt-payload-preview">{r.preview}</code>
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}

                {!running && !done && (
                    <div className="rt-empty">
                        <p>Press <strong>Run Red Team Scan</strong> to fire all 11 OWASP payloads through the gateway.</p>
                    </div>
                )}
            </div>
        </section>
    )
}
