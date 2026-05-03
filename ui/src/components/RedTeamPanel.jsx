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

export default function RedTeamPanel({
    embedded = false,
    title = 'Automated Red Teaming',
    description = 'Run adversarial payloads through the Murdoc Gateway and review which requests were blocked by policy or bypassed for further tuning.',
    buttonLabel = 'Run Red Team Scan',
}) {
    const [running, setRunning] = useState(false)
    const [done, setDone] = useState(false)
    const [results, setResults] = useState([])
    const [summary, setSummary] = useState(null)
    const [expanded, setExpanded] = useState(null)

    const falsePositiveCount = results.filter(result => result.should_pass && result.blocked).length
    const opaUnavailable = results.some(result => String(result.blocked_by || '').includes('opa_unavailable'))

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

    const content = (
        <>
                <header className="rt-header">
                    <div className="rt-title-row">
                        <h2>{title}</h2>
                        <span className="rt-badge-label">OWASP LLM Top 10</span>
                    </div>
                    <p>{description}</p>
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
                            buttonLabel
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
                            <span className="rt-summary-value">{Math.max(0, summary.total - summary.adversarial - falsePositiveCount)}</span>
                            <span className="rt-summary-label">Benign Passed</span>
                        </div>
                        <div className="rt-summary-stat">
                            <span className="rt-summary-value">{falsePositiveCount}</span>
                            <span className="rt-summary-label">False Positives</span>
                        </div>
                        <div className="rt-summary-compliance">
                            {summary.owasp_pass
                                ? 'OWASP LLM threshold met (95%+ prevention)'
                                : 'Below OWASP threshold - tighten policies'}
                        </div>
                    </div>
                )}

                {opaUnavailable && (
                    <div className="rt-warning">
                        Policy service is unreachable and fail-closed is blocking benign requests. Start OPA, clear OPA_POLICY_URL for local testing, or turn off fail-closed before trusting this scan.
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
                        <p>Press <strong>{buttonLabel}</strong> to test adversarial payloads through the gateway.</p>
                    </div>
                )}
        </>
    )

    if (embedded) {
        return (
            <div className="red-team-panel red-team-panel-embedded" id="red-team">
                {content}
            </div>
        )
    }

    return (
        <section className="red-team-panel" id="red-team">
            <div className="container">{content}</div>
        </section>
    )
}
