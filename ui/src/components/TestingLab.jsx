import { useEffect, useMemo, useState } from 'react'
import RedTeamPanel from './RedTeamPanel'
import {
    getJson,
    putJson,
} from '../lib/controlPlaneApi'
import './TestingLab.css'

const DEFAULT_TEST_CONFIG = {
    corpus_profile: 'baseline',
    target: 'agno',
    mode: 'gateway',
    iterations: 1,
    concurrency: 1,
    duration_seconds: 0,
    include_stateful: false,
    run_a2a_scanner: false,
    real_services: false,
}

function Info({ text }) {
    return (
        <span className="tl-info" title={text} aria-label={text} tabIndex="0">
            i
        </span>
    )
}

export default function TestingLab() {
    const [testConfig, setTestConfig] = useState(DEFAULT_TEST_CONFIG)
    const [corpus, setCorpus] = useState(null)
    const [targets, setTargets] = useState([])
    const [status, setStatus] = useState('')
    const [runSummary, setRunSummary] = useState(null)
    const [runningLab, setRunningLab] = useState(false)

    const corpusProfile = useMemo(
        () => corpus?.profiles?.[testConfig.corpus_profile],
        [corpus, testConfig.corpus_profile],
    )

    const loadTestingConfig = async () => {
        const [configPayload, corpusPayload, targetsPayload] = await Promise.all([
            getJson('/api/control-plane/test-config'),
            getJson('/api/control-plane/test-corpus'),
            getJson('/api/control-plane/test-targets'),
        ])
        setTestConfig({ ...DEFAULT_TEST_CONFIG, ...configPayload })
        setCorpus(corpusPayload)
        setTargets(targetsPayload.targets || [])
    }

    useEffect(() => {
        loadTestingConfig().catch(error => setStatus(`Testing controls unavailable: ${error.message}`))
    }, [])

    const saveTestConfig = async () => {
        setStatus('Saving test setup...')
        try {
            const saved = await putJson('/api/control-plane/test-config', testConfig)
            setTestConfig(saved)
            setStatus('Test setup saved.')
            return saved
        } catch (error) {
            setStatus(`Could not save test setup: ${error.message}`)
        }
    }

    const runLab = async () => {
        setRunningLab(true)
        setRunSummary(null)
        setStatus('Saving setup and starting attack lab...')
        try {
            await putJson('/api/control-plane/test-config', testConfig)
            const response = await fetch('/api/control-plane/test-run', {
                method: 'POST',
                credentials: 'same-origin',
            })
            const payload = await response.json()
            if (!response.ok) throw new Error(payload.detail || `${response.status} ${response.statusText}`)
            const summary = payload.result?.gateway_summary || payload.result?.raw_summary || null
            setRunSummary({ ok: payload.ok, returncode: payload.returncode, summary, stderr: payload.stderr })
            setStatus(payload.ok ? 'Attack lab completed.' : 'Attack lab returned failures.')
        } catch (error) {
            setStatus(`Attack lab failed: ${error.message}`)
        } finally {
            setRunningLab(false)
        }
    }

    return (
        <section className="testing-lab" id="testing-lab">
            <div className="container">
                <header className="section-header tl-header">
                    <div>
                        <h2>Attack Lab</h2>
                        <p>Run the active attack corpus through Murdoc with either a quick scan or a configured regression run.</p>
                    </div>
                    <div className="tl-header-tools">
                        {status && <span className="tl-status">{status}</span>}
                    </div>
                </header>

                <div className="tl-panel tl-attack-panel">
                        <div className="tl-panel-title">
                            <div>
                                <h3>Configured Run <Info text="Runs the saved local regression harness against the selected target and gateway mode." /></h3>
                                <p>Use this after route or protection changes when you need repeatable results.</p>
                            </div>
                            <span className="tl-pill">Local targets</span>
                        </div>

                        <div className="tl-inline-fields">
                            <label className="tl-field">
                                <span>Corpus</span>
                                <select
                                    value={testConfig.corpus_profile}
                                    onChange={event => setTestConfig({ ...testConfig, corpus_profile: event.target.value })}
                                >
                                    <option value="baseline">baseline</option>
                                    <option value="extended">extended</option>
                                </select>
                            </label>
                            <label className="tl-field">
                                <span>Target</span>
                                <select
                                    value={testConfig.target}
                                    onChange={event => setTestConfig({ ...testConfig, target: event.target.value })}
                                >
                                    {targets.map(target => (
                                        <option key={target.id} value={target.id}>{target.label}</option>
                                    ))}
                                    {targets.length === 0 && <option value={testConfig.target}>{testConfig.target}</option>}
                                </select>
                            </label>
                        </div>

                        {corpusProfile && (
                            <div className="tl-corpus-summary">
                                <span>{corpusProfile.payloads} payloads</span>
                                <span>{corpusProfile.adversarial} adversarial</span>
                                <span>{corpusProfile.benign} benign</span>
                                <span>{corpus?.stateful_scenarios?.length || 0} stateful scenarios</span>
                            </div>
                        )}

                        <div className="tl-inline-fields tl-inline-fields-compact">
                            <label className="tl-field">
                                <span>Mode <Info text="gateway tests Murdoc only, raw bypasses Murdoc, compare runs both." /></span>
                                <select
                                    value={testConfig.mode}
                                    onChange={event => setTestConfig({ ...testConfig, mode: event.target.value })}
                                >
                                    <option value="gateway">gateway</option>
                                    <option value="raw">raw</option>
                                    <option value="compare">compare</option>
                                </select>
                            </label>
                            <label className="tl-field">
                                <span>Iterations</span>
                                <input
                                    type="number"
                                    min="1"
                                    max="20"
                                    value={testConfig.iterations}
                                    onChange={event => setTestConfig({ ...testConfig, iterations: Number(event.target.value) })}
                                />
                            </label>
                            <label className="tl-field">
                                <span>Concurrency</span>
                                <input
                                    type="number"
                                    min="1"
                                    max="16"
                                    value={testConfig.concurrency}
                                    onChange={event => setTestConfig({ ...testConfig, concurrency: Number(event.target.value) })}
                                />
                            </label>
                        </div>

                        <div className="tl-check-grid">
                            <label className="tl-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(testConfig.include_stateful)}
                                    onChange={event => setTestConfig({ ...testConfig, include_stateful: event.target.checked })}
                                />
                                <span>Include stateful scenarios</span>
                            </label>
                            <label className="tl-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(testConfig.run_a2a_scanner)}
                                    onChange={event => setTestConfig({ ...testConfig, run_a2a_scanner: event.target.checked })}
                                />
                                <span>Run agent-to-agent scanner when available</span>
                            </label>
                        </div>

                        <div className="tl-actions">
                            <button type="button" className="tl-button" onClick={saveTestConfig}>Save test setup</button>
                            <button type="button" className="tl-button tl-button-secondary" onClick={runLab} disabled={runningLab}>
                                {runningLab ? 'Running lab...' : 'Run configured lab'}
                            </button>
                        </div>

                        {runSummary && (
                            <div className={`tl-run-summary ${runSummary.ok ? 'tl-run-pass' : 'tl-run-fail'}`}>
                                <strong>{runSummary.ok ? 'Completed' : 'Failed'}</strong>
                                {runSummary.summary && (
                                    <span>
                                        {runSummary.summary.prevention_rate}% prevention, {runSummary.summary.false_positives} false positives, {runSummary.summary.errors} errors
                                    </span>
                                )}
                                {!runSummary.ok && runSummary.stderr && <code>{runSummary.stderr}</code>}
                            </div>
                        )}

                    <div className="tl-divider" />

                    <RedTeamPanel
                        embedded
                        title="Quick Corpus Scan"
                        description="Run the active corpus through the gateway immediately. This is the fast attack-lab smoke check before a configured run."
                        buttonLabel="Run quick scan"
                    />
                </div>
            </div>
        </section>
    )
}
