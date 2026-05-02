import { useEffect, useMemo, useState } from 'react'
import './ControlPlane.css'

const GUARDRAIL_LABELS = {
    lakera: 'Prompt attack scanner',
    presidio: 'Sensitive data scanner',
    policy: 'Policy engine',
    nemo: 'Semantic guardrails',
}

const GUARDRAIL_MODES = ['disabled', 'advisory', 'advisory_high_risk', 'enforce']
const GATEWAY_ROUTE_KINDS = ['llm_openai', 'http_tool', 'agent_http']

const DEFAULT_GATEWAY_ROUTE = {
    route_id: 'default-llm',
    upstream_url: '',
    kind: 'llm_openai',
    profile_id: 'default-agent',
    description: '',
    strip_prefix: true,
    timeout_seconds: 30,
    owner: 'local',
}

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

const DEFAULT_RUNTIME_SETTINGS = {
    lakera_required: false,
    lakera_confidence_threshold: 0.8,
    lakera_breakdown: false,
    nemo_guardrails_enabled: false,
    nemo_guardrails_required: false,
    nemo_guardrails_enforce: false,
    nemo_guardrails_max_retries: 2,
    nemo_guardrails_retry_backoff_seconds: 2,
    nemo_guardrails_skip_low_risk_reads: true,
    opa_fail_closed: false,
    opa_timeout_seconds: 1,
}

async function getJson(path) {
    const response = await fetch(path)
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
    return response.json()
}

async function putJson(path, body) {
    const response = await fetch(path, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    })
    const payload = await response.json()
    if (!response.ok) throw new Error(payload.detail || `${response.status} ${response.statusText}`)
    return payload
}

export default function ControlPlane() {
    const [profiles, setProfiles] = useState([])
    const [selectedRoute, setSelectedRoute] = useState('default-agent')
    const [profileDraft, setProfileDraft] = useState(null)
    const [gatewayRoutes, setGatewayRoutes] = useState([])
    const [selectedGatewayRoute, setSelectedGatewayRoute] = useState('default-llm')
    const [gatewayRouteDraft, setGatewayRouteDraft] = useState(DEFAULT_GATEWAY_ROUTE)
    const [testConfig, setTestConfig] = useState(DEFAULT_TEST_CONFIG)
    const [runtimeSettings, setRuntimeSettings] = useState(DEFAULT_RUNTIME_SETTINGS)
    const [corpus, setCorpus] = useState(null)
    const [targets, setTargets] = useState([])
    const [status, setStatus] = useState('')
    const [runSummary, setRunSummary] = useState(null)
    const [runningLab, setRunningLab] = useState(false)

    const selectedProfile = useMemo(
        () => profiles.find(item => item.route_id === selectedRoute) || profiles[0],
        [profiles, selectedRoute],
    )

    const selectedGatewayRouteRecord = useMemo(
        () => gatewayRoutes.find(item => item.route_id === selectedGatewayRoute),
        [gatewayRoutes, selectedGatewayRoute],
    )

    const loadControlPlane = async () => {
        const [profilesPayload, gatewayRoutesPayload, configPayload, runtimePayload, corpusPayload, targetsPayload] = await Promise.all([
            getJson('/api/control-plane/profiles'),
            getJson('/api/control-plane/gateway-routes'),
            getJson('/api/control-plane/test-config'),
            getJson('/api/control-plane/runtime-settings'),
            getJson('/api/control-plane/test-corpus'),
            getJson('/api/control-plane/test-targets'),
        ])
        const loadedProfiles = profilesPayload.profiles || []
        const loadedGatewayRoutes = gatewayRoutesPayload.routes || []
        setProfiles(loadedProfiles)
        setGatewayRoutes(loadedGatewayRoutes)
        if (loadedGatewayRoutes[0]) {
            setSelectedGatewayRoute(loadedGatewayRoutes[0].route_id)
        } else {
            setSelectedGatewayRoute('')
            setGatewayRouteDraft({
                ...DEFAULT_GATEWAY_ROUTE,
                profile_id: loadedProfiles[0]?.route_id || DEFAULT_GATEWAY_ROUTE.profile_id,
            })
        }
        setTestConfig({ ...DEFAULT_TEST_CONFIG, ...configPayload })
        setRuntimeSettings({ ...DEFAULT_RUNTIME_SETTINGS, ...runtimePayload })
        setCorpus(corpusPayload)
        setTargets(targetsPayload.targets || [])
    }

    useEffect(() => {
        loadControlPlane().catch(error => setStatus(`Control plane unavailable: ${error.message}`))
    }, [])

    useEffect(() => {
        if (selectedProfile) {
            setProfileDraft(JSON.parse(JSON.stringify(selectedProfile)))
        }
    }, [selectedProfile])

    useEffect(() => {
        if (selectedGatewayRouteRecord) {
            setGatewayRouteDraft(JSON.parse(JSON.stringify(selectedGatewayRouteRecord)))
        }
    }, [selectedGatewayRouteRecord])

    const updateGuardrail = (name, mode) => {
        setProfileDraft(draft => ({
            ...draft,
            guardrails: {
                ...(draft?.guardrails || {}),
                [name]: mode,
            },
        }))
    }

    const saveProfile = async () => {
        if (!profileDraft) return
        setStatus('Saving route profile...')
        const saved = await putJson(`/api/control-plane/profiles/${profileDraft.route_id}`, {
            description: profileDraft.description,
            guardrails: profileDraft.guardrails,
            policy_version: profileDraft.policy_version,
            latency_budget_ms: Number(profileDraft.latency_budget_ms),
            rate_limit_rpm: Number(profileDraft.rate_limit_rpm),
            monthly_budget_usd: Number(profileDraft.monthly_budget_usd),
            estimated_cost_per_1k_tokens_usd: Number(profileDraft.estimated_cost_per_1k_tokens_usd),
            cache_read_only: Boolean(profileDraft.cache_read_only),
            rollout: profileDraft.rollout,
            owner: profileDraft.owner,
        })
        setProfiles(items => items.map(item => item.route_id === saved.route_id ? saved : item))
        setProfileDraft(saved)
        setStatus('Route profile saved.')
    }

    const saveTestConfig = async () => {
        setStatus('Saving test configuration...')
        const saved = await putJson('/api/control-plane/test-config', testConfig)
        setTestConfig(saved)
        setStatus('Test configuration saved.')
    }

    const saveRuntimeSettings = async () => {
        setStatus('Saving runtime settings...')
        const saved = await putJson('/api/control-plane/runtime-settings', runtimeSettings)
        setRuntimeSettings(saved)
        setStatus('Runtime settings saved.')
    }

    const newGatewayRoute = () => {
        const profileId = profiles[0]?.route_id || DEFAULT_GATEWAY_ROUTE.profile_id
        setSelectedGatewayRoute('')
        setGatewayRouteDraft({
            ...DEFAULT_GATEWAY_ROUTE,
            route_id: 'new-route',
            profile_id: profileId,
        })
    }

    const saveGatewayRoute = async () => {
        const routeId = (gatewayRouteDraft.route_id || '').trim()
        if (!routeId || !gatewayRouteDraft.upstream_url) {
            setStatus('Gateway route id and upstream URL are required.')
            return
        }
        setStatus('Saving gateway route...')
        const saved = await putJson(`/api/control-plane/gateway-routes/${routeId}`, {
            upstream_url: gatewayRouteDraft.upstream_url,
            kind: gatewayRouteDraft.kind,
            profile_id: gatewayRouteDraft.profile_id,
            description: gatewayRouteDraft.description,
            strip_prefix: Boolean(gatewayRouteDraft.strip_prefix),
            timeout_seconds: Number(gatewayRouteDraft.timeout_seconds),
            owner: gatewayRouteDraft.owner,
        })
        setGatewayRoutes(items => {
            const exists = items.some(item => item.route_id === saved.route_id)
            return exists ? items.map(item => item.route_id === saved.route_id ? saved : item) : [...items, saved]
        })
        setSelectedGatewayRoute(saved.route_id)
        setGatewayRouteDraft(saved)
        setStatus('Gateway route saved.')
    }

    const runLab = async () => {
        setRunningLab(true)
        setRunSummary(null)
        setStatus('Starting local attack lab...')
        try {
            const response = await fetch('/api/control-plane/test-run', { method: 'POST' })
            const payload = await response.json()
            const summary = payload.result?.gateway_summary || payload.result?.raw_summary || null
            setRunSummary({ ok: payload.ok, returncode: payload.returncode, summary, stderr: payload.stderr })
            setStatus(payload.ok ? 'Attack lab completed.' : 'Attack lab returned failures.')
        } catch (error) {
            setStatus(`Attack lab failed: ${error.message}`)
        } finally {
            setRunningLab(false)
        }
    }

    if (!profileDraft) {
        return (
            <section className="control-plane" id="control-plane">
                <div className="container">Loading control plane...</div>
            </section>
        )
    }

    const corpusProfile = corpus?.profiles?.[testConfig.corpus_profile]

    return (
        <section className="control-plane" id="control-plane">
            <div className="container">
                <header className="section-header cp-header">
                    <div>
                        <h2>Control Plane</h2>
                        <p>Manage route behavior, red-team corpus selection, and local target runs from one place.</p>
                    </div>
                    {status && <span className="cp-status">{status}</span>}
                </header>

                <div className="cp-grid">
                    <div className="cp-panel">
                        <div className="cp-panel-title">
                            <h3>Route Profile</h3>
                            <select value={selectedRoute} onChange={event => setSelectedRoute(event.target.value)}>
                                {profiles.map(profile => (
                                    <option key={profile.route_id} value={profile.route_id}>{profile.route_id}</option>
                                ))}
                            </select>
                        </div>

                        <label className="cp-field">
                            <span>Description</span>
                            <input
                                value={profileDraft.description || ''}
                                onChange={event => setProfileDraft({ ...profileDraft, description: event.target.value })}
                            />
                        </label>

                        <div className="cp-guardrails">
                            {Object.entries(GUARDRAIL_LABELS).map(([name, label]) => (
                                <label key={name} className="cp-field">
                                    <span>{label}</span>
                                    <select
                                        value={profileDraft.guardrails?.[name] || 'enforce'}
                                        onChange={event => updateGuardrail(name, event.target.value)}
                                    >
                                        {GUARDRAIL_MODES.map(mode => (
                                            <option key={mode} value={mode}>{mode.replaceAll('_', ' ')}</option>
                                        ))}
                                    </select>
                                </label>
                            ))}
                        </div>

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Latency budget ms</span>
                                <input
                                    type="number"
                                    min="100"
                                    value={profileDraft.latency_budget_ms}
                                    onChange={event => setProfileDraft({ ...profileDraft, latency_budget_ms: event.target.value })}
                                />
                            </label>
                            <label className="cp-field">
                                <span>Rate limit rpm</span>
                                <input
                                    type="number"
                                    min="1"
                                    value={profileDraft.rate_limit_rpm}
                                    onChange={event => setProfileDraft({ ...profileDraft, rate_limit_rpm: event.target.value })}
                                />
                            </label>
                        </div>

                        <label className="cp-check">
                            <input
                                type="checkbox"
                                checked={Boolean(profileDraft.cache_read_only)}
                                onChange={event => setProfileDraft({ ...profileDraft, cache_read_only: event.target.checked })}
                            />
                            <span>Cache low-risk read-only requests</span>
                        </label>

                        <button type="button" className="cp-button" onClick={saveProfile}>Save profile</button>
                    </div>

                    <div className="cp-panel">
                        <div className="cp-panel-title">
                            <h3>Runtime Settings</h3>
                            <span className="cp-pill">Non-secret</span>
                        </div>

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Prompt threshold</span>
                                <input
                                    type="number"
                                    min="0"
                                    max="1"
                                    step="0.01"
                                    value={runtimeSettings.lakera_confidence_threshold}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, lakera_confidence_threshold: Number(event.target.value) })}
                                />
                            </label>
                            <label className="cp-field">
                                <span>Policy timeout seconds</span>
                                <input
                                    type="number"
                                    min="0.05"
                                    max="30"
                                    step="0.05"
                                    value={runtimeSettings.opa_timeout_seconds}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, opa_timeout_seconds: Number(event.target.value) })}
                                />
                            </label>
                        </div>

                        <div className="cp-check-grid">
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.lakera_required)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, lakera_required: event.target.checked })}
                                />
                                <span>Require prompt scanner</span>
                            </label>
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.lakera_breakdown)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, lakera_breakdown: event.target.checked })}
                                />
                                <span>Request prompt breakdown</span>
                            </label>
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.nemo_guardrails_enabled)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, nemo_guardrails_enabled: event.target.checked })}
                                />
                                <span>Enable semantic guardrails</span>
                            </label>
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.nemo_guardrails_required)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, nemo_guardrails_required: event.target.checked })}
                                />
                                <span>Require semantic guardrails</span>
                            </label>
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.nemo_guardrails_enforce)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, nemo_guardrails_enforce: event.target.checked })}
                                />
                                <span>Enforce semantic blocks globally</span>
                            </label>
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.nemo_guardrails_skip_low_risk_reads)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, nemo_guardrails_skip_low_risk_reads: event.target.checked })}
                                />
                                <span>Skip semantic checks on low-risk reads</span>
                            </label>
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.opa_fail_closed)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, opa_fail_closed: event.target.checked })}
                                />
                                <span>Fail closed when policy service is unavailable</span>
                            </label>
                        </div>

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Semantic retries</span>
                                <input
                                    type="number"
                                    min="0"
                                    max="5"
                                    value={runtimeSettings.nemo_guardrails_max_retries}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, nemo_guardrails_max_retries: Number(event.target.value) })}
                                />
                            </label>
                            <label className="cp-field">
                                <span>Retry backoff seconds</span>
                                <input
                                    type="number"
                                    min="0"
                                    max="30"
                                    step="0.5"
                                    value={runtimeSettings.nemo_guardrails_retry_backoff_seconds}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, nemo_guardrails_retry_backoff_seconds: Number(event.target.value) })}
                                />
                            </label>
                        </div>

                        <button type="button" className="cp-button" onClick={saveRuntimeSettings}>Save runtime settings</button>
                    </div>

                    <div className="cp-panel">
                        <div className="cp-panel-title">
                            <h3>Gateway Route</h3>
                            <select
                                value={selectedGatewayRoute}
                                onChange={event => setSelectedGatewayRoute(event.target.value)}
                                disabled={gatewayRoutes.length === 0}
                            >
                                {!selectedGatewayRoute && <option value="">new route</option>}
                                {gatewayRoutes.map(route => (
                                    <option key={route.route_id} value={route.route_id}>{route.route_id}</option>
                                ))}
                            </select>
                        </div>

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Route ID</span>
                                <input
                                    value={gatewayRouteDraft.route_id || ''}
                                    onChange={event => setGatewayRouteDraft({ ...gatewayRouteDraft, route_id: event.target.value })}
                                />
                            </label>
                            <label className="cp-field">
                                <span>Mode</span>
                                <select
                                    value={gatewayRouteDraft.kind || 'http_tool'}
                                    onChange={event => setGatewayRouteDraft({ ...gatewayRouteDraft, kind: event.target.value })}
                                >
                                    {GATEWAY_ROUTE_KINDS.map(kind => (
                                        <option key={kind} value={kind}>{kind.replaceAll('_', ' ')}</option>
                                    ))}
                                </select>
                            </label>
                        </div>

                        <label className="cp-field cp-spaced-field">
                            <span>Upstream URL</span>
                            <input
                                value={gatewayRouteDraft.upstream_url || ''}
                                placeholder="https://api.openai.com"
                                onChange={event => setGatewayRouteDraft({ ...gatewayRouteDraft, upstream_url: event.target.value })}
                            />
                        </label>

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Profile</span>
                                <select
                                    value={gatewayRouteDraft.profile_id || 'default-agent'}
                                    onChange={event => setGatewayRouteDraft({ ...gatewayRouteDraft, profile_id: event.target.value })}
                                >
                                    {profiles.map(profile => (
                                        <option key={profile.route_id} value={profile.route_id}>{profile.route_id}</option>
                                    ))}
                                </select>
                            </label>
                            <label className="cp-field">
                                <span>Timeout seconds</span>
                                <input
                                    type="number"
                                    min="0.1"
                                    max="300"
                                    step="0.5"
                                    value={gatewayRouteDraft.timeout_seconds || 30}
                                    onChange={event => setGatewayRouteDraft({ ...gatewayRouteDraft, timeout_seconds: Number(event.target.value) })}
                                />
                            </label>
                        </div>

                        <label className="cp-field cp-spaced-field">
                            <span>Description</span>
                            <input
                                value={gatewayRouteDraft.description || ''}
                                onChange={event => setGatewayRouteDraft({ ...gatewayRouteDraft, description: event.target.value })}
                            />
                        </label>

                        <label className="cp-check">
                            <input
                                type="checkbox"
                                checked={Boolean(gatewayRouteDraft.strip_prefix)}
                                onChange={event => setGatewayRouteDraft({ ...gatewayRouteDraft, strip_prefix: event.target.checked })}
                            />
                            <span>Strip /proxy route prefix before forwarding</span>
                        </label>

                        <div className="cp-actions">
                            <button type="button" className="cp-button" onClick={saveGatewayRoute}>Save gateway route</button>
                            <button type="button" className="cp-button cp-button-secondary" onClick={newGatewayRoute}>New route</button>
                        </div>
                    </div>

                    <div className="cp-panel">
                        <div className="cp-panel-title">
                            <h3>Attack Lab</h3>
                            <span className="cp-pill">Local targets</span>
                        </div>

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Corpus</span>
                                <select
                                    value={testConfig.corpus_profile}
                                    onChange={event => setTestConfig({ ...testConfig, corpus_profile: event.target.value })}
                                >
                                    <option value="baseline">baseline</option>
                                    <option value="extended">extended</option>
                                </select>
                            </label>
                            <label className="cp-field">
                                <span>Target</span>
                                <select
                                    value={testConfig.target}
                                    onChange={event => setTestConfig({ ...testConfig, target: event.target.value })}
                                >
                                    {targets.map(target => (
                                        <option key={target.id} value={target.id}>{target.label}</option>
                                    ))}
                                </select>
                            </label>
                        </div>

                        {corpusProfile && (
                            <div className="cp-corpus-summary">
                                <span>{corpusProfile.payloads} payloads</span>
                                <span>{corpusProfile.adversarial} adversarial</span>
                                <span>{corpusProfile.benign} benign</span>
                                <span>{corpus?.stateful_scenarios?.length || 0} stateful scenarios</span>
                            </div>
                        )}

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Mode</span>
                                <select
                                    value={testConfig.mode}
                                    onChange={event => setTestConfig({ ...testConfig, mode: event.target.value })}
                                >
                                    <option value="gateway">gateway</option>
                                    <option value="raw">raw</option>
                                    <option value="compare">compare</option>
                                </select>
                            </label>
                            <label className="cp-field">
                                <span>Iterations</span>
                                <input
                                    type="number"
                                    min="1"
                                    max="20"
                                    value={testConfig.iterations}
                                    onChange={event => setTestConfig({ ...testConfig, iterations: Number(event.target.value) })}
                                />
                            </label>
                            <label className="cp-field">
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

                        <label className="cp-check">
                            <input
                                type="checkbox"
                                checked={Boolean(testConfig.include_stateful)}
                                onChange={event => setTestConfig({ ...testConfig, include_stateful: event.target.checked })}
                            />
                            <span>Include stateful scenarios</span>
                        </label>
                        <label className="cp-check">
                            <input
                                type="checkbox"
                                checked={Boolean(testConfig.run_a2a_scanner)}
                                onChange={event => setTestConfig({ ...testConfig, run_a2a_scanner: event.target.checked })}
                            />
                            <span>Run agent-to-agent scanner when available</span>
                        </label>

                        <div className="cp-actions">
                            <button type="button" className="cp-button" onClick={saveTestConfig}>Save test setup</button>
                            <button type="button" className="cp-button cp-button-secondary" onClick={runLab} disabled={runningLab}>
                                {runningLab ? 'Running lab...' : 'Run lab'}
                            </button>
                        </div>

                        {runSummary && (
                            <div className={`cp-run-summary ${runSummary.ok ? 'cp-run-pass' : 'cp-run-fail'}`}>
                                <strong>{runSummary.ok ? 'Completed' : 'Failed'}</strong>
                                {runSummary.summary && (
                                    <span>
                                        {runSummary.summary.prevention_rate}% prevention, {runSummary.summary.false_positives} false positives, {runSummary.summary.errors} errors
                                    </span>
                                )}
                                {!runSummary.ok && runSummary.stderr && <code>{runSummary.stderr}</code>}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </section>
    )
}
