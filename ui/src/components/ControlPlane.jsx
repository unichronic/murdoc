import { useEffect, useMemo, useState } from 'react'
import { getJson, putJson } from '../lib/controlPlaneApi'
import './ControlPlane.css'

const GUARDRAIL_LABELS = {
    lakera: 'Prompt attack scanner',
    presidio: 'Sensitive data scanner',
    policy: 'Policy engine',
    nemo: 'Semantic guardrails',
}

const GUARDRAIL_MODES = ['disabled', 'advisory', 'advisory_high_risk', 'enforce']
const GATEWAY_ROUTE_KINDS = ['llm_openai', 'http_tool', 'agent_http']
const CONTROL_SECTIONS = [
    { id: 'routing', label: 'Routing', note: 'Register model, tool, and agent upstreams.' },
    { id: 'protection', label: 'Protection', note: 'Tune guardrail modes and non-secret runtime behavior.' },
]

const PROFILE_GUIDE = {
    'default-agent': {
        label: 'Default agent traffic',
        use: 'General agent requests where the risk level is mixed or not yet classified.',
        posture: 'Balanced checks with prompt, data, policy, and semantic review enabled.',
    },
    'read-only-low-risk': {
        label: 'Read-only low risk',
        use: 'Summaries, lookups, and answer-only workflows that should not change systems.',
        posture: 'Lower latency, higher rate limit, and caching for safe read-only traffic.',
    },
    'tool-write': {
        label: 'Tool or write actions',
        use: 'Workflows that update tickets, write memory, send messages, or call tools.',
        posture: 'Stricter policy path with caching disabled for state-changing actions.',
    },
    'admin-high-impact': {
        label: 'High-impact admin actions',
        use: 'Approved exports, external sends, privileged operations, and sensitive changes.',
        posture: 'Strictest default posture with tighter rate limits and enforced semantic checks.',
    },
    'mcp-tool': {
        label: 'MCP tool traffic',
        use: 'MCP tool discovery, tool calls, and tool-result inspection.',
        posture: 'Tool-focused checks with semantic review and no read cache.',
    },
}

const HELP = {
    route_profile: 'Route profiles define how a class of traffic is protected. Gateway routes attach to one profile.',
    runtime_settings: 'Runtime settings are non-secret global defaults for the gateway runtime.',
    prompt_threshold: 'Higher values reduce prompt-scanner sensitivity. Keep this conservative until false positives are understood.',
    policy_timeout: 'Maximum time Murdoc waits for policy evaluation before applying fail-open or fail-closed behavior.',
    require_prompt_scanner: 'When enabled, Murdoc blocks if the prompt scanner is unavailable.',
    semantic_required: 'When enabled, Murdoc treats semantic guardrail availability as required.',
    semantic_enforce: 'When enabled, semantic guardrail blocks are enforced globally instead of advisory.',
    fail_closed: 'When enabled, policy-service errors block requests instead of allowing them.',
    gateway_route: 'Gateway routes expose upstream models, tools, or agents through Murdoc.',
    strip_prefix: 'For proxy routes, forward the request path without the gateway route prefix.',
}

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

function Info({ text }) {
    return (
        <span className="cp-info" title={text} aria-label={text} tabIndex="0">
            i
        </span>
    )
}

export default function ControlPlane() {
    const [profiles, setProfiles] = useState([])
    const [selectedRoute, setSelectedRoute] = useState('default-agent')
    const [profileDraft, setProfileDraft] = useState(null)
    const [gatewayRoutes, setGatewayRoutes] = useState([])
    const [selectedGatewayRoute, setSelectedGatewayRoute] = useState('default-llm')
    const [gatewayRouteDraft, setGatewayRouteDraft] = useState(DEFAULT_GATEWAY_ROUTE)
    const [runtimeSettings, setRuntimeSettings] = useState(DEFAULT_RUNTIME_SETTINGS)
    const [status, setStatus] = useState('')
    const [activeSection, setActiveSection] = useState('routing')

    const selectedProfile = useMemo(
        () => profiles.find(item => item.route_id === selectedRoute) || profiles[0],
        [profiles, selectedRoute],
    )

    const selectedGatewayRouteRecord = useMemo(
        () => gatewayRoutes.find(item => item.route_id === selectedGatewayRoute),
        [gatewayRoutes, selectedGatewayRoute],
    )

    const loadControlPlane = async () => {
        const [profilesPayload, gatewayRoutesPayload, runtimePayload] = await Promise.all([
            getJson('/api/control-plane/profiles'),
            getJson('/api/control-plane/gateway-routes'),
            getJson('/api/control-plane/runtime-settings'),
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
        setRuntimeSettings({ ...DEFAULT_RUNTIME_SETTINGS, ...runtimePayload })
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
        try {
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
        } catch (error) {
            setStatus(`Could not save route profile: ${error.message}`)
        }
    }

    const saveRuntimeSettings = async () => {
        setStatus('Saving runtime settings...')
        try {
            const saved = await putJson('/api/control-plane/runtime-settings', runtimeSettings)
            setRuntimeSettings(saved)
            setStatus('Runtime settings saved.')
        } catch (error) {
            setStatus(`Could not save runtime settings: ${error.message}`)
        }
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
        try {
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
        } catch (error) {
            setStatus(`Could not save gateway route: ${error.message}`)
        }
    }

    if (!profileDraft) {
        return (
            <section className="control-plane" id="control-plane">
                <div className="container">Loading control plane...</div>
            </section>
        )
    }

    return (
        <section className="control-plane" id="control-plane">
            <div className="container">
                <header className="section-header cp-header">
                    <div>
                        <h2>Control Plane</h2>
                        <p>Configure what agents can reach and how gateway traffic is protected.</p>
                    </div>
                    <div className="cp-header-tools">
                        {status && <span className="cp-status">{status}</span>}
                    </div>
                </header>

                <div className="cp-tabs" role="tablist" aria-label="Control plane sections">
                    {CONTROL_SECTIONS.map(section => (
                        <button
                            key={section.id}
                            type="button"
                            className={`cp-tab ${activeSection === section.id ? 'cp-tab-active' : ''}`}
                            onClick={() => setActiveSection(section.id)}
                        >
                            <span>{section.label}</span>
                            <small>{section.note}</small>
                        </button>
                    ))}
                </div>

                <div className={`cp-grid cp-grid-${activeSection}`}>
                    {activeSection === 'protection' && (
                        <>
                    <div className="cp-panel">
                        <div className="cp-panel-title">
                            <div>
                                <h3>Route Profile <Info text={HELP.route_profile} /></h3>
                                <p>Choose the default protection posture for a route or agent workflow.</p>
                            </div>
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

                        <div className="cp-profile-guide">
                            <div>
                                <span className="cp-guide-kicker">Profile guide</span>
                                <strong>{PROFILE_GUIDE[profileDraft.route_id]?.label || 'Custom profile'}</strong>
                                <p>{PROFILE_GUIDE[profileDraft.route_id]?.use || 'Custom protection profile for a specific route or workflow.'}</p>
                            </div>
                            <div>
                                <span className="cp-guide-kicker">Posture</span>
                                <p>{PROFILE_GUIDE[profileDraft.route_id]?.posture || 'Use the guardrail, rate, latency, and cache controls below to define this profile.'}</p>
                            </div>
                        </div>

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
                            <div>
                                <h3>Runtime Settings <Info text={HELP.runtime_settings} /></h3>
                                <p>Global non-secret switches. Keep these conservative for production-like tests.</p>
                            </div>
                            <span className="cp-pill">Non-secret</span>
                        </div>

                        <div className="cp-inline-fields">
                            <label className="cp-field">
                                <span>Prompt threshold <Info text={HELP.prompt_threshold} /></span>
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
                                <span>Policy timeout seconds <Info text={HELP.policy_timeout} /></span>
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
                                <span>Require prompt scanner <Info text={HELP.require_prompt_scanner} /></span>
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
                                <span>Require semantic guardrails <Info text={HELP.semantic_required} /></span>
                            </label>
                            <label className="cp-check">
                                <input
                                    type="checkbox"
                                    checked={Boolean(runtimeSettings.nemo_guardrails_enforce)}
                                    onChange={event => setRuntimeSettings({ ...runtimeSettings, nemo_guardrails_enforce: event.target.checked })}
                                />
                                <span>Enforce semantic blocks globally <Info text={HELP.semantic_enforce} /></span>
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
                                <span>Fail closed when policy service is unavailable <Info text={HELP.fail_closed} /></span>
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
                        </>
                    )}

                    {activeSection === 'routing' && (
                    <div className="cp-panel">
                        <div className="cp-panel-title">
                            <div>
                                <h3>Gateway Route <Info text={HELP.gateway_route} /></h3>
                                <p>Register one upstream and attach it to a protection profile.</p>
                            </div>
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
                            <span>Upstream</span>
                            <input
                                value={gatewayRouteDraft.upstream_url || ''}
                                placeholder="Model or service destination"
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
                            <span>Forward without gateway prefix <Info text={HELP.strip_prefix} /></span>
                        </label>

                        <div className="cp-actions">
                            <button type="button" className="cp-button" onClick={saveGatewayRoute}>Save gateway route</button>
                            <button type="button" className="cp-button cp-button-secondary" onClick={newGatewayRoute}>New route</button>
                        </div>
                    </div>
                    )}

                </div>
            </div>
        </section>
    )
}
