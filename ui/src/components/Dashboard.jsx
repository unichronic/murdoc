import { useState, useEffect } from 'react'
import './Dashboard.css'

function useStats() {
    const [stats, setStats] = useState({
        total_requests: 0,
        threats_blocked: 0,
        pii_entities_redacted: 0,
        source: 'loading',
    })

    useEffect(() => {
        const fetch_ = async () => {
            try {
                const r = await fetch('/api/stats')
                if (r.ok) setStats(await r.json())
            } catch { }
        }
        fetch_()
        const id = setInterval(fetch_, 5000)
        return () => clearInterval(id)
    }, [])

    return stats
}

export default function Dashboard() {
    const liveStats = useStats()

    const stats = [
        { label: 'Total Requests', value: liveStats.total_requests || '-' },
        { label: 'Threats Blocked', value: liveStats.threats_blocked || '-' },
        { label: 'PII Entities Redacted', value: liveStats.pii_entities_redacted || '-' },
        { label: 'Security Layers Active', value: 4 },
    ]

    const activities = [
        { time: 'Live', agent: 'Murdoc Gateway', event: 'Shared security runtime active across agent traffic', status: 'cleared' },
        { time: 'Ready', agent: 'Attack Lab', event: 'OWASP LLM payloads available for gateway regression testing', status: 'blocked' },
        { time: 'Ready', agent: 'MCP Gateway', event: 'Tool discovery, tool calls, and tool output can be inspected', status: 'scrubbed' },
        { time: 'Live', agent: 'Observability', event: 'Metrics, audit summaries, and security events wired into the gateway', status: 'cleared' },
    ]

    return (
        <section className="dashboard" id="dashboard">
            <div className="container">
                <header className="section-header">
                    <h2>Gateway Security Dashboard</h2>
                    <p>Visibility into agent traffic, policy decisions, redaction, and attack-lab results.</p>
                </header>

                <div className="dashboard-grid">
                    {stats.map((stat, i) => (
                        <div key={i} className="stat-card">
                            <span className="stat-value">{stat.value}</span>
                            <span className="stat-label">{stat.label}</span>
                        </div>
                    ))}
                </div>

                <div className="recent-activity">
                    <div className="activity-header">
                        <h3>System Status</h3>
                        <span className="badge badge-safe">Gateway Live</span>
                    </div>
                    <ul className="activity-list">
                        {activities.map((act, i) => (
                            <li key={i} className="activity-item">
                                <div className={`status-dot status-${act.status}`}></div>
                                <div className="activity-info">
                                    <strong>{act.agent}</strong> - {act.event}
                                </div>
                                <div className="activity-time">{act.time}</div>
                            </li>
                        ))}
                    </ul>
                </div>
            </div>
        </section>
    )
}
