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
        { time: 'Live', agent: 'AgentVault Gateway', event: 'Gateway protection layers active', status: 'cleared' },
        { time: 'Ready', agent: 'Red Team Harness', event: '11 OWASP LLM payloads available for gateway testing', status: 'blocked' },
        { time: 'Ready', agent: 'MCP Interceptor', event: 'Secure call_tool() wrapper available for MCP clients', status: 'scrubbed' },
        { time: 'Live', agent: 'Observability', event: 'Metrics, traces, and safe security events wired into the gateway', status: 'cleared' },
    ]

    return (
        <section className="dashboard" id="dashboard">
            <div className="container">
                <header className="section-header">
                    <h2>Security Operations Dashboard</h2>
                    <p>Real-time visibility into your agent infrastructure's security posture.</p>
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
