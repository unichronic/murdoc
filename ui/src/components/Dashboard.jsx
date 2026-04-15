import React from 'react'
import './Dashboard.css'

export default function Dashboard() {
    const stats = [
        { label: 'Total Scans', value: '12,482' },
        { label: 'Threats Blocked', value: '142' },
        { label: 'PII Redacted', value: '2,891' },
        { label: 'Active Agents', value: '12' },
    ]

    const activities = [
        { time: '2 mins ago', agent: 'SupportBot-01', event: 'Prompt Injection Blocked', status: 'blocked' },
        { time: '15 mins ago', agent: 'DevAssist-v2', event: 'PII Scrubbed from Output', status: 'scrubbed' },
        { time: '24 mins ago', agent: 'MarketingWriter', event: 'Clean Interaction', status: 'cleared' },
        { time: '1 hour ago', agent: 'SupportBot-01', event: 'Prompt Injection Blocked', status: 'blocked' },
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
                        <h3>Recent Security Events</h3>
                        <span className="badge badge-safe">Live Feed</span>
                    </div>
                    <ul className="activity-list">
                        {activities.map((act, i) => (
                            <li key={i} className="activity-item">
                                <div className={`status-dot status-${act.status}`}></div>
                                <div className="activity-info">
                                    <strong>{act.agent}</strong> — {act.event}
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
