import { useEffect, useState } from 'react'
import { postJson } from '../lib/controlPlaneApi'
import './AuthStatus.css'

export default function AuthStatus({ onAuthChange = () => { }, variant = 'compact' }) {
    const [authRequired, setAuthRequired] = useState(false)
    const [authenticated, setAuthenticated] = useState(false)
    const [password, setPassword] = useState('')
    const [status, setStatus] = useState('Checking access...')
    const [busy, setBusy] = useState(false)

    const refresh = () => {
        return fetch('/api/auth/me', { credentials: 'same-origin' })
            .then(response => response.ok ? response.json() : Promise.reject(new Error(`${response.status} ${response.statusText}`)))
            .then(payload => {
                setAuthRequired(Boolean(payload.auth_required))
                setAuthenticated(Boolean(payload.authenticated))
                onAuthChange({
                    authRequired: Boolean(payload.auth_required),
                    authenticated: Boolean(payload.authenticated),
                })
                setStatus('')
            })
            .catch(error => setStatus(`Access check failed: ${error.message}`))
    }

    useEffect(() => {
        refresh()
    }, [])

    const signIn = async (event) => {
        event.preventDefault()
        setBusy(true)
        setStatus('Signing in...')
        try {
            const payload = await postJson('/api/auth/login', { password })
            const nextAuthenticated = Boolean(payload.authenticated)
            setAuthenticated(nextAuthenticated)
            onAuthChange({ authRequired, authenticated: nextAuthenticated })
            setPassword('')
            setStatus('')
        } catch (error) {
            setStatus('Sign in failed.')
        } finally {
            setBusy(false)
        }
    }

    const signOut = async () => {
        setBusy(true)
        try {
            await postJson('/api/auth/logout')
            setAuthenticated(false)
            onAuthChange({ authRequired, authenticated: false })
        } finally {
            setBusy(false)
        }
    }

    return (
        <div className={`auth-status auth-status-${variant} ${authenticated ? 'auth-status-ok' : 'auth-status-required'}`}>
            <div className="auth-status-copy">
                <span className="auth-status-label">
                    {authRequired ? (authenticated ? 'Signed in' : 'Sign in to continue') : 'Local console'}
                </span>
                {variant === 'card' && (
                    <p>Use your console password to manage routes, policy behavior, observability, and attack-lab runs.</p>
                )}
                {!authRequired && <span className="auth-status-detail">Development access is open.</span>}
                {status && <span className="auth-status-detail">{status}</span>}
            </div>
            {authRequired && !authenticated && (
                <form className="auth-status-form" onSubmit={signIn}>
                    <input
                        type="password"
                        value={password}
                        placeholder="Password"
                        autoComplete="current-password"
                        onChange={event => setPassword(event.target.value)}
                    />
                    <button type="submit" disabled={busy || !password}>Sign in</button>
                </form>
            )}
            {authRequired && authenticated && (
                <button type="button" className="auth-status-link" onClick={signOut} disabled={busy}>
                    Sign out
                </button>
            )}
        </div>
    )
}
