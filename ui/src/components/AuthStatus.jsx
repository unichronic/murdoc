import { useEffect, useState } from 'react'
import { postJson } from '../lib/controlPlaneApi'
import './AuthStatus.css'

export default function AuthStatus({ onAuthChange = () => { }, variant = 'compact' }) {
    const [authRequired, setAuthRequired] = useState(false)
    const [authenticated, setAuthenticated] = useState(false)
    const [supportsPassword, setSupportsPassword] = useState(true)
    const [authMode, setAuthMode] = useState('Console password')
    const [role, setRole] = useState('')
    const [password, setPassword] = useState('')
    const [status, setStatus] = useState('Checking access...')
    const [busy, setBusy] = useState(false)

    const refresh = () => {
        return fetch('/api/auth/me', { credentials: 'same-origin' })
            .then(response => response.ok ? response.json() : Promise.reject(new Error(`${response.status} ${response.statusText}`)))
            .then(payload => {
                setAuthRequired(Boolean(payload.auth_required))
                setAuthenticated(Boolean(payload.authenticated))
                setSupportsPassword(payload.supports_password !== false)
                setAuthMode(payload.mode || 'Console password')
                setRole(payload.role || '')
                onAuthChange({
                    authRequired: Boolean(payload.auth_required),
                    authenticated: Boolean(payload.authenticated),
                    role: payload.role || '',
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
            setRole(payload.role || '')
            onAuthChange({ authRequired, authenticated: nextAuthenticated, role: payload.role || '' })
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
            setRole('')
            onAuthChange({ authRequired, authenticated: false, role: '' })
        } finally {
            setBusy(false)
        }
    }

    return (
        <div className={`auth-status auth-status-${variant} ${authenticated ? 'auth-status-ok' : 'auth-status-required'}`}>
            <div className="auth-status-copy">
                <span className="auth-status-label">
                    {authRequired ? (authenticated ? `Signed in${role ? ` as ${role}` : ''}` : 'Sign in to continue') : 'Local console'}
                </span>
                {variant === 'card' && (
                    <p>{supportsPassword ? 'Use your console password to manage routes, policy behavior, observability, and attack-lab runs.' : 'Access is managed by your enterprise identity layer. Refresh after your identity provider has granted a session.'}</p>
                )}
                {!authRequired && <span className="auth-status-detail">Development access is open.</span>}
                {authRequired && <span className="auth-status-detail">{authMode}</span>}
                {status && <span className="auth-status-detail">{status}</span>}
            </div>
            {authRequired && !authenticated && supportsPassword && (
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
            {authRequired && !authenticated && !supportsPassword && (
                <button type="button" onClick={refresh} disabled={busy}>Check session</button>
            )}
            {authRequired && authenticated && (
                <button type="button" className="auth-status-link" onClick={signOut} disabled={busy}>
                    Sign out
                </button>
            )}
        </div>
    )
}
