import { useEffect, useState } from 'react'
import Header from './components/Header'
import Hero from './components/Hero'
import ControlPlane from './components/ControlPlane'
import Solution from './components/Solution'
import HowItWorks from './components/HowItWorks'
import FAQ from './components/FAQ'
import Dashboard from './components/Dashboard'
import TestingLab from './components/TestingLab'
import Footer from './components/Footer'
import AuthStatus from './components/AuthStatus'
import './App.css'

const WORKSPACE_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'control', label: 'Control Plane' },
  { id: 'testing', label: 'Attack Lab' },
]

function App() {
  const initialView = window.location.pathname.startsWith('/console') ? 'console' : 'main'
  const [currentView, setCurrentViewState] = useState(initialView)
  const [workspaceTab, setWorkspaceTab] = useState('overview')
  const [authState, setAuthState] = useState({ checked: false, authRequired: true, authenticated: false })
  const updateAuthState = (next) => setAuthState({ checked: true, ...next })

  const setCurrentView = (view) => {
    setCurrentViewState(view)
    const nextPath = view === 'console' ? '/console' : '/'
    if (window.location.pathname !== nextPath) {
      window.history.pushState({}, '', nextPath)
    }
  }

  useEffect(() => {
    const handlePopState = () => {
      setCurrentViewState(window.location.pathname.startsWith('/console') ? 'console' : 'main')
    }
    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [])

  const consoleUnlocked = authState.checked && (!authState.authRequired || authState.authenticated)

  return (
    <div className="page">
      <Header currentView={currentView} setCurrentView={setCurrentView} />
      <main>
        {currentView === 'main' ? (
          <>
            <Hero setCurrentView={setCurrentView} />
            <Solution />
            <HowItWorks />
            <FAQ />
          </>
        ) : (
          <section className="workspace" aria-label="Murdoc workspace">
            {consoleUnlocked && (
              <div className="container workspace-topbar">
                <div className="workspace-tabs" role="tablist" aria-label="Workspace sections">
                  {WORKSPACE_TABS.map(tab => (
                    <button
                      key={tab.id}
                      type="button"
                      role="tab"
                      aria-selected={workspaceTab === tab.id}
                      className={`workspace-tab ${workspaceTab === tab.id ? 'workspace-tab-active' : ''}`}
                      onClick={() => setWorkspaceTab(tab.id)}
                    >
                      <span>{tab.label}</span>
                    </button>
                  ))}
                </div>
                <AuthStatus onAuthChange={updateAuthState} />
              </div>
            )}
            {!consoleUnlocked ? (
              <section className="console-locked">
                <div className="container console-auth-grid">
                  <div className="console-auth-copy">
                    <span>Admin Console</span>
                    <h2>Manage Murdoc from one protected workspace.</h2>
                    <p>Sign in to configure gateway routes, tune protection profiles, review system visibility, and run attack-lab checks.</p>
                    <div className="console-auth-points">
                      <div>
                        <strong>Route Control</strong>
                        <small>Connect model, tool, and agent traffic to the right protection profile.</small>
                      </div>
                      <div>
                        <strong>Protection Settings</strong>
                        <small>Adjust scanner, policy, semantic guardrail, rate, and latency behavior.</small>
                      </div>
                      <div>
                        <strong>Attack Lab</strong>
                        <small>Validate policy posture against local adversarial corpora before rollout.</small>
                      </div>
                    </div>
                  </div>
                  <AuthStatus onAuthChange={updateAuthState} variant="card" />
                </div>
              </section>
            ) : (
              <>
                {workspaceTab === 'overview' && <Dashboard />}
                {workspaceTab === 'control' && <ControlPlane />}
                {workspaceTab === 'testing' && <TestingLab />}
              </>
            )}
          </section>
        )}
      </main>
      <Footer currentView={currentView} setCurrentView={setCurrentView} />
    </div>
  )
}

export default App
