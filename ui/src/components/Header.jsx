import './Header.css'

export default function Header({ currentView, setCurrentView }) {
  return (
    <header className="site-header">
      <div className="container header-inner">
        <div className="logo" onClick={() => setCurrentView('main')} style={{ cursor: 'pointer' }}>
          <div className="logo-mark">M</div>
          <div className="logo-text">
            <span className="logo-title">Murdoc</span>
            <span className="logo-subtitle">AI Security Gateway</span>
          </div>
        </div>
        <nav className="nav">
          {currentView === 'main' ? (
            <>
              <a href="#solution" className="nav-link">Solution</a>
              <a href="#how-it-works" className="nav-link">How it works</a>
              <a href="#faq" className="nav-link">FAQ</a>
              <button
                type="button"
                className="nav-link"
                onClick={() => setCurrentView('demo')}
                style={{ background: 'transparent', border: '1px solid var(--border)', borderRadius: '4px', padding: '4px 12px', cursor: 'pointer', color: 'var(--text)' }}
              >
                Interactive Demo
              </button>
            </>
          ) : (
            <button
              type="button"
              className="nav-link"
              onClick={() => setCurrentView('main')}
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text)' }}
            >
              Back to Main
            </button>
          )}
        </nav>
      </div>
    </header>
  )
}
