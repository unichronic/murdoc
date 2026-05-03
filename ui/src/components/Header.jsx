import './Header.css'

export default function Header({ currentView, setCurrentView }) {
  return (
    <header className="site-header">
      <div className="container header-inner">
        <button type="button" className="logo" onClick={() => setCurrentView('main')}>
          <div className="logo-text">
            <span className="logo-title">Murdoc</span>
            <span className="logo-subtitle">AI security gateway</span>
          </div>
        </button>
        <nav className="nav">
          {currentView === 'main' ? (
            <>
              <a href="#solution" className="nav-link">Solution</a>
              <a href="#how-it-works" className="nav-link">How it works</a>
              <a href="#faq" className="nav-link">FAQ</a>
              <button
                type="button"
                className="nav-link nav-action"
                onClick={() => setCurrentView('console')}
              >
                Admin Console
              </button>
            </>
          ) : (
            <button
              type="button"
              className="nav-link nav-button"
              onClick={() => setCurrentView('main')}
            >
              Back to Main
            </button>
          )}
        </nav>
      </div>
    </header>
  )
}
