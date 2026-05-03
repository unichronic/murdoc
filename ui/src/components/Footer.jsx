import './Footer.css'

export default function Footer({ currentView, setCurrentView }) {
  const goToSection = (id) => {
    setCurrentView('main')
    window.setTimeout(() => {
      document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' })
    }, 0)
  }

  return (
    <footer className="site-footer">
      <div className="container footer-inner">
        <div className="footer-left">
          <span className="logo-title">Murdoc</span>
          <span className="footer-tagline">Policy enforcement for agent traffic.</span>
        </div>
        <div className="footer-links">
          <button type="button" className="footer-link" onClick={() => setCurrentView('console')}>Admin Console</button>
          {currentView === 'main' ? (
            <>
              <a href="#solution" className="footer-link">Solution</a>
              <a href="#how-it-works" className="footer-link">How it works</a>
              <a href="#faq" className="footer-link">FAQ</a>
            </>
          ) : (
            <>
              <button type="button" className="footer-link" onClick={() => goToSection('solution')}>Solution</button>
              <button type="button" className="footer-link" onClick={() => goToSection('how-it-works')}>How it works</button>
              <button type="button" className="footer-link" onClick={() => goToSection('faq')}>FAQ</button>
            </>
          )}
        </div>
      </div>
    </footer>
  )
}
