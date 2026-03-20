import './Header.css'

export default function Header() {
  return (
    <header className="site-header">
      <div className="container header-inner">
        <div className="logo">
          <div className="logo-mark">λ</div>
          <div className="logo-text">
            <span className="logo-title">sandbox</span>
            <span className="logo-subtitle">Protected AI Layer</span>
          </div>
        </div>
        <nav className="nav">
          <a href="#demo" className="nav-link">Demo</a>
          <a href="#solution" className="nav-link">Solution</a>
          <a href="#how-it-works" className="nav-link">How it works</a>
          <a href="#faq" className="nav-link">FAQ</a>
        </nav>
      </div>
    </header>
  )
}
