import './Footer.css'

export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="container footer-inner">
        <div className="footer-left">
          <span className="logo-title">sandbox</span>
          <span className="footer-tagline">Not just powerful AI. Protected AI.</span>
        </div>
        <div className="footer-links">
          <a href="#demo" className="footer-link">Demo</a>
          <a href="#solution" className="footer-link">Solution</a>
          <a href="#how-it-works" className="footer-link">How it works</a>
          <a href="#faq" className="footer-link">FAQ</a>
        </div>
      </div>
    </footer>
  )
}
