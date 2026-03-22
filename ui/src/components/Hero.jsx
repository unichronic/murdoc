import './Hero.css'

export default function Hero() {
  return (
    <section className="hero">
      <div className="container hero-inner">
        <p className="hero-pill">Security Proxy for AI Agents</p>
        <h1 className="hero-title">
          <span className="accent">GenAI risks.</span>
          <br />
          Handled.
        </h1>
        <p className="hero-lead">
          Recent exploits like EchoLeak, BodySnatcher, and the OpenClaw crisis prove that autonomous
          agents can easily be manipulated into leaking data or hijacking administrative identities.
          Our Security Proxy Layer sits between your AI agents and the world — monitoring what the
          AI reads, remembers, and what actions it tries to perform.
        </p>
      </div>
    </section>
  )
}
