import Header from './components/Header'
import Hero from './components/Hero'
import SecurityDemo from './components/SecurityDemo'
import Solution from './components/Solution'
import HowItWorks from './components/HowItWorks'
import FAQ from './components/FAQ'
import Footer from './components/Footer'
import './App.css'

function App() {
  return (
    <div className="page">
      <Header />
      <main>
        <Hero />
        <SecurityDemo />
        <Solution />
        <HowItWorks />
        <FAQ />
      </main>
      <Footer />
    </div>
  )
}

export default App
