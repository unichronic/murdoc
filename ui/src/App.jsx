import { useState } from 'react'
import Header from './components/Header'
import Hero from './components/Hero'
import SecurityDemo from './components/SecurityDemo'
import RedTeamPanel from './components/RedTeamPanel'
import ControlPlane from './components/ControlPlane'
import Solution from './components/Solution'
import HowItWorks from './components/HowItWorks'
import FAQ from './components/FAQ'
import Dashboard from './components/Dashboard'
import Footer from './components/Footer'
import './App.css'

function App() {
  const [currentView, setCurrentView] = useState('main')

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
          <>
            <Dashboard />
            <ControlPlane />
            <SecurityDemo />
            <RedTeamPanel />
          </>
        )}
      </main>
      <Footer />
    </div>
  )
}

export default App
