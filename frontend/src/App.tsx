import { Link, Route, Routes } from 'react-router-dom'
import HealthStatus from './components/health-status'
import RegisterForm from './features/auth/register-form'
import LoginForm from './features/auth/login-form'

export default function App() {
  return (
    <main style={{ fontFamily: 'system-ui, sans-serif', padding: 32 }}>
      <h1>Secure Vault</h1>
      <nav style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        <Link to="/">Početna</Link>
        <Link to="/register">Registracija</Link>
        <Link to="/login">Prijava</Link>
      </nav>
      <Routes>
        <Route path="/" element={<HealthStatus />} />
        <Route path="/register" element={<RegisterForm />} />
        <Route path="/login" element={<LoginForm />} />
      </Routes>
    </main>
  )
}
