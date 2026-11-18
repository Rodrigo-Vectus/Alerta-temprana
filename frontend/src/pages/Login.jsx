import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { ThemeToggle } from '../components/Layout'
import { ErrorBox } from '../components/ui'

export default function Login() {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  if (user) return <Navigate to={user.must_change_password ? '/cambiar-clave' : '/'} replace />

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true); setError(null)
    try {
      const u = await login(email.trim(), password)
      navigate(u.must_change_password ? '/cambiar-clave' : '/', { replace: true })
    } catch (err) { setError(err) }
    setBusy(false)
  }

  return (
    <div className="auth-wrap">
      <div style={{ position: 'fixed', top: 18, right: 22, zIndex: 2 }}><ThemeToggle /></div>
      <form className="auth-card" onSubmit={submit}>
        <div className="topbar-line" />
        <div className="auth-brand">
          <div className="logo-icon"><img src="/logo_vectus.png" alt="Vectus" /></div>
          <div>
            <div className="logo-text">Vectus SAT</div>
            <div className="logo-sub">Sistema de Alerta Temprana</div>
          </div>
        </div>
        <div className="auth-title">Iniciar sesión</div>
        <p className="auth-desc">Consola de monitoreo de vulnerabilidades explotadas activamente y comunicación preventiva a clientes.</p>

        <div className="stack" style={{ gap: 16 }}>
          <div className="fg">
            <label>Email <span className="req">*</span></label>
            <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="usuario@vectus.la" required autoFocus />
          </div>
          <div className="fg">
            <label>Contraseña <span className="req">*</span></label>
            <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <ErrorBox error={error} />
          <button className="btn btn-primary btn-block" disabled={busy || !email || !password}>
            {busy ? 'Ingresando…' : 'Ingresar'}
          </button>
        </div>

        <div className="auth-foot"><span>Grupo Vectus</span><span>Tecnología y ciberseguridad</span></div>
      </form>
    </div>
  )
}
