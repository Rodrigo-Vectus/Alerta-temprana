import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { ThemeToggle } from '../components/Layout'
import { ErrorBox, useToast } from '../components/ui'

export default function ChangePassword() {
  const { user, reload, logout } = useAuth()
  const navigate = useNavigate()
  const toast = useToast()
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [rep, setRep] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const forced = user?.must_change_password

  const valid = next.length >= 10 && /[A-Za-z]/.test(next) && /\d/.test(next)
  const submit = async (e) => {
    e.preventDefault()
    if (next !== rep) { setError(new Error('Las contraseñas nuevas no coinciden')); return }
    setBusy(true); setError(null)
    try {
      await api.post('/auth/change-password', { current_password: cur, new_password: next })
      await reload()
      toast('Contraseña actualizada')
      navigate('/', { replace: true })
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
            <div className="logo-sub">{user?.email}</div>
          </div>
        </div>
        <div className="auth-title">Cambiar contraseña</div>
        <p className="auth-desc">
          {forced ? 'Por seguridad, tenés que definir una contraseña propia antes de continuar.' : 'Definí una nueva contraseña para tu cuenta.'}
        </p>
        <div className="stack" style={{ gap: 16 }}>
          <div className="fg"><label>Contraseña actual</label><input type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} required autoFocus /></div>
          <div className="fg"><label>Nueva contraseña</label><input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required /></div>
          <div className="fg"><label>Repetir nueva contraseña</label><input type="password" autoComplete="new-password" value={rep} onChange={(e) => setRep(e.target.value)} required /></div>
          <p className="hint">Mínimo 10 caracteres, con letras y números.</p>
          <ErrorBox error={error} />
          <button className="btn btn-primary btn-block" disabled={busy || !valid || !cur || !rep}>{busy ? 'Guardando…' : 'Guardar contraseña'}</button>
          {forced
            ? <button type="button" className="btn btn-secondary btn-block" onClick={() => { logout(); navigate('/login') }}>Salir</button>
            : <button type="button" className="btn btn-secondary btn-block" onClick={() => navigate(-1)}>Cancelar</button>}
        </div>
      </form>
    </div>
  )
}
