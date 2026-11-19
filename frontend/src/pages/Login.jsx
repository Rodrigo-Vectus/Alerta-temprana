import { useEffect, useRef, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { ThemeToggle } from '../components/Layout'
import { ErrorBox } from '../components/ui'

// Ingreso sin contraseña: 1) correo → 2) código que llega por mail.
const RESEND_SECONDS = 60
export default function Login() {
  const { user, requestCode, verifyCode } = useAuth()
  const navigate = useNavigate()
  const [step, setStep] = useState('email')
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [wait, setWait] = useState(0)
  const codeRef = useRef(null)

  useEffect(() => {
    if (wait <= 0) return undefined
    const t = setTimeout(() => setWait((w) => w - 1), 1000)
    return () => clearTimeout(t)
  }, [wait])

  useEffect(() => { if (step === 'code') codeRef.current?.focus() }, [step])

  if (user) return <Navigate to="/" replace />

  const send = async (e) => {
    e?.preventDefault()
    setBusy(true); setError(null)
    try {
      const r = await requestCode(email.trim())
      setWait(RESEND_SECONDS); setCode(''); setStep('code')
    } catch (err) { setError(err) }
    setBusy(false)
  }

  const verify = async (value) => {
    const c = (value ?? code).replace(/\D/g, '')
    if (c.length !== 6 || busy) return
    setBusy(true); setError(null)
    try {
      await verifyCode(email.trim(), c)
      navigate('/', { replace: true })
    } catch (err) { setError(err); setCode(''); codeRef.current?.focus() }
    setBusy(false)
  }

  const onCode = (v) => {
    const c = v.replace(/\D/g, '').slice(0, 6)
    setCode(c)
    if (c.length === 6) verify(c)
  }

  return (
    <div className="auth-wrap">
      <div style={{ position: 'fixed', top: 18, right: 22, zIndex: 2 }}><ThemeToggle /></div>
      <form className="auth-card" onSubmit={step === 'email' ? send : (e) => { e.preventDefault(); verify() }}>
        <div className="topbar-line" />
        <div className="auth-brand">
          <div className="logo-icon"><img src="/logo_vectus.png" alt="Vectus" /></div>
          <div>
            <div className="logo-text">Vectus SAT</div>
            <div className="logo-sub">Sistema de Alerta Temprana</div>
          </div>
        </div>

        {step === 'email' ? (
          <>
            <div className="auth-title">Iniciar sesión</div>
            <p className="auth-desc">Ingresá tu correo y te enviamos un código de acceso. No hace falta contraseña.</p>
            <div className="stack" style={{ gap: 16 }}>
              <div className="fg">
                <label>Email <span className="req">*</span></label>
                <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="usuario@vectus.la" required autoFocus />
              </div>
              <ErrorBox error={error} />
              <button className="btn btn-primary btn-block" disabled={busy || !email.includes('@')}>
                {busy ? 'Enviando…' : 'Enviar código'}
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="auth-title">Revisá tu correo</div>
            <div className="otp-notice">
              <div className="otp-notice-icon">✉</div>
              <div>
                Si <b>{email.trim().toLowerCase()}</b> está registrado en la plataforma, vas a recibir un código de acceso.
              </div>
            </div>
            <div className="stack" style={{ gap: 16 }}>
              <div className="fg">
                <label>Código de acceso</label>
                <input ref={codeRef} className="otp-input" inputMode="numeric" autoComplete="one-time-code" maxLength={7}
                  value={code} onChange={(e) => onCode(e.target.value)} onPaste={(e) => { e.preventDefault(); onCode(e.clipboardData.getData('text')) }}
                  placeholder="Código" aria-label="Código de acceso" />
              </div>
              <ErrorBox error={error} />
              <button className="btn btn-primary btn-block" disabled={busy || code.length !== 6}>
                {busy ? 'Verificando…' : 'Ingresar'}
              </button>
              <div className="otp-actions">
                <button type="button" className="link-btn" onClick={() => { setStep('email'); setError(null); setCode('') }}>← Usar otro correo</button>
                <button type="button" className="link-btn" disabled={wait > 0 || busy} onClick={() => send()}>
                  {wait > 0 ? `Reenviar en ${wait} s` : 'Reenviar código'}
                </button>
              </div>
            </div>
          </>
        )}

        <div className="auth-foot"><span>Grupo Vectus</span><span>Tecnología y ciberseguridad</span></div>
      </form>
    </div>
  )
}
