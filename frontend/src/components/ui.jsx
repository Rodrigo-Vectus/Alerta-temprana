import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { createPortal } from 'react-dom'

// ---------- Formato ----------
export const fmtDate = (d) => (d ? new Date(d.length === 10 ? `${d}T12:00:00` : d).toLocaleDateString('es-AR', { day: '2-digit', month: '2-digit', year: 'numeric' }) : '—')
export const fmtDateTime = (d) => (d ? new Date(d).toLocaleString('es-AR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—')
export const fmtPct = (v, digits = 1) => (v === null || v === undefined ? '—' : `${(v * 100).toFixed(digits)}%`)
export function timeAgo(d) {
  if (!d) return '—'
  const s = Math.round((Date.now() - new Date(d).getTime()) / 1000)
  if (s < 60) return 'hace instantes'
  if (s < 3600) return `hace ${Math.round(s / 60)} min`
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`
  return `hace ${Math.round(s / 86400)} d`
}
export function daysUntil(d) {
  if (!d) return null
  const target = new Date(`${d}T23:59:59`)
  return Math.ceil((target - Date.now()) / 86400000)
}

// ---------- Badges ----------
export const STATUS = {
  candidata: { label: 'Candidata', cls: 'b-danger' },
  en_revision: { label: 'En revisión', cls: 'b-warn' },
  aprobada: { label: 'Aprobada', cls: 'b-cyan' },
  enviada: { label: 'Enviada', cls: 'b-ok' },
  monitoreo: { label: 'Monitoreo', cls: 'b-info' },
  descartada_auto: { label: 'Descartada (auto)', cls: 'b-muted' },
  descartada: { label: 'Descartada', cls: 'b-muted' },
  cerrada: { label: 'Cerrada', cls: 'b-ok' },
}

export function StatusBadge({ status }) {
  const s = STATUS[status] || { label: status, cls: 'b-muted' }
  return <span className={`badge ${s.cls}`}>{s.label}</span>
}

export const scoreClass = (v) => (v >= 60 ? 's-high' : v >= 40 ? 's-med' : 's-low')
export function Score({ value, xl = false, label }) {
  return (
    <span className={`score ${scoreClass(value)} ${xl ? 'score-xl' : ''}`} title="Puntaje de riesgo (0-100)">
      {value}{xl && <small>{label || (value >= 60 ? 'Riesgo alto' : value >= 40 ? 'Riesgo medio' : 'Riesgo bajo')}</small>}
    </span>
  )
}

export const RoleBadge = ({ role }) => {
  const map = { admin: 'b-danger', analista: 'b-info', lector: 'b-muted' }
  return <span className={`badge ${map[role] || 'b-muted'}`}>{role}</span>
}

// ---------- Estados de carga ----------
export const Loading = ({ text = 'Cargando' }) => <div className="loading"><div className="spinner" />{text.toUpperCase()}…</div>
export const Empty = ({ icon = '◎', children }) => <div className="empty"><div className="big">{icon}</div>{children}</div>
export const ErrorBox = ({ error }) => (error ? <div className="alert-box err">{error.message || String(error)}</div> : null)

// ---------- Hook de datos ----------
export function useFetch(fn, deps = [], { interval } = {}) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try { setData(await fn()); setError(null) } catch (e) { setError(e) }
    setLoading(false)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!interval) return undefined
    const t = setInterval(() => load(true), interval)
    return () => clearInterval(t)
  }, [load, interval])
  return { data, error, loading, reload: load, setData }
}

// ---------- Modal ----------
export function Modal({ title, desc, children, onClose, actions }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose?.()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  // Se renderiza en <body> para que quede centrado en la pantalla, sin importar el scroll
  // ni las animaciones de la página que lo contiene.
  return createPortal(
    <div className="modal-bg" onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}>
      <div className="modal" role="dialog" aria-modal="true">
        <h3>{title}</h3>
        {desc && <p className="desc">{desc}</p>}
        {children}
        {actions && <div className="modal-actions">{actions}</div>}
      </div>
    </div>,
    document.body,
  )
}

// ---------- Toasts ----------
const ToastCtx = createContext(() => {})
export function ToastProvider({ children }) {
  const [items, setItems] = useState([])
  const push = useCallback((msg, kind = 'ok') => {
    const id = Math.random().toString(36).slice(2)
    setItems((xs) => [...xs, { id, msg, kind }])
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 4500)
  }, [])
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts">{items.map((t) => <div key={t.id} className={`toast ${t.kind}`}>{t.msg}</div>)}</div>
    </ToastCtx.Provider>
  )
}
export const useToast = () => useContext(ToastCtx)
