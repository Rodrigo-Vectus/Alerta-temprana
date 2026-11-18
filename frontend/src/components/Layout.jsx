import { createContext, useContext, useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, storage } from '../api'
import { useAuth } from '../auth'
import { timeAgo } from './ui'
import {
  IconAlert, IconBuilding, IconDashboard, IconEye, IconFlow, IconKey, IconList, IconLogout, IconMail, IconMenu, IconUsers,
} from './icons'

// ---------- Título de página (cada página lo define) ----------
const HeaderCtx = createContext(() => {})
export function usePageHeader(title, sub) {
  const set = useContext(HeaderCtx)
  useEffect(() => { set({ title, sub }) }, [set, title, sub])
}

// ---------- Tema claro / oscuro (misma clave que la consola de Evaluación) ----------
function useTheme() {
  const [theme, setTheme] = useState(() => document.documentElement.getAttribute('data-theme') || 'dark')
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    document.documentElement.setAttribute('data-theme', next)
    storage.set('vectus-theme', next)
    setTheme(next)
  }
  return [theme, toggle]
}

export function ThemeToggle() {
  const [theme, toggle] = useTheme()
  return (
    <button className="theme-toggle" onClick={toggle} title="Cambiar modo claro / oscuro">
      {theme === 'dark' ? '☀️' : '🌙'}
    </button>
  )
}

const NAV = [
  { group: 'Monitoreo', items: [
    { to: '/', label: 'Panel', icon: IconDashboard, end: true },
    { to: '/alertas', label: 'Alertas', icon: IconAlert, badge: true },
  ] },
  { group: 'Respuesta', items: [
    { to: '/comunicados', label: 'Comunicados', icon: IconMail, soon: 'Fase 6' },
    { to: '/casos-de-uso', label: 'Casos de uso SOC', icon: IconFlow, soon: 'Fase 7' },
  ] },
  { group: 'Gestión', items: [
    { to: '/clientes', label: 'Clientes', icon: IconBuilding },
    { to: '/fabricantes', label: 'Fabricantes vigilados', icon: IconEye },
  ] },
  { group: 'Administración', admin: true, items: [
    { to: '/usuarios', label: 'Usuarios', icon: IconUsers },
    { to: '/auditoria', label: 'Auditoría', icon: IconList },
  ] },
]

const ROLE_LABEL = { admin: 'Administrador', analista: 'Analista SOC', lector: 'Lector' }

export default function Layout() {
  const { user, logout, isAdmin } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [header, setHeader] = useState({ title: '', sub: '' })
  const [summary, setSummary] = useState(null)
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    let alive = true
    const load = () => api.get('/alerts/summary').then((s) => alive && setSummary(s)).catch(() => {})
    load()
    const t = setInterval(load, 60000)
    return () => { alive = false; clearInterval(t) }
  }, [location.pathname])

  useEffect(() => { setMenuOpen(false) }, [location.pathname])

  const candidates = summary?.by_status?.candidata || 0
  const run = summary?.last_run
  const initials = (user?.full_name || user?.email || '?').split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((s) => s[0].toUpperCase()).join('')

  return (
    <HeaderCtx.Provider value={setHeader}>
      <div className="app">
        <aside className={`sidebar ${menuOpen ? 'open' : ''}`}>
          <div className="sb-brand">
            <div className="logo-icon"><img src="/logo_vectus.png" alt="Vectus" /></div>
            <div>
              <div className="logo-text">Vectus SAT</div>
              <div className="logo-sub">Alerta temprana · SOC</div>
            </div>
          </div>

          <nav className="sb-nav">
            {NAV.filter((g) => !g.admin || isAdmin).map((g) => (
              <div className="sb-group" key={g.group}>
                <div className="sb-group-lbl">{g.group}</div>
                {g.items.map((it) => (
                  <NavLink key={it.to} to={it.to} end={it.end} className={({ isActive }) => `sb-link ${isActive ? 'active' : ''} ${it.soon ? 'disabled' : ''}`}>
                    <it.icon />{it.label}
                    {it.badge && candidates > 0 && <span className="sb-badge">{candidates}</span>}
                    {it.soon && <span className="sb-soon">{it.soon}</span>}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>

          <div className="sb-user">
            <div className="avatar">{initials}</div>
            <div className="sb-user-info">
              <div className="sb-user-name" title={user?.email}>{user?.full_name || user?.email}</div>
              <div className="sb-user-role">{ROLE_LABEL[user?.role] || user?.role}</div>
            </div>
            <button className="icon-btn" title="Cambiar contraseña" onClick={() => navigate('/cambiar-clave')}><IconKey /></button>
            <button className="icon-btn" title="Cerrar sesión" onClick={() => { logout(); navigate('/login') }}><IconLogout /></button>
          </div>
        </aside>

        <div className="main">
          <header className="topbar">
            <div className="topbar-line" />
            <div className="topbar-inner">
              <button className="icon-btn menu-btn" onClick={() => setMenuOpen((v) => !v)} title="Menú"><IconMenu /></button>
              <div>
                <div className="page-title">{header.title}</div>
                {header.sub && <div className="page-sub">{header.sub}</div>}
              </div>
              <div className="topbar-right">
                {run && (
                  <div className="sync-chip" title={run.error || `Catálogo KEV ${run.catalog_version || ''}`}>
                    <span className={`dot ${run.status === 'error' ? 'err' : ''}`} />
                    CISA KEV · {run.status === 'error' ? 'error' : timeAgo(run.started_at)}
                  </div>
                )}
                <ThemeToggle />
              </div>
            </div>
          </header>
          <main className="content" key={location.pathname}>
            <Outlet />
          </main>
        </div>
      </div>
    </HeaderCtx.Provider>
  )
}
