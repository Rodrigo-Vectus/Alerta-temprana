import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { usePageHeader } from '../components/Layout'
import { daysUntil, Empty, ErrorBox, fmtDate, fmtDateTime, Loading, Score, StatusBadge, timeAgo, useFetch } from '../components/ui'

const LEVELS = [
  { key: 'alta', label: 'Alta (≥ 60)', color: 'var(--danger)' },
  { key: 'media', label: 'Media (40-59)', color: 'var(--warn)' },
  { key: 'baja', label: 'Baja (< 40)', color: 'var(--dim)' },
]

export default function Dashboard() {
  usePageHeader('Panel de alerta temprana', 'Vulnerabilidades explotadas activamente · CISA KEV')
  const navigate = useNavigate()
  const { data, error, loading } = useFetch(() => api.get('/alerts/summary'), [], { interval: 60000 })

  if (loading && !data) return <Loading />
  if (error) return <ErrorBox error={error} />
  const s = data.by_status || {}
  const run = data.last_run
  const maxLevel = Math.max(1, ...LEVELS.map((l) => data.by_level?.[l.key] || 0))

  return (
    <>
      <div className="kpis">
        <Link to="/alertas?f=candidata" className="kpi" style={{ '--kpi-c': 'var(--danger)' }}>
          <div className="kpi-lbl">Candidatas</div>
          <div className="kpi-val">{s.candidata || 0}</div>
          <div className="kpi-foot">Esperan validación del analista</div>
        </Link>
        <Link to="/alertas?f=en_revision" className="kpi" style={{ '--kpi-c': 'var(--warn)' }}>
          <div className="kpi-lbl">En revisión</div>
          <div className="kpi-val">{s.en_revision || 0}</div>
          <div className="kpi-foot">{s.aprobada || 0} aprobadas · {s.enviada || 0} enviadas</div>
        </Link>
        <Link to="/alertas?f=monitoreo" className="kpi" style={{ '--kpi-c': 'var(--accent-l)' }}>
          <div className="kpi-lbl">Monitoreo</div>
          <div className="kpi-val">{s.monitoreo || 0}</div>
          <div className="kpi-foot">Riesgo medio, sin comunicar</div>
        </Link>
        <div className="kpi" style={{ '--kpi-c': 'var(--cyan)' }}>
          <div className="kpi-lbl">Catálogo KEV</div>
          <div className="kpi-val">{data.total_kev?.toLocaleString('es-AR')}</div>
          <div className="kpi-foot">{data.total} evaluadas por el motor</div>
        </div>
        <div className="kpi" style={{ '--kpi-c': run?.status === 'error' ? 'var(--danger)' : 'var(--ok)' }}>
          <div className="kpi-lbl">Última consulta CISA</div>
          <div className="kpi-val" style={{ fontSize: 22, marginTop: 10 }}>{run ? timeAgo(run.started_at) : '—'}</div>
          <div className="kpi-foot" title={run?.error || ''}>
            {run ? (run.status === 'error' ? 'Error en la consulta' : `Catálogo ${run.catalog_version || ''} · ${run.status}`) : 'Sin ejecuciones'}
          </div>
        </div>
      </div>

      <div className="grid g-main">
        <div className="card">
          <div className="card-title">Alertas prioritarias <span className="spacer" /><Link to="/alertas" className="mono" style={{ fontSize: 10 }}>VER TODAS →</Link></div>
          {data.top.length === 0 ? <Empty icon="✓">No hay alertas activas. El motor sigue monitoreando CISA KEV.</Empty> : (
            <div className="table-wrap">
              <table className="tbl">
                <thead><tr><th>Score</th><th>Alerta</th><th>Producto</th><th>Clientes</th><th>Estado</th></tr></thead>
                <tbody>
                  {data.top.map((a) => (
                    <tr key={a.code} className="click" onClick={() => navigate(`/alertas/${a.code}`)}>
                      <td><Score value={a.score} /></td>
                      <td><div className="code">{a.code}</div><div className="sub mono">{a.cve_id}</div></td>
                      <td><div className="prod">{a.vendor} {a.product}</div><div className="sub">KEV {fmtDate(a.date_added)} · detectada {fmtDateTime(a.created_at)} hs</div></td>
                      <td>{a.clients.length ? <span className="badge b-danger">{a.clients.length}</span> : <span className="dim">—</span>}</td>
                      <td><StatusBadge status={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="stack">
          <div className="card">
            <div className="card-title">Plazos de CISA más próximos</div>
            {data.upcoming_due.length === 0 ? <Empty icon="◷">Sin vencimientos pendientes en alertas activas.</Empty> : data.upcoming_due.map((a) => {
              const d = daysUntil(a.due_date)
              return (
                <Link key={a.code} to={`/alertas/${a.code}`} className="list-item" style={{ textDecoration: 'none' }}>
                  <Score value={a.score} />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div className="name" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.vendor} {a.product}</div>
                    <div className="sub mono dim" style={{ fontSize: 11 }}>{a.cve_id} · vence {fmtDate(a.due_date)}</div>
                  </div>
                  <span className={`badge ${d <= 3 ? 'b-danger' : d <= 7 ? 'b-warn' : 'b-muted'}`}>{d === 0 ? 'hoy' : `${d} d`}</span>
                </Link>
              )
            })}
          </div>

          <div className="card">
            <div className="card-title">Distribución por nivel de riesgo</div>
            {LEVELS.map((l) => {
              const n = data.by_level?.[l.key] || 0
              return (
                <div key={l.key} className="factor" style={{ gridTemplateColumns: '110px 1fr 36px' }}>
                  <div className="factor-name" style={{ fontSize: 12 }}>{l.label}</div>
                  <div className="bar"><span style={{ width: `${(n / maxLevel) * 100}%`, background: l.color }} /></div>
                  <div className="factor-pts" style={{ color: 'var(--bright)' }}>{n}</div>
                </div>
              )
            })}
            {run && <p className="hint" style={{ marginTop: 12 }}>Consulta automática cada 15 min · última: {fmtDateTime(run.started_at)}</p>}
          </div>
        </div>
      </div>
    </>
  )
}
