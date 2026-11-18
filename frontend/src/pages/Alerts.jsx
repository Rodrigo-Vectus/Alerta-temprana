import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconRefresh, IconSearch } from '../components/icons'
import { Empty, ErrorBox, fmtDate, fmtPct, Loading, Score, StatusBadge, useFetch, useToast } from '../components/ui'

const FILTERS = [
  { key: 'activas', label: 'Activas', status: 'candidata,en_revision,aprobada' },
  { key: 'candidata', label: 'Candidatas', status: 'candidata' },
  { key: 'en_revision', label: 'En revisión', status: 'en_revision' },
  { key: 'monitoreo', label: 'Monitoreo', status: 'monitoreo' },
  { key: 'enviada', label: 'Enviadas', status: 'enviada,cerrada' },
  { key: 'descartadas', label: 'Descartadas', status: 'descartada,descartada_auto' },
  { key: 'todas', label: 'Todas', status: '' },
]

export default function Alerts() {
  usePageHeader('Alertas', 'Evaluación automática de CVE nuevas o actualizadas en CISA KEV')
  const navigate = useNavigate()
  const toast = useToast()
  const { canWrite } = useAuth()
  const [params, setParams] = useSearchParams()
  const filter = FILTERS.find((f) => f.key === params.get('f')) || FILTERS[0]
  const [q, setQ] = useState(params.get('q') || '')
  const [qDebounced, setQDebounced] = useState(q)
  const [busy, setBusy] = useState(false)

  useEffect(() => { const t = setTimeout(() => setQDebounced(q), 300); return () => clearTimeout(t) }, [q])

  const { data, error, loading, reload } = useFetch(() => {
    const p = new URLSearchParams({ limit: '500' })
    if (filter.status) p.set('status', filter.status)
    if (qDebounced.trim()) p.set('q', qDebounced.trim())
    return api.get(`/alerts?${p}`)
  }, [filter.key, qDebounced], { interval: 60000 })

  const rescore = async () => {
    setBusy(true)
    try {
      const r = await api.post('/alerts/rescore-all')
      toast(`Puntajes recalculados: ${r.changed} de ${r.total} cambiaron`)
      reload()
    } catch (e) { toast(e.message, 'err') }
    setBusy(false)
  }

  return (
    <>
      <div className="toolbar">
        <div className="chips">
          {FILTERS.map((f) => (
            <button key={f.key} className={`chip ${f.key === filter.key ? 'on' : ''}`} onClick={() => setParams({ f: f.key })}>{f.label}</button>
          ))}
        </div>
        <span className="spacer" />
        <div className="search"><IconSearch /><input placeholder="Buscar CVE, código, fabricante…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        {canWrite && <button className="btn btn-secondary" onClick={rescore} disabled={busy} title="Recalcular con el inventario y fabricantes actuales"><IconRefresh />{busy ? 'Recalculando…' : 'Recalcular'}</button>}
      </div>

      <div className="card" style={{ padding: '6px 22px' }}>
        {error && <div style={{ padding: 16 }}><ErrorBox error={error} /></div>}
        {loading && !data ? <Loading /> : data?.length === 0 ? <Empty>No hay alertas con este filtro.</Empty> : data && (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr><th>Score</th><th>Alerta</th><th>Fabricante / producto</th><th>CVSS</th><th>EPSS</th><th>Ransomware</th><th>Clientes</th><th>Agregada KEV</th><th>Vence CISA</th><th>Estado</th></tr>
              </thead>
              <tbody>
                {data.map((a) => (
                  <tr key={a.code} className="click" onClick={() => navigate(`/alertas/${a.code}`)}>
                    <td><Score value={a.score} /></td>
                    <td><div className="code">{a.code}</div><div className="sub mono">{a.cve_id}</div></td>
                    <td style={{ maxWidth: 360 }}><div className="prod">{a.vendor} {a.product}</div><div className="sub" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.name}</div></td>
                    <td className="num">{a.cvss ?? '—'}</td>
                    <td className="num">{fmtPct(a.epss)}</td>
                    <td>{a.ransomware === 'Known' ? <span className="badge b-danger">Sí</span> : <span className="dim mono" style={{ fontSize: 11 }}>—</span>}</td>
                    <td>{a.clients.length ? <span className="badge b-danger" title={a.clients.join(', ')}>{a.clients.length}</span> : <span className="dim">—</span>}</td>
                    <td className="num">{fmtDate(a.date_added)}</td>
                    <td className="num">{fmtDate(a.due_date)}</td>
                    <td><StatusBadge status={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {data && <p className="hint" style={{ marginTop: 12 }}>{data.length} alerta(s) · se actualiza automáticamente cada minuto</p>}
    </>
  )
}
