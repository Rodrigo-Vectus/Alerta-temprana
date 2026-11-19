import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconRefresh, IconSearch } from '../components/icons'
import { Empty, ErrorBox, fmtDate, fmtPct, Loading, Score, StatusBadge, useFetch, useToast } from '../components/ui'

// Pestañas: lo nuevo, lo que salió a clientes, lo que el SOC decidió no enviar y el histórico completo
const FILTERS = [
  { key: 'nuevas', label: 'Nuevas', count: 'nuevas', order: 'recent', newDays: true,
    hint: (d) => `Ingresadas a la plataforma en los últimos ${d} días, de la más reciente a la más antigua.` },
  { key: 'monitoreo', label: 'Monitoreo', count: 'monitoreo', status: 'monitoreo',
    hint: () => 'Riesgo medio (puntaje 40 a 59): no se comunican a clientes, quedan a la vista. Si cambian los datos o cargás un cliente con esa tecnología, el puntaje se recalcula y pueden pasar a notificarse.' },
  { key: 'enviadas', label: 'Enviadas', count: 'enviadas', status: 'enviada,cerrada', order: 'recent',
    hint: () => 'Alertas cuyo comunicado ya se envió a los clientes.' },
  { key: 'no_enviadas', label: 'No enviadas', count: 'no_enviadas', status: 'no_enviada,descartada', order: 'recent',
    hint: () => 'El SOC canceló el envío o descartó la alerta. El motivo queda en el historial de cada una; se pueden enviar más adelante desde su comunicado.' },
  { key: 'todas', label: 'Todas', count: 'todas',
    hint: () => 'Todas las vulnerabilidades evaluadas, ordenadas por puntaje.' },
]

// Filtros por estado que no tienen pestaña propia (se llega desde las tarjetas del Panel)
const EXTRA = {
  candidata: { key: 'candidata', label: 'Candidatas', status: 'candidata',
    hint: () => 'Puntaje 60 o más, todavía sin comunicado: esperan validación del analista.' },
  en_revision: { key: 'en_revision', label: 'En revisión', status: 'en_revision,aprobada',
    hint: () => 'Tienen comunicado en preparación o programado, todavía no enviado.' },
}

function Detected({ a }) {
  const d = new Date(a.created_at)
  return (
    <>
      <div className="num">{d.toLocaleDateString('es-AR', { day: '2-digit', month: '2-digit', year: 'numeric' })}</div>
      <div className="sub mono">{d.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit', hour12: false })} hs{a.origin === 'carga_inicial' && ' · carga inicial'}</div>
    </>
  )
}

export default function Alerts() {
  usePageHeader('Alertas', 'Evaluación automática de CVE nuevas o actualizadas en CISA KEV')
  const navigate = useNavigate()
  const toast = useToast()
  const { canWrite } = useAuth()
  const [params, setParams] = useSearchParams()
  const filter = FILTERS.find((f) => f.key === params.get('f')) || EXTRA[params.get('f')] || FILTERS[0]
  const extra = !!EXTRA[params.get('f')]
  const [q, setQ] = useState(params.get('q') || '')
  const [qDebounced, setQDebounced] = useState(q)
  const [busy, setBusy] = useState(false)

  useEffect(() => { const t = setTimeout(() => setQDebounced(q), 300); return () => clearTimeout(t) }, [q])

  const counts = useFetch(() => api.get('/alerts/counts'), [], { interval: 60000 })
  const newDays = counts.data?.new_days || 7
  const { data, error, loading, reload } = useFetch(() => {
    const p = new URLSearchParams({ limit: '500' })
    if (filter.status) p.set('status', filter.status)
    if (filter.newDays) p.set('new_days', String(newDays))
    if (filter.order) p.set('order', filter.order)
    if (qDebounced.trim()) p.set('q', qDebounced.trim())
    return api.get(`/alerts?${p}`)
  }, [filter.key, qDebounced], { interval: 60000 })

  const rescore = async () => {
    setBusy(true)
    try {
      const r = await api.post('/alerts/rescore-all')
      toast(`Puntajes recalculados: ${r.changed} de ${r.total} cambiaron`)
      reload(); counts.reload(true)
    } catch (e) { toast(e.message, 'err') }
    setBusy(false)
  }

  return (
    <>
      <div className="toolbar">
        <div className="chips">
          {FILTERS.map((f) => (
            <button key={f.key} className={`chip ${f.key === filter.key ? 'on' : ''}`} onClick={() => setParams({ f: f.key })}>
              {f.label}{counts.data && <span className="chip-n">{counts.data[f.count]}</span>}
            </button>
          ))}
          {extra && (
            <button className="chip on" onClick={() => setParams({ f: 'nuevas' })} title="Quitar filtro">
              {filter.label} <span style={{ marginLeft: 6, opacity: 0.8 }}>✕</span>
            </button>
          )}
        </div>
        <span className="spacer" />
        <div className="search"><IconSearch /><input placeholder="Buscar CVE, código, fabricante…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        {canWrite && <button className="btn btn-secondary" onClick={rescore} disabled={busy} title="Recalcular con el inventario y fabricantes actuales"><IconRefresh />{busy ? 'Recalculando…' : 'Recalcular'}</button>}
      </div>

      <p className="hint" style={{ margin: '-6px 0 14px' }}>{filter.hint(newDays)}</p>
      <div className="card" style={{ padding: '6px 22px' }}>
        {error && <div style={{ padding: 16 }}><ErrorBox error={error} /></div>}
        {loading && !data ? <Loading /> : data?.length === 0 ? <Empty>{filter.key === 'nuevas' ? `No ingresaron alertas en los últimos ${newDays} días. El sistema sigue consultando CISA cada 15 minutos.` : 'No hay alertas en esta pestaña.'}</Empty> : data && (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr><th>Score</th><th>Alerta</th><th>Fabricante / producto</th><th>CVSS</th><th>EPSS</th><th title="Usada en campañas de ransomware">Ransom.</th><th>Clientes</th><th>Detectada</th><th>Agregada KEV</th><th>Vence CISA</th><th>Estado</th></tr>
              </thead>
              <tbody>
                {data.map((a) => (
                  <tr key={a.code} className="click" onClick={() => navigate(`/alertas/${a.code}`)}>
                    <td><Score value={a.score} /></td>
                    <td style={{ whiteSpace: 'nowrap' }}><div className="code">{a.code}</div><div className="sub mono">{a.cve_id}</div></td>
                    <td style={{ maxWidth: 300 }}><div className="prod">{a.vendor} {a.product}</div><div className="sub" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.name}</div></td>
                    <td className="num">{a.cvss ?? '—'}</td>
                    <td className="num">{fmtPct(a.epss)}</td>
                    <td>{a.ransomware === 'Known' ? <span className="badge b-danger">Sí</span> : <span className="dim mono" style={{ fontSize: 11 }}>—</span>}</td>
                    <td>{a.clients.length ? <span className="badge b-danger" title={a.clients.join(', ')}>{a.clients.length}</span> : <span className="dim">—</span>}</td>
                    <td style={{ whiteSpace: 'nowrap' }}><Detected a={a} /></td>
                    <td className="num">{fmtDate(a.date_added)}</td>
                    <td className="num">{fmtDate(a.due_date)}</td>
                    <td style={{ whiteSpace: 'nowrap' }}><StatusBadge status={a.status} /></td>
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
