import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { COMM_STATUS } from './Communications'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconArrowLeft, IconExternal, IconFlow, IconMail } from '../components/icons'
import {
  daysUntil, Empty, ErrorBox, fmtDate, fmtDateTime, fmtPct, Loading, Modal, Score, STATUS, StatusBadge, useFetch, useToast,
} from '../components/ui'

// Acciones disponibles según el estado actual
const ACTIONS = {
  candidata: [['en_revision', 'Tomar en revisión', 'btn-primary'], ['monitoreo', 'Pasar a monitoreo', 'btn-secondary'], ['descartada', 'Descartar', 'btn-danger']],
  monitoreo: [['candidata', 'Escalar a candidata', 'btn-primary'], ['descartada', 'Descartar', 'btn-danger']],
  descartada_auto: [['candidata', 'Escalar a candidata', 'btn-primary']],
  en_revision: [['candidata', 'Devolver a candidata', 'btn-secondary'], ['descartada', 'Descartar', 'btn-danger']],
  aprobada: [['cerrada', 'Cerrar', 'btn-secondary']],
  enviada: [['cerrada', 'Cerrar', 'btn-success']],
  descartada: [['candidata', 'Reabrir', 'btn-secondary']],
  cerrada: [['en_revision', 'Reabrir', 'btn-secondary']],
}

const EVENT_LABEL = {
  nueva_en_kev: 'Nueva en CISA KEV', actualizada_en_kev: 'Actualizada en CISA KEV', recalculo: 'Puntaje recalculado',
  reintento_nvd: 'Datos de NVD completados', cambio_estado: 'Cambio de estado',
  comunicado_generado: 'Comunicado generado', comunicado_regenerado: 'Comunicado regenerado',
  comunicado_programado: 'Envío automático programado', envio_cancelado: 'Envío cancelado', envio_manual: 'Envío a clientes solicitado',
}

export default function AlertDetail() {
  const { code } = useParams()
  const { canWrite } = useAuth()
  const toast = useToast()
  const navigate = useNavigate()
  const { data: a, error, loading, setData } = useFetch(() => api.get(`/alerts/${code}`), [code])
  const comm = useFetch(() => api.get(`/communications/by-alert/${code}`), [code])
  const [generating, setGenerating] = useState(false)
  const [pending, setPending] = useState(null)
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  usePageHeader(a ? `${a.code} · ${a.cve_id}` : code, a ? `${a.vendor} ${a.product}` : 'Detalle de alerta')

  if (loading && !a) return <Loading />
  if (error) return <><Link to="/alertas" className="back"><IconArrowLeft width={14} />Volver</Link><ErrorBox error={error} /></>

  const doChange = async () => {
    setBusy(true)
    try {
      const r = await api.patch(`/alerts/${a.code}/status`, { status: pending[0], comment })
      setData(r); toast(`Estado actualizado: ${STATUS[pending[0]]?.label}`)
      setPending(null); setComment('')
    } catch (e) { toast(e.message, 'err') }
    setBusy(false)
  }

  const generate = async () => {
    setGenerating(true)
    try { const r = await api.post(`/communications/from-alert/${a.code}`); toast(`Borrador ${r.code} generado`); navigate(`/comunicados/${r.code}`) } catch (e) { toast(e.message, 'err') }
    setGenerating(false)
  }

  const due = daysUntil(a.due_date)
  const maxPts = Math.max(...(a.breakdown || []).map((b) => b.puntos), 1)
  const refs = [
    { url: `https://nvd.nist.gov/vuln/detail/${a.cve_id}`, label: `NVD · ${a.cve_id}` },
    { url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${a.cve_id}`, label: 'CISA KEV' },
    ...(a.references || []).map((u) => ({ url: u, label: u })),
  ]

  return (
    <>
      <Link to="/alertas" className="back"><IconArrowLeft width={14} />Volver a alertas</Link>

      <div className="hero">
        <Score value={a.score} xl />
        <div style={{ minWidth: 0, flex: 1 }}>
          <h2>{a.name}</h2>
          <div className="hero-meta">
            <StatusBadge status={a.status} />
            <span className="badge b-info">{a.cve_id}</span>
            {a.ransomware === 'Known' && <span className="badge b-danger">Usada en ransomware</span>}
            {a.clients.length > 0 && <span className="badge b-danger">{a.clients.length} cliente(s) afectado(s)</span>}
            {due !== null && due >= 0 && <span className={`badge ${due <= 3 ? 'b-danger' : due <= 7 ? 'b-warn' : 'b-muted'}`}>Plazo CISA: {due} d</span>}
          </div>
        </div>
        {canWrite && (
          <div className="row wrap" style={{ justifyContent: 'flex-end', maxWidth: 340 }}>
            {(ACTIONS[a.status] || []).map((act) => (
              <button key={act[0]} className={`btn btn-sm ${act[2]}`} onClick={() => setPending(act)}>{act[1]}</button>
            ))}
          </div>
        )}
      </div>

      <div className="grid g-main">
        <div className="stack">
          <div className="card">
            <div className="card-title">Descripción (CISA KEV)</div>
            <p className="prose">{a.description}</p>
            {a.required_action && <>
              <div className="card-title" style={{ marginTop: 20 }}>Acción requerida por CISA</div>
              <p className="prose dim" style={{ fontSize: 12.5 }}>{a.required_action}</p>
            </>}
          </div>

          <div className="card">
            <div className="card-title">Cómo se calculó el puntaje <span className="spacer" /><span className="mono bright" style={{ fontSize: 12 }}>{a.score} / 100</span></div>
            {(a.breakdown || []).map((b, i) => (
              <div className="factor" key={i}>
                <div><div className="factor-name">{b.factor}</div><div className="factor-det">{b.detalle}</div></div>
                <div className="bar"><span style={{ width: `${(b.puntos / maxPts) * 100}%` }} /></div>
                <div className="factor-pts">+{b.puntos}</div>
              </div>
            ))}
          </div>

          <div className="card">
            <div className="card-title">Clientes afectados</div>
            {(a.matched_clients || []).length === 0 ? (
              <Empty icon="◎">Ningún cliente tiene registrada esta tecnología en el inventario.<br /><Link to="/clientes">Revisar inventario de clientes</Link></Empty>
            ) : (
              <div className="table-wrap">
                <table className="tbl">
                  <thead><tr><th>Cliente</th><th>Tecnología registrada</th><th>Versión</th><th>Expuesta a internet</th></tr></thead>
                  <tbody>{a.matched_clients.map((m, i) => (
                    <tr key={i}>
                      <td className="prod">{m.client}</td>
                      <td>{m.vendor} {m.product === '*' ? <span className="dim">(todo el fabricante)</span> : m.product}</td>
                      <td className="num">{m.version || '—'}</td>
                      <td>{m.internet_exposed ? <span className="badge b-danger">Sí</span> : <span className="badge b-muted">No</span>}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <div className="card-title">Datos técnicos</div>
            <dl className="kv">
              <dt>Fabricante</dt><dd>{a.vendor}</dd>
              <dt>Producto</dt><dd>{a.product}</dd>
              <dt>CVSS</dt><dd>{a.cvss != null ? <><b>{a.cvss}</b> <span className="dim">{a.cvss_severity} · v{a.cvss_version}</span></> : <span className="dim">{a.nvd_ok ? '—' : 'Pendiente en NVD'}</span>}</dd>
              {a.cvss_vector && <><dt>Vector</dt><dd className="mono" style={{ fontSize: 11 }}>{a.cvss_vector}</dd></>}
              <dt>EPSS</dt><dd>{fmtPct(a.epss, 2)} {a.epss_percentile != null && <span className="dim">· percentil {fmtPct(a.epss_percentile, 0)}</span>}</dd>
              <dt>CWE</dt><dd>{a.cwes?.length ? a.cwes.join(', ') : '—'}</dd>
              <dt>Agregada a KEV</dt><dd>{fmtDate(a.date_added)}</dd>
              <dt>Plazo CISA</dt><dd>{fmtDate(a.due_date)}</dd>
              <dt>Publicada NVD</dt><dd>{fmtDate(a.nvd_published)}</dd>
              <dt>Ransomware</dt><dd>{a.ransomware === 'Known' ? 'Uso conocido en campañas' : 'Sin evidencia pública'}</dd>
            </dl>
          </div>

          <div className="card" style={{ borderColor: comm.data ? 'var(--accent-l)' : undefined }}>
            <div className="card-title"><IconMail width={14} />Comunicado al cliente</div>
            {comm.data ? (
              <div className="row">
                <div><div className="code mono" style={{ color: 'var(--accent-l)', fontWeight: 700 }}>{comm.data.code}</div><div className="hint">Estado: {COMM_STATUS[comm.data.status]?.label || comm.data.status}</div></div>
                <span className="spacer" />
                <Link to={`/comunicados/${comm.data.code}`} className="btn btn-sm btn-primary" style={{ textDecoration: 'none' }}>Abrir</Link>
              </div>
            ) : (
              <>
                <p className="hint" style={{ marginBottom: 14 }}>Genera el borrador del newsletter (cuerpo del mail) y del informe adjunto con el formato Vectus, a partir de los datos públicos de CISA y NVD.</p>
                {canWrite ? <button className="btn btn-sm btn-primary" onClick={generate} disabled={generating}>{generating ? 'Generando…' : 'Generar comunicado'}</button> : <span className="hint">Sin comunicado todavía.</span>}
              </>
            )}
          </div>
          <div className="card soon-card">
            <div className="card-title"><IconFlow width={14} />Caso de uso SOC</div>
            <p>El flujo y el playbook para el equipo de seguridad, asociados a <b className="mono">{a.code}</b>, llegan en la <b>Fase 7</b>.</p>
          </div>

          <div className="card">
            <div className="card-title">Historial</div>
            <div className="timeline">
              {[...(a.history || [])].reverse().map((h, i) => (
                <div className="tl-item" key={i}>
                  <div className="tl-head">
                    {EVENT_LABEL[h.evento] || h.evento}
                    {h.evento === 'cambio_estado' && <> · {STATUS[h.de]?.label || h.de} → {STATUS[h.a]?.label || h.a}</>}
                  </div>
                  <div className="tl-meta">
                    {fmtDateTime(h.fecha)}{h.usuario && ` · ${h.usuario}`}
                    {h.score_anterior != null && h.score_anterior !== h.score ? ` · score ${h.score_anterior} → ${h.score}` : h.score != null ? ` · score ${h.score}` : ''}
                  </div>
                  {h.comentario && <div className="tl-body">“{h.comentario}”</div>}
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-title">Referencias</div>
            <div className="stack" style={{ gap: 8 }}>
              {refs.slice(0, 14).map((r) => (
                <a key={r.url} href={r.url} target="_blank" rel="noreferrer noopener" className="row" style={{ fontSize: 12, wordBreak: 'break-all', gap: 6 }}>
                  <IconExternal width={12} style={{ flexShrink: 0 }} />{r.label}
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>

      {pending && (
        <Modal
          title={pending[1]}
          desc={`${a.code} pasará de "${STATUS[a.status]?.label}" a "${STATUS[pending[0]]?.label}". El cambio queda registrado en el historial y en la auditoría.`}
          onClose={() => setPending(null)}
          actions={<>
            <button className="btn btn-secondary" onClick={() => setPending(null)}>Cancelar</button>
            <button className={`btn ${pending[2] === 'btn-danger' ? 'btn-danger' : 'btn-primary'}`} onClick={doChange} disabled={busy || (pending[0] === 'descartada' && !comment.trim())}>
              {busy ? 'Guardando…' : 'Confirmar'}
            </button>
          </>}
        >
          <div className="fg">
            <label>Comentario {pending[0] === 'descartada' && <span className="req">*</span>}</label>
            <textarea value={comment} onChange={(e) => setComment(e.target.value)} placeholder={pending[0] === 'descartada' ? 'Motivo del descarte (obligatorio)' : 'Opcional: contexto para el equipo'} autoFocus />
          </div>
        </Modal>
      )}
    </>
  )
}
