import { Fragment, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconArrowLeft, IconRefresh } from '../components/icons'
import { ErrorBox, fmtDateTime, Loading, Modal, Score, StatusBadge, useFetch, useToast } from '../components/ui'
import { UcBadge } from './UseCases'

const EXPOSURE = [['desconocido', 'Sin confirmar'], ['expuesto', 'Expuesto'], ['no_expuesto', 'No expuesto']]
const PATCH = [['pendiente', 'Pendiente'], ['en_curso', 'En curso'], ['parcheado', 'Parcheado'], ['no_aplica', 'No aplica']]
const IOC = [['no_revisado', 'No revisado'], ['sin_hallazgos', 'Sin hallazgos'], ['con_hallazgos', 'Con hallazgos']]
const EVENTS = {
  caso_creado: 'Caso creado', paso_completado: 'Paso completado', paso_reabierto: 'Paso reabierto',
  seguimiento_cliente: 'Seguimiento actualizado', clientes_agregados: 'Clientes agregados', caso_cerrado: 'Caso cerrado', caso_reabierto: 'Caso reabierto',
}

function Flow({ uc }) {
  return (
    <div className="flow">
      <div className="flow-head">
        <div className="t">{uc.code} | {uc.vendor} {uc.product}</div>
        <div className="s">{uc.cve_id} · {uc.alert_name} · CISA KEV</div>
      </div>
      {uc.flow.map((s, i) => (
        <Fragment key={s.id}>
          <div className="flow-arrow">↓</div>
          {s.type === 'decision' ? (
            <div className="flow-dec">
              <div className="q">{s.title}</div>
              {s.no_label && (
                <div className="flow-branches">
                  <div className={`flow-branch no ${s.answer === 'no' ? 'taken' : ''}`}><div className="lbl">↓ NO</div><div className="n">{s.no_label}</div></div>
                  <div className={`flow-branch si ${s.answer === 'si' ? 'taken' : ''}`}><div className="lbl">↓ SÍ</div><div className="n">{s.si_label}</div></div>
                </div>
              )}
              {!s.no_label && <div className="mono" style={{ fontSize: 11, color: 'var(--ok)', marginTop: 4 }}>SÍ</div>}
            </div>
          ) : (
            <div className={`flow-step ${s.state} ${i === uc.flow.length - 1 ? 'final' : ''}`}>
              <span className="st" />
              <div className="t">{s.title}</div>
              <div className="d">{s.desc}</div>
              {(s.detail || s.at) && <div className="x">{s.detail}{s.at ? ` · ${fmtDateTime(s.at)}` : ''}</div>}
            </div>
          )}
        </Fragment>
      ))}
      <div className="row wrap" style={{ justifyContent: 'center', gap: 14, marginTop: 18 }}>
        <span className="hint">✓ completado</span><span className="hint" style={{ color: 'var(--warn)' }}>● en curso</span>
        <span className="hint">◌ pendiente</span><span className="hint" style={{ color: 'var(--danger)' }}>✕ cancelado</span>
      </div>
    </div>
  )
}

export default function UseCaseDetail() {
  const { code } = useParams()
  const { canWrite } = useAuth()
  const toast = useToast()
  const { data: uc, error, loading, setData } = useFetch(() => api.get(`/usecases/${code}`), [code], { interval: 60000 })
  const [tab, setTab] = useState('flujo')
  const [closing, setClosing] = useState(null)
  const [notes, setNotes] = useState({})
  usePageHeader(uc ? `${uc.code} · ${uc.cve_id}` : code, uc ? `${uc.vendor} ${uc.product}` : 'Caso de uso SOC')

  if (loading && !uc) return <Loading />
  if (error) return <><Link to="/casos-de-uso" className="back"><IconArrowLeft width={14} />Volver</Link><ErrorBox error={error} /></>

  const call = async (fn, msg) => { try { setData(await fn()); if (msg) toast(msg) } catch (e) { toast(e.message, 'err') } }
  const locked = !canWrite || uc.status === 'cerrado'
  const pct = uc.progress.total ? Math.round((uc.progress.done / uc.progress.total) * 100) : 0
  const setRow = (r, body, msg) => call(() => api.patch(`/usecases/${code}/clients/${r.id}`, body), msg)

  return (
    <>
      <Link to="/casos-de-uso" className="back"><IconArrowLeft width={14} />Volver a casos de uso</Link>
      <div className="hero">
        <Score value={uc.score} xl />
        <div style={{ minWidth: 0, flex: 1 }}>
          <h2>{uc.alert_name}</h2>
          <div className="hero-meta">
            <UcBadge status={uc.status} />
            <Link to={`/alertas/${uc.alert_code}`} className="badge b-info" style={{ textDecoration: 'none' }}>{uc.alert_code}</Link>
            <StatusBadge status={uc.alert_status} />
            {uc.communication && <Link to={`/comunicados/${uc.communication.code}`} className="badge b-cyan" style={{ textDecoration: 'none' }}>{uc.communication.code} · {uc.communication.status}</Link>}
            {uc.clients.ioc > 0 && <span className="badge b-danger">{uc.clients.ioc} cliente(s) con indicadores de compromiso</span>}
          </div>
          <div className="row" style={{ marginTop: 12, maxWidth: 520 }}>
            <div className="progress" style={{ flex: 1 }}><span style={{ width: `${pct}%` }} /></div>
            <span className="mono dim" style={{ fontSize: 11 }}>Playbook {uc.progress.done}/{uc.progress.total} · Clientes parcheados {uc.clients.patched}/{uc.clients.total}</span>
          </div>
        </div>
        {canWrite && (uc.status === 'cerrado'
          ? <button className="btn btn-sm btn-secondary" onClick={() => call(() => api.post(`/usecases/${code}/reopen`), 'Caso reabierto')}>Reabrir caso</button>
          : <button className="btn btn-sm btn-success" onClick={() => setClosing('')}>Cerrar caso</button>)}
      </div>

      <div className="toolbar">
        <div className="chips">
          {[['flujo', 'Flujo'], ['playbook', `Playbook (${uc.progress.done}/${uc.progress.total})`], ['clientes', `Seguimiento por cliente (${uc.clients.total})`], ['historial', 'Historial']].map(([k, l]) => (
            <button key={k} className={`chip ${tab === k ? 'on' : ''}`} onClick={() => setTab(k)}>{l}</button>
          ))}
        </div>
      </div>

      {tab === 'flujo' && <div className="card"><Flow uc={uc} /></div>}

      {tab === 'playbook' && (
        <div className="card">
          <p className="hint" style={{ marginBottom: 16 }}>Pasos para el equipo de seguridad, armados según el tipo de vulnerabilidad y la cobertura de FortiGuard. Tildá cada paso a medida que se completa: queda registrado quién y cuándo.</p>
          {uc.playbook.map((sec) => {
            const done = sec.steps.filter((s) => s.done).length
            return (
              <div className="pb-sec" key={sec.id}>
                <h5>{sec.title} <span className={`badge ${done === sec.steps.length ? 'b-ok' : 'b-muted'}`}>{done}/{sec.steps.length}</span></h5>
                {sec.steps.map((s) => (
                  <label key={s.id} className={`pb-step ${s.done ? 'done' : ''}`} style={{ textTransform: 'none', letterSpacing: 0, fontFamily: 'inherit' }}>
                    <input type="checkbox" checked={s.done} disabled={locked}
                      onChange={(e) => {
                        const done = e.target.checked
                        // actualización inmediata en pantalla; el servidor confirma y registra quién lo hizo
                        setData({ ...uc, playbook: uc.playbook.map((x) => ({ ...x, steps: x.steps.map((y) => (y.id === s.id ? { ...y, done } : y)) })) })
                        call(() => api.patch(`/usecases/${code}/steps/${s.id}`, { done }))
                      }} />
                    <div><div className="txt">{s.text}</div>{s.done && <div className="who">{s.done_by} · {fmtDateTime(s.done_at)}</div>}</div>
                  </label>
                ))}
              </div>
            )
          })}
        </div>
      )}

      {tab === 'clientes' && (
        <div className="card" style={{ padding: '6px 22px' }}>
          <div className="row" style={{ padding: '14px 0 6px' }}>
            <p className="hint">Estado de cada cliente que recibió la alerta. Los cambios quedan en el historial del caso.</p>
            <span className="spacer" />
            {!locked && <button className="btn btn-sm btn-secondary" onClick={() => call(() => api.post(`/usecases/${code}/sync-clients`), 'Clientes sincronizados')}><IconRefresh />Sumar clientes nuevos</button>}
          </div>
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr><th>Cliente</th><th>Exposición</th><th>Parcheo</th><th>Indicadores de compromiso</th><th>Notas</th></tr></thead>
              <tbody>{uc.client_rows.map((r) => (
                <tr key={r.id}>
                  <td><div className="prod">{r.client}</div>{r.updated_by && <div className="sub mono">{r.updated_by}</div>}</td>
                  {[['exposure', EXPOSURE], ['patch', PATCH], ['ioc', IOC]].map(([f, opts]) => (
                    <td key={f}>
                      <select className="sel-sm" value={r[f]} disabled={locked} onChange={(e) => setRow(r, { [f]: e.target.value }, 'Seguimiento actualizado')}
                        style={{ width: 150, borderColor: (r[f] === 'con_hallazgos' || r[f] === 'expuesto') ? 'var(--danger)' : (r[f] === 'parcheado' || r[f] === 'sin_hallazgos' || r[f] === 'no_expuesto') ? 'var(--ok)' : undefined }}>
                        {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                      </select>
                    </td>
                  ))}
                  <td style={{ minWidth: 220 }}>
                    <input className="sel-sm" defaultValue={r.notes || ''} disabled={locked} placeholder="Versión, fecha, ticket…"
                      onChange={(e) => setNotes({ ...notes, [r.id]: e.target.value })}
                      onBlur={() => notes[r.id] !== undefined && notes[r.id] !== (r.notes || '') && setRow(r, { notes: notes[r.id] }, 'Nota guardada')} />
                  </td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'historial' && (
        <div className="card">
          <div className="timeline">
            {[...(uc.history || [])].reverse().map((h, i) => (
              <div className="tl-item" key={i}>
                <div className="tl-head">{EVENTS[h.evento] || h.evento}{h.cliente && ` · ${h.cliente}`}</div>
                <div className="tl-meta">{fmtDateTime(h.fecha)} · {h.usuario}</div>
                {h.paso && <div className="tl-body">{h.paso}</div>}
                {h.cambios && <div className="tl-body mono" style={{ fontSize: 11 }}>{Object.entries(h.cambios).map(([k, v]) => `${k}: ${v}`).join(' · ')}</div>}
                {h.comentario && <div className="tl-body">“{h.comentario}”</div>}
              </div>
            ))}
          </div>
          {uc.closure_notes && <div className="alert-box ok" style={{ marginTop: 16 }}><b>Notas de cierre:</b> {uc.closure_notes}</div>}
        </div>
      )}

      {closing !== null && (
        <Modal title={`Cerrar ${uc.code}`} desc={`Playbook: ${uc.progress.done}/${uc.progress.total} pasos. Clientes parcheados o sin impacto: ${uc.clients.patched}/${uc.clients.total}. La alerta ${uc.alert_code} pasa a "Cerrada".`}
          onClose={() => setClosing(null)}
          actions={<><button className="btn btn-secondary" onClick={() => setClosing(null)}>Cancelar</button>
            <button className="btn btn-success" onClick={async () => { await call(() => api.post(`/usecases/${code}/close`, { notes: closing }), 'Caso cerrado'); setClosing(null) }}>Cerrar caso</button></>}>
          <div className="fg"><label>Notas de cierre</label><textarea value={closing} onChange={(e) => setClosing(e.target.value)} placeholder="Resultado, pendientes, lecciones aprendidas…" autoFocus /></div>
        </Modal>
      )}
    </>
  )
}
