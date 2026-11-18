import { Fragment, useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, download } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconArrowLeft, IconMail, IconPlus, IconRefresh, IconTrash } from '../components/icons'
import { ErrorBox, fmtDateTime, Loading, Modal, Score, StatusBadge, useFetch, useToast } from '../components/ui'
import { CommBadge } from './Communications'

// ---------- Editores reutilizables ----------
function Field({ label, value, onChange, area = false, rows = 3, disabled }) {
  return (
    <div className="fg full">
      <label>{label}</label>
      {area
        ? <textarea rows={rows} value={value || ''} onChange={(e) => onChange(e.target.value)} disabled={disabled} />
        : <input value={value || ''} onChange={(e) => onChange(e.target.value)} disabled={disabled} />}
    </div>
  )
}

function ListEditor({ label, items, onChange, disabled, numbered = false, rows = 2, addLabel = 'Agregar' }) {
  const set = (i, v) => onChange(items.map((x, j) => (j === i ? v : x)))
  return (
    <div className="fg full">
      <label>{label}</label>
      <div className="stack" style={{ gap: 8 }}>
        {items.map((it, i) => (
          <div key={i} className="row" style={{ alignItems: 'flex-start' }}>
            {numbered && <span className="badge b-info" style={{ marginTop: 10 }}>{String(i + 1).padStart(2, '0')}</span>}
            <textarea rows={rows} value={it} onChange={(e) => set(i, e.target.value)} disabled={disabled} style={{ minHeight: 0 }} />
            {!disabled && <button className="icon-btn" title="Quitar" onClick={() => onChange(items.filter((_, j) => j !== i))} style={{ marginTop: 6 }}><IconTrash /></button>}
          </div>
        ))}
        {!disabled && <button className="btn btn-sm btn-secondary" style={{ alignSelf: 'flex-start' }} onClick={() => onChange([...items, ''])}><IconPlus />{addLabel}</button>}
      </div>
    </div>
  )
}

function ObjListEditor({ label, items, onChange, fields, disabled, addLabel = 'Agregar', empty }) {
  const set = (i, k, v) => onChange(items.map((x, j) => (j === i ? { ...x, [k]: v } : x)))
  return (
    <div className="fg full">
      <label>{label}</label>
      <div className="stack" style={{ gap: 8 }}>
        {items.map((it, i) => (
          <div key={i} className="row" style={{ alignItems: 'flex-start' }}>
            {fields.map((f) => (f.area
              ? <textarea key={f.k} rows={2} value={it[f.k] || ''} placeholder={f.ph} onChange={(e) => set(i, f.k, e.target.value)} disabled={disabled} style={{ flex: f.flex || 1, minHeight: 0 }} />
              : <input key={f.k} value={it[f.k] || ''} placeholder={f.ph} onChange={(e) => set(i, f.k, e.target.value)} disabled={disabled} style={{ flex: f.flex || 1 }} />))}
            {!disabled && <button className="icon-btn" title="Quitar" onClick={() => onChange(items.filter((_, j) => j !== i))} style={{ marginTop: 6 }}><IconTrash /></button>}
          </div>
        ))}
        {!disabled && <button className="btn btn-sm btn-secondary" style={{ alignSelf: 'flex-start' }} onClick={() => onChange([...items, empty])}><IconPlus />{addLabel}</button>}
      </div>
    </div>
  )
}

const TECH_LABELS = { cve: 'CVE', vendor: 'Fabricante', product: 'Producto', cvss: 'CVSS', vector: 'Vector', epss: 'EPSS', cwe: 'CWE', date_added: 'Agregada KEV', due_date: 'Plazo CISA', ransomware: 'Ransomware' }

// ---------- Página ----------
export default function CommunicationEditor() {
  const { code } = useParams()
  const { user, canWrite } = useAuth()
  const toast = useToast()
  const { data, error, loading, setData } = useFetch(() => api.get(`/communications/${code}`), [code])
  const mail = useFetch(() => api.get('/communications/mail-status'), [])
  const [content, setContent] = useState(null)
  const [dirty, setDirty] = useState(false)
  const [tab, setTab] = useState('newsletter')
  const [html, setHtml] = useState('')
  const [pdfUrl, setPdfUrl] = useState(null)
  const [busy, setBusy] = useState('')
  const [sendModal, setSendModal] = useState(null)
  const [confirmRegen, setConfirmRegen] = useState(false)
  const previewTimer = useRef(null)
  usePageHeader(data ? `${data.code} · ${data.cve_id}` : code, data ? data.title : 'Comunicado')

  useEffect(() => { if (data) { setContent(data.content); setDirty(false) } }, [data])

  // Vista previa en vivo del newsletter
  useEffect(() => {
    if (!content) return undefined
    clearTimeout(previewTimer.current)
    previewTimer.current = setTimeout(() => {
      api.text('/communications/preview', 'POST', { content }).then(setHtml).catch(() => {})
    }, 400)
    return () => clearTimeout(previewTimer.current)
  }, [content])

  useEffect(() => () => pdfUrl && URL.revokeObjectURL(pdfUrl), [pdfUrl])

  if (loading && !data) return <Loading />
  if (error) return <><Link to="/comunicados" className="back"><IconArrowLeft width={14} />Volver</Link><ErrorBox error={error} /></>
  if (!content) return <Loading />

  const locked = !canWrite || data.status === 'enviado'
  const set = (k) => (v) => { setContent((c) => ({ ...c, [k]: v })); setDirty(true) }

  const run = async (key, fn, okMsg) => {
    setBusy(key)
    try { const r = await fn(); if (okMsg) toast(okMsg); return r } catch (e) { toast(e.message, 'err') } finally { setBusy('') }
    return null
  }
  const save = () => run('save', async () => { const r = await api.patch(`/communications/${code}`, { content }); setData(r) }, 'Cambios guardados')
  const approve = async () => {
    if (dirty) await save()
    await run('approve', async () => setData(await api.post(`/communications/${code}/approve`)), 'Comunicado aprobado')
  }
  const reopen = () => run('approve', async () => setData(await api.post(`/communications/${code}/reopen`)), 'Comunicado vuelto a borrador')
  const regenerate = () => run('regen', async () => { setData(await api.post(`/communications/from-alert/${data.alert_code}?regenerate=true`)); setConfirmRegen(false) }, 'Contenido regenerado desde la plantilla')
  const loadPdf = () => run('pdf', async () => {
    if (dirty) await save()
    const { blob } = await api.blob(`/communications/${code}/document.pdf?inline=true`)
    if (pdfUrl) URL.revokeObjectURL(pdfUrl)
    setPdfUrl(URL.createObjectURL(blob))
  })
  const sendTest = () => run('send', async () => {
    if (dirty) await save()
    const r = await api.post(`/communications/${code}/send-test`, { to: sendModal.to, attach_docx: sendModal.docx })
    setSendModal(null)
    setData(await api.get(`/communications/${code}`))
    if (r.warning) toast(r.warning, 'err')
    return r
  }, 'Mail de prueba enviado')

  return (
    <>
      <Link to="/comunicados" className="back"><IconArrowLeft width={14} />Volver a comunicados</Link>

      <div className="hero">
        <Score value={data.score} xl />
        <div style={{ minWidth: 0, flex: 1 }}>
          <h2>{content.title}</h2>
          <div className="hero-meta">
            <CommBadge status={data.status} />
            <Link to={`/alertas/${data.alert_code}`} className="badge b-info" style={{ textDecoration: 'none' }}>{data.alert_code}</Link>
            <StatusBadge status={data.alert_status} />
            {data.clients.length > 0 && <span className="badge b-danger">Clientes afectados: {data.clients.join(', ')}</span>}
            {dirty && <span className="badge b-warn">Cambios sin guardar</span>}
          </div>
          {data.approved_by && <div className="hint" style={{ marginTop: 8 }}>Aprobado por {data.approved_by} · {fmtDateTime(data.approved_at)}</div>}
        </div>
        {canWrite && (
          <div className="row wrap" style={{ justifyContent: 'flex-end', maxWidth: 380 }}>
            {dirty && <button className="btn btn-sm btn-primary" onClick={save} disabled={!!busy}>{busy === 'save' ? 'Guardando…' : 'Guardar cambios'}</button>}
            {data.status === 'borrador' && <button className="btn btn-sm btn-success" onClick={approve} disabled={!!busy}>Aprobar</button>}
            {data.status === 'aprobado' && <button className="btn btn-sm btn-secondary" onClick={reopen} disabled={!!busy}>Volver a borrador</button>}
            <button className="btn btn-sm btn-secondary" onClick={() => setSendModal({ to: user.email, docx: false })} disabled={!!busy}><IconMail />Enviar prueba</button>
          </div>
        )}
      </div>

      <div className="toolbar">
        <div className="chips">
          {[['newsletter', 'Newsletter (cuerpo del mail)'], ['informe', 'Informe (adjunto)'], ['envios', `Envíos (${data.sends_log.length})`]].map(([k, l]) => (
            <button key={k} className={`chip ${tab === k ? 'on' : ''}`} onClick={() => setTab(k)}>{l}</button>
          ))}
        </div>
        <span className="spacer" />
        <button className="btn btn-sm btn-secondary" onClick={() => run('docx', () => download(`/communications/${code}/document.docx`))} disabled={!!busy || dirty} title={dirty ? 'Guardá los cambios primero' : ''}>Descargar DOCX</button>
        <button className="btn btn-sm btn-secondary" onClick={() => run('dl', () => download(`/communications/${code}/document.pdf`))} disabled={!!busy || dirty} title={dirty ? 'Guardá los cambios primero' : ''}>{busy === 'dl' ? 'Generando…' : 'Descargar PDF'}</button>
        {canWrite && data.status !== 'enviado' && <button className="btn btn-sm btn-secondary" onClick={() => setConfirmRegen(true)} disabled={!!busy}><IconRefresh />Regenerar</button>}
      </div>

      {tab === 'newsletter' && (
        <div className="grid" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1.05fr)', alignItems: 'start' }}>
          <div className="stack">
            <div className="card">
              <div className="card-title">Encabezado</div>
              <div className="form-grid">
                <Field label="Asunto del mail" value={content.subject} onChange={set('subject')} disabled={locked} />
                <div className="fg"><label>Etiqueta</label>
                  <select value={content.badge} onChange={(e) => set('badge')(e.target.value)} disabled={locked}>
                    {['ALERTA DE SEGURIDAD · EXPLOTACIÓN ACTIVA', 'ALERTA DE SEGURIDAD · ZERO-DAY', 'ALERTA DE SEGURIDAD · CRÍTICA', 'AVISO DE SEGURIDAD'].map((b) => <option key={b}>{b}</option>)}
                  </select>
                </div>
                <div className="fg"><label>Fecha de emisión</label><input type="date" value={content.emitted || ''} onChange={(e) => set('emitted')(e.target.value)} disabled={locked} /></div>
                <Field label="Título" value={content.title} onChange={set('title')} disabled={locked} area rows={2} />
                <Field label="Subtítulo" value={content.subtitle} onChange={set('subtitle')} disabled={locked} />
              </div>
            </div>
            <div className="card">
              <div className="card-title">¿Qué pasó?</div>
              <Field label="Texto" value={content.what_happened} onChange={set('what_happened')} disabled={locked} area rows={6} />
            </div>
            <div className="card">
              <div className="card-title">¿Qué hacer?</div>
              <ListEditor label="Pasos" items={content.actions} onChange={set('actions')} disabled={locked} numbered addLabel="Agregar paso" />
            </div>
            <div className="card">
              <div className="card-title">Cómo te protege Fortinet</div>
              <Field label="Bajada" value={content.fortinet_intro} onChange={set('fortinet_intro')} disabled={locked} />
              <div className="stack" style={{ gap: 10, marginTop: 14 }}>
                {content.fortinet.map((f, i) => (
                  <div key={f.key || i} className="list-item" style={{ cursor: 'default', alignItems: 'flex-start', opacity: f.included ? 1 : 0.5 }}>
                    <input type="checkbox" checked={f.included} disabled={locked} style={{ marginTop: 12 }}
                      onChange={(e) => set('fortinet')(content.fortinet.map((x, j) => (j === i ? { ...x, included: e.target.checked } : x)))} />
                    <div className="stack" style={{ gap: 6, flex: 1 }}>
                      <input value={f.product} disabled={locked} onChange={(e) => set('fortinet')(content.fortinet.map((x, j) => (j === i ? { ...x, product: e.target.value } : x)))} style={{ fontWeight: 700 }} />
                      <textarea rows={2} value={f.text} disabled={locked} onChange={(e) => set('fortinet')(content.fortinet.map((x, j) => (j === i ? { ...x, text: e.target.value } : x)))} style={{ minHeight: 0 }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="card">
              <div className="card-title">Cierre</div>
              <Field label="Importante" value={content.important} onChange={set('important')} disabled={locked} area rows={2} />
              <div style={{ height: 14 }} />
              <ObjListEditor label="Referencias" items={content.references} onChange={set('references')} disabled={locked}
                fields={[{ k: 'label', ph: 'Nombre', flex: 0.35 }, { k: 'url', ph: 'https://…' }]} empty={{ label: '', url: '' }} addLabel="Agregar referencia" />
            </div>
          </div>

          <div className="card" style={{ position: 'sticky', top: 100, padding: 0, overflow: 'hidden' }}>
            <div className="card-title" style={{ padding: '16px 20px 0' }}>Vista previa del mail <span className="spacer" /><span className="mono dim" style={{ fontSize: 10 }}>en vivo</span></div>
            <iframe title="Vista previa del newsletter" srcDoc={html} sandbox="allow-popups" style={{ width: '100%', height: 'calc(100vh - 200px)', border: 0, background: '#f3f6fb' }} />
          </div>
        </div>
      )}

      {tab === 'informe' && (
        <div className="grid" style={{ gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1.05fr)', alignItems: 'start' }}>
          <div className="stack">
            <div className="alert-box info">El informe usa además el título, ¿Qué pasó?, ¿Qué hacer?, Fortinet e Importante de la pestaña Newsletter. Acá se editan las secciones propias del documento.</div>
            <div className="card">
              <div className="card-title">Portada y resumen</div>
              <Field label="Clasificación" value={content.classification} onChange={set('classification')} disabled={locked} />
              <div style={{ height: 14 }} />
              <Field label="1. Resumen ejecutivo" value={content.executive_summary} onChange={set('executive_summary')} disabled={locked} area rows={6} />
            </div>
            <div className="card">
              <div className="card-title">2. Datos técnicos (de CISA / NVD)</div>
              <dl className="kv">{Object.keys(TECH_LABELS).filter((k) => content.technical?.[k] != null).map((k) => [k, content.technical[k]]).map(([k, v]) => <Fragment key={k}><dt>{TECH_LABELS[k] || k}</dt><dd className="mono" style={{ fontSize: 12 }}>{v}</dd></Fragment>)}</dl>
            </div>
            <div className="card">
              <ListEditor label="3. Estado actual y explotación" items={content.status_items} onChange={set('status_items')} disabled={locked} />
            </div>
            <div className="card">
              <Field label="4. Impacto · introducción" value={content.impact_intro} onChange={set('impact_intro')} disabled={locked} />
              <div style={{ height: 14 }} />
              <ObjListEditor label="Tabla de impacto" items={content.impact_rows} onChange={set('impact_rows')} disabled={locked}
                fields={[{ k: 'area', ph: 'Área', flex: 0.35 }, { k: 'text', ph: 'Descripción e impacto', area: true }]} empty={{ area: '', text: '' }} addLabel="Agregar fila" />
            </div>
            <div className="card">
              <ListEditor label="5. Productos afectados" items={content.affected_products} onChange={set('affected_products')} disabled={locked} rows={1} />
            </div>
            <div className="card">
              <ListEditor label="6. Recomendaciones de hardening" items={content.hardening} onChange={set('hardening')} disabled={locked} />
            </div>
            <div className="card">
              <Field label="8. Próximos pasos y soporte" value={content.next_steps} onChange={set('next_steps')} disabled={locked} area rows={5} />
            </div>
          </div>
          <div className="card" style={{ position: 'sticky', top: 100, padding: 0, overflow: 'hidden' }}>
            <div className="card-title" style={{ padding: '16px 20px 0' }}>Vista previa del PDF <span className="spacer" />
              <button className="btn btn-sm btn-primary" onClick={loadPdf} disabled={!!busy}>{busy === 'pdf' ? 'Generando…' : pdfUrl ? 'Actualizar' : 'Generar vista previa'}</button>
            </div>
            {pdfUrl
              ? <iframe title="Informe PDF" src={pdfUrl} style={{ width: '100%', height: 'calc(100vh - 200px)', border: 0, marginTop: 12 }} />
              : <div className="empty" style={{ padding: '80px 20px' }}><div className="big">▤</div>Generá la vista previa para ver el informe tal como lo recibe el cliente.</div>}
          </div>
        </div>
      )}

      {tab === 'envios' && (
        <div className="grid g2" style={{ alignItems: 'start' }}>
          <div className="card">
            <div className="card-title">Historial de envíos</div>
            {data.sends_log.length === 0 ? <div className="empty">Todavía no se envió este comunicado.</div> : (
              <div className="timeline">
                {[...data.sends_log].reverse().map((s, i) => (
                  <div className="tl-item" key={i}>
                    <div className="tl-head">{s.tipo === 'prueba' ? 'Envío de prueba' : 'Envío a clientes'} · {s.ok ? <span className="badge b-ok">OK</span> : <span className="badge b-danger">Error</span>}</div>
                    <div className="tl-meta">{fmtDateTime(s.fecha)} · {s.usuario} → {s.to.join(', ')}</div>
                    {s.adjuntos?.length > 0 && <div className="tl-body">Adjuntos: {s.adjuntos.join(', ')}</div>}
                    {s.error && <div className="tl-body" style={{ color: 'var(--danger)' }}>{s.error}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
          <div className="card">
            <div className="card-title">Configuración de correo</div>
            {mail.data && (mail.data.configured ? (
              <dl className="kv">
                <dt>Remitente</dt><dd>{mail.data.from_name} &lt;{mail.data.from}&gt;</dd>
                <dt>Servidor</dt><dd className="mono" style={{ fontSize: 12 }}>{mail.data.host}:{mail.data.port} ({mail.data.security})</dd>
              </dl>
            ) : <div className="alert-box info">Falta configurar el SMTP en el <span className="mono">.env</span> del servidor.</div>)}
            <p className="hint" style={{ marginTop: 14 }}>El envío a clientes afectados (según el inventario) se habilita en la Fase 8. Por ahora solo envíos de prueba.</p>
          </div>
        </div>
      )}

      {sendModal && (
        <Modal title="Enviar mail de prueba" desc="Se envía el newsletter como cuerpo del mail y el informe en PDF adjunto, con el asunto marcado como [PRUEBA]. No se envía a clientes."
          onClose={() => setSendModal(null)}
          actions={<><button className="btn btn-secondary" onClick={() => setSendModal(null)}>Cancelar</button>
            <button className="btn btn-primary" onClick={sendTest} disabled={busy === 'send' || !mail.data?.configured}>{busy === 'send' ? 'Enviando…' : 'Enviar'}</button></>}>
          <div className="stack" style={{ gap: 14 }}>
            <div className="fg"><label>Destinatario</label><input type="email" value={sendModal.to} onChange={(e) => setSendModal({ ...sendModal, to: e.target.value })} /></div>
            <label className="check"><input type="checkbox" checked={sendModal.docx} onChange={(e) => setSendModal({ ...sendModal, docx: e.target.checked })} />Adjuntar también el DOCX editable</label>
            {mail.data && !mail.data.configured && <div className="alert-box err">El correo no está configurado en el servidor.</div>}
          </div>
        </Modal>
      )}

      {confirmRegen && (
        <Modal title="Regenerar desde la plantilla" desc="Se descartan las ediciones y se vuelve a armar todo el contenido con los datos actuales de CISA y NVD. El comunicado vuelve a borrador."
          onClose={() => setConfirmRegen(false)}
          actions={<><button className="btn btn-secondary" onClick={() => setConfirmRegen(false)}>Cancelar</button><button className="btn btn-danger" onClick={regenerate} disabled={!!busy}>Regenerar</button></>} />
      )}
    </>
  )
}
