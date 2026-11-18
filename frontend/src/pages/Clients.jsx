import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconPlus, IconRefresh, IconTrash } from '../components/icons'
import { Empty, ErrorBox, Loading, Modal, useFetch, useToast } from '../components/ui'

const EMPTY_CLIENT = { name: '', country: '', sector: '', contact_email: '' }
const EMPTY_TECH = { vendor: '', product: '', version: '', internet_exposed: false }

export default function Clients() {
  usePageHeader('Clientes', 'Inventario de tecnologías para cruzar con las vulnerabilidades')
  const { canWrite } = useAuth()
  const toast = useToast()
  const { data, error, loading, reload } = useFetch(() => api.get('/clients'), [])
  const [selId, setSelId] = useState(null)
  const [newClient, setNewClient] = useState(null)
  const [editClient, setEditClient] = useState(null)
  const [tech, setTech] = useState(EMPTY_TECH)
  const [suggest, setSuggest] = useState([])
  const [dirty, setDirty] = useState(false)

  const sel = data?.find((c) => c.id === selId) || data?.[0]

  useEffect(() => {
    const term = `${tech.vendor} ${tech.product}`.trim()
    if (term.length < 2) { setSuggest([]); return undefined }
    const t = setTimeout(() => api.get(`/catalog/vendors?q=${encodeURIComponent(tech.vendor || tech.product)}`).then(setSuggest).catch(() => {}), 250)
    return () => clearTimeout(t)
  }, [tech.vendor, tech.product])

  const run = async (fn, okMsg) => {
    try { await fn(); if (okMsg) toast(okMsg); await reload(true); return true } catch (e) { toast(e.message, 'err'); return false }
  }

  const createClient = async () => {
    let created
    const ok = await run(async () => { created = await api.post('/clients', clean(newClient)) }, 'Cliente creado')
    if (ok) { setNewClient(null); setSelId(created.id) }
  }
  const saveClient = async () => {
    const ok = await run(() => api.patch(`/clients/${editClient.id}`, clean(editClient)), 'Cliente actualizado')
    if (ok) { setEditClient(null); setDirty(true) }
  }
  const addTech = async (e) => {
    e.preventDefault()
    const ok = await run(() => api.post(`/clients/${sel.id}/technologies`, [{ ...tech, version: tech.version || null }]), 'Tecnología agregada')
    if (ok) { setTech(EMPTY_TECH); setDirty(true) }
  }
  const delTech = (t) => run(() => api.del(`/clients/${sel.id}/technologies/${t.id}`), 'Tecnología eliminada').then((ok) => ok && setDirty(true))
  const toggleActive = () => run(() => api.patch(`/clients/${sel.id}`, { active: !sel.active }), sel.active ? 'Cliente desactivado' : 'Cliente activado').then((ok) => ok && setDirty(true))
  const rescore = async () => {
    try { const r = await api.post('/alerts/rescore-all'); toast(`Puntajes recalculados: ${r.changed} de ${r.total} cambiaron`); setDirty(false) } catch (e) { toast(e.message, 'err') }
  }

  if (loading && !data) return <Loading />
  if (error) return <ErrorBox error={error} />

  return (
    <>
      {dirty && canWrite && (
        <div className="alert-box info row" style={{ marginBottom: 18 }}>
          El inventario cambió. Recalculá los puntajes para que las alertas reflejen los clientes afectados.
          <span className="spacer" />
          <button className="btn btn-sm btn-primary" onClick={rescore}><IconRefresh />Recalcular ahora</button>
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: 'minmax(240px, 320px) minmax(0, 1fr)' }}>
        <div>
          <div className="row" style={{ marginBottom: 12 }}>
            <span className="lbl">{data.length} cliente(s)</span><span className="spacer" />
            {canWrite && <button className="btn btn-sm btn-primary" onClick={() => setNewClient(EMPTY_CLIENT)}><IconPlus />Nuevo</button>}
          </div>
          {data.length === 0 && <Empty>Todavía no hay clientes cargados.</Empty>}
          {data.map((c) => (
            <div key={c.id} className={`list-item ${sel?.id === c.id ? 'on' : ''}`} onClick={() => setSelId(c.id)} style={{ opacity: c.active ? 1 : 0.55 }}>
              <div className="avatar" style={{ width: 30, height: 30, fontSize: 11 }}>{c.name.slice(0, 2).toUpperCase()}</div>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div className="name">{c.name}</div>
                <div className="mono dim" style={{ fontSize: 10.5 }}>{[c.sector, c.country].filter(Boolean).join(' · ') || 'Sin datos'}</div>
              </div>
              <span className="badge b-info">{c.technologies.length}</span>
            </div>
          ))}
        </div>

        {sel ? (
          <div className="stack">
            <div className="card">
              <div className="row">
                <div>
                  <h2 style={{ fontSize: 20, fontWeight: 800, color: 'var(--bright)' }}>{sel.name}</h2>
                  <div className="row wrap" style={{ marginTop: 8 }}>
                    {sel.sector && <span className="badge b-muted">{sel.sector}</span>}
                    {sel.country && <span className="badge b-muted">{sel.country}</span>}
                    {sel.contact_email && <span className="badge b-info">{sel.contact_email}</span>}
                    {!sel.active && <span className="badge b-warn">Inactivo</span>}
                  </div>
                </div>
                <span className="spacer" />
                {canWrite && <>
                  <button className="btn btn-sm btn-secondary" onClick={() => setEditClient({ ...sel })}>Editar</button>
                  <button className="btn btn-sm btn-secondary" onClick={toggleActive}>{sel.active ? 'Desactivar' : 'Activar'}</button>
                </>}
              </div>
            </div>

            <div className="card">
              <div className="card-title">Tecnologías registradas</div>
              {sel.technologies.length === 0 ? <Empty>Sin tecnologías. Cargá las que usa el cliente para que el motor detecte cuándo lo afecta una vulnerabilidad.</Empty> : (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead><tr><th>Fabricante</th><th>Producto</th><th>Versión</th><th>Expuesta a internet</th>{canWrite && <th />}</tr></thead>
                    <tbody>{sel.technologies.map((t) => (
                      <tr key={t.id}>
                        <td className="prod">{t.vendor}</td>
                        <td>{t.product || <span className="dim">Todo el fabricante</span>}</td>
                        <td className="num">{t.version || '—'}</td>
                        <td>{t.internet_exposed ? <span className="badge b-danger">Sí</span> : <span className="badge b-muted">No</span>}</td>
                        {canWrite && <td style={{ textAlign: 'right' }}><button className="icon-btn" title="Eliminar" onClick={() => delTech(t)}><IconTrash /></button></td>}
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              )}
            </div>

            {canWrite && (
              <form className="card" onSubmit={addTech}>
                <div className="card-title">Agregar tecnología</div>
                <div className="form-grid">
                  <div className="fg"><label>Fabricante <span className="req">*</span></label><input list="vendors" value={tech.vendor} onChange={(e) => setTech({ ...tech, vendor: e.target.value })} placeholder="Microsoft, Fortinet, Cisco…" required /></div>
                  <div className="fg"><label>Producto</label><input list="products" value={tech.product} onChange={(e) => setTech({ ...tech, product: e.target.value })} placeholder="Vacío = todo el fabricante" /></div>
                  <div className="fg"><label>Versión</label><input value={tech.version} onChange={(e) => setTech({ ...tech, version: e.target.value })} placeholder="Opcional" /></div>
                  <div className="fg" style={{ justifyContent: 'flex-end' }}>
                    <label className="check"><input type="checkbox" checked={tech.internet_exposed} onChange={(e) => setTech({ ...tech, internet_exposed: e.target.checked })} />Expuesta a internet</label>
                  </div>
                </div>
                <datalist id="vendors">{[...new Set(suggest.map((s) => s.vendor))].map((v) => <option key={v} value={v} />)}</datalist>
                <datalist id="products">{suggest.filter((s) => !tech.vendor || s.vendor.toLowerCase().includes(tech.vendor.toLowerCase())).map((s) => <option key={`${s.vendor}-${s.product}`} value={s.product}>{s.vendor} · {s.count} en KEV</option>)}</datalist>
                <div className="row" style={{ marginTop: 16 }}>
                  <p className="hint">Las sugerencias usan los nombres exactos del catálogo de CISA, así las coincidencias son precisas.</p>
                  <span className="spacer" />
                  <button className="btn btn-primary" disabled={!tech.vendor.trim()}><IconPlus />Agregar</button>
                </div>
              </form>
            )}
          </div>
        ) : <div className="card"><Empty>Seleccioná o creá un cliente.</Empty></div>}
      </div>

      {newClient && <ClientModal title="Nuevo cliente" value={newClient} onChange={setNewClient} onClose={() => setNewClient(null)} onSave={createClient} />}
      {editClient && <ClientModal title="Editar cliente" value={editClient} onChange={setEditClient} onClose={() => setEditClient(null)} onSave={saveClient} />}
    </>
  )
}

const clean = (c) => ({ name: c.name.trim(), country: c.country || null, sector: c.sector || null, contact_email: c.contact_email || null })

function ClientModal({ title, value, onChange, onClose, onSave }) {
  const set = (k) => (e) => onChange({ ...value, [k]: e.target.value })
  return (
    <Modal title={title} onClose={onClose} actions={<>
      <button className="btn btn-secondary" onClick={onClose}>Cancelar</button>
      <button className="btn btn-primary" onClick={onSave} disabled={!value.name.trim()}>Guardar</button>
    </>}>
      <div className="form-grid">
        <div className="fg full"><label>Empresa <span className="req">*</span></label><input value={value.name} onChange={set('name')} autoFocus /></div>
        <div className="fg"><label>País</label><input value={value.country || ''} onChange={set('country')} /></div>
        <div className="fg"><label>Rubro</label><input value={value.sector || ''} onChange={set('sector')} /></div>
        <div className="fg full"><label>Email de contacto</label><input type="email" value={value.contact_email || ''} onChange={set('contact_email')} /></div>
      </div>
    </Modal>
  )
}
