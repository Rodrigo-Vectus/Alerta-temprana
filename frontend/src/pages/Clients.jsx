import { useEffect, useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconPlus, IconRefresh, IconTrash } from '../components/icons'
import { Empty, ErrorBox, Loading, Modal, useFetch, useToast } from '../components/ui'

const EMPTY_CLIENT = { name: '', country: '', sector: '', contact_email: '' }
const EMPTY_TECH = { vendor: '', product: '', version: '', internet_exposed: false }
const EMPTY_CONTACT = { name: '', email: '', position: '' }

export default function Clients() {
  usePageHeader('Clientes', 'Contactos que reciben las alertas automáticas')
  const { canWrite } = useAuth()
  const toast = useToast()
  const { data, error, loading, reload } = useFetch(() => api.get('/clients'), [])
  const summary = useFetch(() => api.get('/clients/recipients'), [data])
  const [contact, setContact] = useState(EMPTY_CONTACT)
  const [showInventory, setShowInventory] = useState(false)
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
  const addContact = async (e) => {
    e.preventDefault()
    const ok = await run(() => api.post(`/clients/${sel.id}/contacts`, { ...contact, position: contact.position || null }), 'Contacto agregado')
    if (ok) setContact(EMPTY_CONTACT)
  }
  const toggleContact = (x) => run(() => api.patch(`/clients/${sel.id}/contacts/${x.id}`, { active: !x.active }), x.active ? 'Contacto pausado' : 'Contacto activado')
  const delContact = (x) => run(() => api.del(`/clients/${sel.id}/contacts/${x.id}`), 'Contacto eliminado')
  const delTech = (t) => run(() => api.del(`/clients/${sel.id}/technologies/${t.id}`), 'Tecnología eliminada').then((ok) => ok && setDirty(true))
  const toggleActive = () => run(() => api.patch(`/clients/${sel.id}`, { active: !sel.active }), sel.active ? 'Cliente desactivado' : 'Cliente activado').then((ok) => ok && setDirty(true))
  const rescore = async () => {
    try { const r = await api.post('/alerts/rescore-all'); toast(`Puntajes recalculados: ${r.changed} de ${r.total} cambiaron`); setDirty(false) } catch (e) { toast(e.message, 'err') }
  }

  if (loading && !data) return <Loading />
  if (error) return <ErrorBox error={error} />

  return (
    <>
      {summary.data && (
        <div className={`alert-box ${summary.data.contacts ? 'info' : 'err'}`} style={{ marginBottom: 18 }}>
          {summary.data.contacts
            ? <>Las alertas automáticas se envían a <b>{summary.data.contacts} contacto(s)</b> de <b>{summary.data.clients} cliente(s)</b> activos.</>
            : <>Todavía no hay contactos activos: cargá al menos uno para que las alertas se envíen automáticamente.</>}
        </div>
      )}
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
              <span className="badge b-info" title="Contactos activos">{c.contacts.filter((x) => x.active).length} ✉</span>
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
              <div className="card-title">Contactos que reciben las alertas <span className="spacer" /><span className="mono dim" style={{ fontSize: 10 }}>{sel.contacts.filter((x) => x.active).length} activo(s)</span></div>
              {sel.contacts.length === 0 ? <Empty icon="✉">Sin contactos. Agregá las personas de este cliente que deben recibir las alertas.</Empty> : (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead><tr><th>Nombre</th><th>Email</th><th>Cargo</th><th>Estado</th>{canWrite && <th />}</tr></thead>
                    <tbody>{sel.contacts.map((x) => (
                      <tr key={x.id} style={{ opacity: x.active ? 1 : 0.55 }}>
                        <td className="prod">{x.name || '—'}</td>
                        <td className="mono" style={{ fontSize: 12 }}>{x.email}</td>
                        <td>{x.position || <span className="dim">—</span>}</td>
                        <td>{x.active ? <span className="badge b-ok">Recibe</span> : <span className="badge b-muted">Pausado</span>}</td>
                        {canWrite && <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                          <button className="btn btn-sm btn-secondary" onClick={() => toggleContact(x)}>{x.active ? 'Pausar' : 'Activar'}</button>
                          <button className="icon-btn" style={{ display: 'inline-flex', marginLeft: 6 }} title="Eliminar" onClick={() => delContact(x)}><IconTrash /></button>
                        </td>}
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              )}
              {canWrite && (
                <form onSubmit={addContact} className="row wrap" style={{ marginTop: 16, alignItems: 'flex-end' }}>
                  <div className="fg" style={{ flex: 1, minWidth: 160 }}><label>Nombre</label><input value={contact.name} onChange={(e) => setContact({ ...contact, name: e.target.value })} placeholder="Nombre y apellido" /></div>
                  <div className="fg" style={{ flex: 1.3, minWidth: 200 }}><label>Email <span className="req">*</span></label><input type="email" value={contact.email} onChange={(e) => setContact({ ...contact, email: e.target.value })} placeholder="persona@cliente.com" required /></div>
                  <div className="fg" style={{ flex: 0.8, minWidth: 130 }}><label>Cargo</label><input value={contact.position} onChange={(e) => setContact({ ...contact, position: e.target.value })} placeholder="CISO, IT…" /></div>
                  <button className="btn btn-primary" disabled={!contact.email.trim()}><IconPlus />Agregar</button>
                </form>
              )}
            </div>

            <div className="card" style={{ padding: showInventory ? 22 : '16px 22px' }}>
              <div className="row" style={{ cursor: 'pointer' }} onClick={() => setShowInventory((v) => !v)}>
                <div className="card-title" style={{ margin: 0 }}>Inventario tecnológico <span className="badge b-muted">opcional</span> <span className="badge b-info">{sel.technologies.length}</span></div>
                <span className="spacer" /><span className="mono dim" style={{ fontSize: 11 }}>{showInventory ? 'OCULTAR ▲' : 'MOSTRAR ▼'}</span>
              </div>
              {showInventory && <p className="hint" style={{ margin: '12px 0 4px' }}>No es obligatorio: las alertas se envían a todos los contactos igual. Si cargás las tecnologías del cliente, la alerta sube de prioridad y el informe indica qué clientes están afectados.</p>}
            </div>

            {showInventory && <div className="card">
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
            </div>}

            {canWrite && showInventory && (
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

const clean = (c) => ({ name: c.name.trim(), country: c.country || null, sector: c.sector || null })

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
      </div>
    </Modal>
  )
}
