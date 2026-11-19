import { useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconPlus } from '../components/icons'
import { ErrorBox, fmtDateTime, Loading, Modal, RoleBadge, useFetch, useToast } from '../components/ui'

const NEW = { email: '', full_name: '', role: 'analista' }
const ROLES = [
  ['admin', 'Administrador — gestiona usuarios y ve la auditoría'],
  ['analista', 'Analista SOC — valida alertas, edita clientes'],
  ['lector', 'Lector — solo consulta'],
]

export default function Users() {
  usePageHeader('Usuarios', 'Accesos a la consola y roles')
  const { user: me } = useAuth()
  const toast = useToast()
  const { data, error, loading, reload } = useFetch(() => api.get('/users'), [])
  const [form, setForm] = useState(null)

  const save = async () => {
    try { await api.post('/users', form); toast('Usuario creado. Ingresa con un código que le llega a su correo.'); setForm(null); reload(true) } catch (e) { toast(e.message, 'err') }
  }
  const patch = async (u, body, msg) => {
    try { await api.patch(`/users/${u.id}`, body); toast(msg); reload(true) } catch (e) { toast(e.message, 'err') }
  }

  if (loading && !data) return <Loading />
  if (error) return <ErrorBox error={error} />

  return (
    <>
      <div className="toolbar"><span className="lbl">{data.length} usuario(s)</span><span className="spacer" /><button className="btn btn-primary" onClick={() => setForm(NEW)}><IconPlus />Nuevo usuario</button></div>
      <div className="card" style={{ padding: '6px 22px' }}>
        <div className="table-wrap">
          <table className="tbl">
            <thead><tr><th>Usuario</th><th>Rol</th><th>Estado</th><th>Último ingreso</th><th style={{ textAlign: 'right' }}>Acciones</th></tr></thead>
            <tbody>{data.map((u) => (
              <tr key={u.id} style={{ opacity: u.active ? 1 : 0.55 }}>
                <td><div className="prod">{u.full_name || '—'}</div><div className="sub mono">{u.email}</div></td>
                <td>
                  {u.id === me.id ? <RoleBadge role={u.role} /> : (
                    <select value={u.role} style={{ width: 140, padding: '6px 10px', fontSize: 12 }} onChange={(e) => patch(u, { role: e.target.value }, 'Rol actualizado')}>
                      <option value="admin">admin</option><option value="analista">analista</option><option value="lector">lector</option>
                    </select>
                  )}
                </td>
                <td>
                  <div className="row wrap" style={{ gap: 6 }}>
                    {u.active ? <span className="badge b-ok">Activo</span> : <span className="badge b-muted">Inactivo</span>}
                    {u.locked && <span className="badge b-danger">Bloqueado</span>}
                  </div>
                </td>
                <td className="num">{fmtDateTime(u.last_login_at)}</td>
                <td style={{ textAlign: 'right' }}>
                  {u.id !== me.id && <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
                    <button className="btn btn-sm btn-secondary" onClick={() => patch(u, { active: !u.active }, u.active ? 'Usuario desactivado' : 'Usuario activado')}>{u.active ? 'Desactivar' : 'Activar'}</button>
                  </div>}
                </td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>

      {form && (
        <Modal title="Nuevo usuario" desc="No usa contraseña: para ingresar escribe su correo y recibe un código de 6 dígitos. Solo los usuarios cargados acá reciben el código." onClose={() => setForm(null)}
          actions={<><button className="btn btn-secondary" onClick={() => setForm(null)}>Cancelar</button><button className="btn btn-primary" onClick={save} disabled={!form.email.includes('@')}>Crear</button></>}>
          <div className="form-grid">
            <div className="fg full"><label>Nombre y apellido</label><input value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} autoFocus /></div>
            <div className="fg full"><label>Email <span className="req">*</span></label><input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
            <div className="fg full"><label>Rol</label>
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{ROLES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
            </div>
          </div>
        </Modal>
      )}

    </>
  )
}
