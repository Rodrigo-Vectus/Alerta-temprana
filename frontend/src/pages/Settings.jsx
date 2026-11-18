import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { ErrorBox, Loading, useFetch, useToast } from '../components/ui'

export default function Settings() {
  usePageHeader('Configuración', 'Envío automático de alertas a clientes')
  const { isAdmin } = useAuth()
  const toast = useToast()
  const { data, error, loading, setData } = useFetch(() => api.get('/settings'), [])
  const rc = useFetch(() => api.get('/clients/recipients'), [])
  const [form, setForm] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => { if (data) setForm({ ...data, soc_text: (data.soc_emails || []).join(', ') }) }, [data])
  if (loading && !data) return <Loading />
  if (error) return <ErrorBox error={error} />
  if (!form) return <Loading />

  const set = (k) => (v) => setForm({ ...form, [k]: v })
  const save = async () => {
    setBusy(true)
    try {
      const r = await api.put('/settings', {
        auto_send: form.auto_send, delay_minutes: Number(form.delay_minutes), min_score: Number(form.min_score),
        soc_emails: form.soc_text.split(/[,;\s]+/).filter(Boolean), attach_docx: form.attach_docx, public_url: form.public_url,
      })
      setData(r); toast('Configuración guardada')
    } catch (e) { toast(e.message, 'err') }
    setBusy(false)
  }

  return (
    <div className="stack" style={{ maxWidth: 900 }}>
      <div className="card">
        <div className="card-title">Cómo funciona</div>
        <ol className="prose" style={{ paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 6, fontSize: 13 }}>
          <li>Cada 15 minutos se consulta el catálogo KEV de CISA.</li>
          <li>Si aparece una vulnerabilidad <b>nueva</b> con puntaje igual o mayor al umbral, se genera el comunicado (newsletter + informe PDF).</li>
          <li>El SOC recibe en ese momento el mismo mail, con un aviso y el link para editarlo o cancelarlo.</li>
          <li>Pasada la ventana, se envía solo a <b>todos los contactos activos</b> cargados en <Link to="/clientes">Clientes</Link>{rc.data && <> (hoy: {rc.data.contacts} contacto(s) de {rc.data.clients} cliente(s))</>}.</li>
        </ol>
      </div>

      <div className="card">
        <div className="card-title">Envío automático</div>
        <div className="form-grid">
          <div className="fg full">
            <label className="check" style={{ fontSize: 14 }}>
              <input type="checkbox" checked={form.auto_send} disabled={!isAdmin} onChange={(e) => set('auto_send')(e.target.checked)} />
              <b>Enviar automáticamente</b> las alertas nuevas a todos los contactos de clientes
            </label>
            {!form.auto_send && <p className="hint" style={{ marginTop: 6 }}>Desactivado: los comunicados se generan solo a mano desde cada alerta y se envían con “Enviar a clientes”.</p>}
          </div>
          <div className="fg">
            <label>Ventana de revisión del SOC</label>
            <select value={form.delay_minutes} disabled={!isAdmin} onChange={(e) => set('delay_minutes')(e.target.value)}>
              {[0, 15, 30, 60, 120].map((m) => <option key={m} value={m}>{m === 0 ? 'Sin ventana (inmediato)' : `${m} minutos`}</option>)}
            </select>
          </div>
          <div className="fg">
            <label>Puntaje mínimo para enviar</label>
            <input type="number" min={0} max={100} value={form.min_score} disabled={!isAdmin} onChange={(e) => set('min_score')(e.target.value)} />
          </div>
          <div className="fg full">
            <label>Emails del SOC (reciben el aviso previo)</label>
            <input value={form.soc_text} disabled={!isAdmin} onChange={(e) => set('soc_text')(e.target.value)} placeholder="soc@vectus.la, rgonzalez@vectus.la" />
          </div>
          <div className="fg full">
            <label>Dirección de la consola (para el link del aviso)</label>
            <input value={form.public_url} disabled={!isAdmin} onChange={(e) => set('public_url')(e.target.value)} />
          </div>
          <div className="fg full">
            <label className="check"><input type="checkbox" checked={form.attach_docx} disabled={!isAdmin} onChange={(e) => set('attach_docx')(e.target.checked)} />Adjuntar también el DOCX editable (además del PDF)</label>
          </div>
        </div>
        {isAdmin && <div className="row" style={{ marginTop: 18 }}><span className="spacer" /><button className="btn btn-primary" onClick={save} disabled={busy}>{busy ? 'Guardando…' : 'Guardar'}</button></div>}
      </div>

      <div className="card">
        <div className="card-title">Correo saliente</div>
        {data.mail.configured ? (
          <dl className="kv">
            <dt>Remitente</dt><dd>{data.mail.from_name} &lt;{data.mail.from}&gt;</dd>
            <dt>Servidor</dt><dd className="mono" style={{ fontSize: 12 }}>{data.mail.host}:{data.mail.port} ({data.mail.security})</dd>
          </dl>
        ) : <div className="alert-box err">El correo no está configurado en el <span className="mono">.env</span> del servidor.</div>}
        <p className="hint" style={{ marginTop: 12 }}>Los datos de la cuenta (usuario y contraseña) se configuran en el servidor, no desde la consola.</p>
      </div>
    </div>
  )
}
