import { useState } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import { usePageHeader } from '../components/Layout'
import { IconPlus } from '../components/icons'
import { ErrorBox, Loading, useFetch, useToast } from '../components/ui'

const TIERS = [
  { tier: 1, title: 'Uso masivo', pts: '+20 puntos', desc: 'Fabricantes presentes en la mayoría de los clientes. Una vulnerabilidad explotada de estos casi siempre amerita evaluación.' },
  { tier: 2, title: 'Vigilados', pts: '+10 puntos', desc: 'Fabricantes relevantes para parte de la cartera.' },
]

export default function Vendors() {
  usePageHeader('Fabricantes vigilados', 'Ponderación del motor de puntaje por fabricante')
  const { canWrite } = useAuth()
  const toast = useToast()
  const { data, error, loading, reload } = useFetch(() => api.get('/watchlist'), [])
  const [form, setForm] = useState({ vendor: '', tier: 1 })

  const add = async (e) => {
    e.preventDefault()
    try { await api.post('/watchlist', { vendor: form.vendor.trim(), tier: Number(form.tier) }); toast('Fabricante agregado'); setForm({ ...form, vendor: '' }); reload(true) } catch (err) { toast(err.message, 'err') }
  }
  const del = async (w) => {
    try { await api.del(`/watchlist/${w.id}`); toast(`${w.vendor} quitado`); reload(true) } catch (err) { toast(err.message, 'err') }
  }

  if (loading && !data) return <Loading />
  if (error) return <ErrorBox error={error} />

  return (
    <div className="stack">
      <div className="grid g2">
        {TIERS.map((t) => (
          <div className="card" key={t.tier}>
            <div className="card-title">{t.title} <span className="badge b-info">{t.pts}</span></div>
            <p className="hint" style={{ marginBottom: 16 }}>{t.desc}</p>
            <div className="chips">
              {data.filter((w) => w.tier === t.tier).map((w) => (
                <span key={w.id} className="chip" style={{ cursor: 'default' }}>
                  {w.vendor}{canWrite && <span className="x" title="Quitar" onClick={() => del(w)}>×</span>}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
      {canWrite && (
        <form className="card" onSubmit={add}>
          <div className="card-title">Agregar fabricante</div>
          <div className="row wrap">
            <input style={{ maxWidth: 340 }} value={form.vendor} onChange={(e) => setForm({ ...form, vendor: e.target.value })} placeholder="Nombre como figura en CISA (ej. Fortinet)" required />
            <select style={{ maxWidth: 200 }} value={form.tier} onChange={(e) => setForm({ ...form, tier: e.target.value })}>
              <option value={1}>Uso masivo (+20)</option><option value={2}>Vigilado (+10)</option>
            </select>
            <button className="btn btn-primary" disabled={!form.vendor.trim()}><IconPlus />Agregar</button>
          </div>
          <p className="hint" style={{ marginTop: 12 }}>Los cambios se aplican en la próxima evaluación. Para recalcular las alertas existentes usá “Recalcular” en Alertas.</p>
        </form>
      )}
    </div>
  )
}
