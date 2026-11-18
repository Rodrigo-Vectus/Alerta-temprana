import { useEffect, useState } from 'react'
import { api } from '../api'
import { usePageHeader } from '../components/Layout'
import { IconSearch } from '../components/icons'
import { Empty, ErrorBox, fmtDateTime, Loading, useFetch } from '../components/ui'

const LABELS = { login_ok: 'Ingreso', login_fallido: 'Ingreso fallido', login_bloqueado: 'Ingreso bloqueado' }

export default function Audit() {
  usePageHeader('Auditoría', 'Registro de ingresos y acciones de escritura')
  const [q, setQ] = useState('')
  const [term, setTerm] = useState('')
  useEffect(() => { const t = setTimeout(() => setTerm(q), 300); return () => clearTimeout(t) }, [q])
  const { data, error, loading } = useFetch(() => api.get(`/audit?limit=300${term ? `&action=${encodeURIComponent(term)}` : ''}`), [term], { interval: 30000 })

  const cls = (c) => (!c ? 'b-muted' : c < 300 ? 'b-ok' : c < 500 && c !== 423 ? 'b-warn' : 'b-danger')

  return (
    <>
      <div className="toolbar">
        <div className="search"><IconSearch /><input placeholder="Filtrar por acción (login, alerts, users…)" value={q} onChange={(e) => setQ(e.target.value)} /></div>
      </div>
      <div className="card" style={{ padding: '6px 22px' }}>
        <ErrorBox error={error} />
        {loading && !data ? <Loading /> : data?.length === 0 ? <Empty>Sin registros.</Empty> : data && (
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>Resultado</th><th>IP</th></tr></thead>
              <tbody>{data.map((a) => (
                <tr key={a.id}>
                  <td className="num">{fmtDateTime(a.created_at)}</td>
                  <td>{a.user_email || <span className="dim">anónimo</span>}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{LABELS[a.action] || a.action}</td>
                  <td><span className={`badge ${cls(a.status_code)}`}>{a.status_code || '—'}</span></td>
                  <td className="num dim">{a.ip || '—'}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
