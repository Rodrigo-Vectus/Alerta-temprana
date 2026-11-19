import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { usePageHeader } from '../components/Layout'
import { Empty, ErrorBox, fmtDateTime, Loading, Score, useFetch } from '../components/ui'

export const UcBadge = ({ status }) => (status === 'cerrado'
  ? <span className="badge b-ok">Cerrado</span>
  : <span className="badge b-warn">Abierto</span>)

export default function UseCases() {
  usePageHeader('Casos de uso SOC', 'Flujo, playbook y seguimiento de remediación por alerta')
  const navigate = useNavigate()
  const { data, error, loading } = useFetch(() => api.get('/usecases'), [], { interval: 60000 })

  return (
    <div className="card" style={{ padding: '6px 22px' }}>
      <ErrorBox error={error} />
      {loading && !data ? <Loading /> : data?.length === 0 ? (
        <Empty icon="⑂">Todavía no hay casos de uso. Se crean solos cuando se genera un comunicado, o desde el detalle de una alerta.</Empty>
      ) : data && (
        <div className="table-wrap">
          <table className="tbl">
            <thead><tr><th>Caso</th><th>Score</th><th>Alerta</th><th>Vulnerabilidad</th><th>Playbook</th><th>Clientes parcheados</th><th>Estado</th><th>Actualizado</th></tr></thead>
            <tbody>{data.map((u) => {
              const pct = u.progress.total ? Math.round((u.progress.done / u.progress.total) * 100) : 0
              return (
                <tr key={u.code} className="click" onClick={() => navigate(`/casos-de-uso/${u.code}`)}>
                  <td className="code">{u.code}</td>
                  <td><Score value={u.score} /></td>
                  <td><div className="code" style={{ color: 'var(--text)' }}>{u.alert_code}</div><div className="sub mono">{u.cve_id}</div></td>
                  <td className="prod">{u.vendor} {u.product}</td>
                  <td style={{ minWidth: 140 }}><div className="progress"><span style={{ width: `${pct}%` }} /></div><div className="sub mono">{u.progress.done}/{u.progress.total} pasos</div></td>
                  <td className="num">{u.clients.patched}/{u.clients.total}{u.clients.ioc > 0 && <span className="badge b-danger" style={{ marginLeft: 6 }}>IoC</span>}</td>
                  <td><UcBadge status={u.status} /></td>
                  <td className="num">{fmtDateTime(u.updated_at)}</td>
                </tr>
              )
            })}</tbody>
          </table>
        </div>
      )}
    </div>
  )
}
