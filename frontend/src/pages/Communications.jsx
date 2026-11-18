import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { usePageHeader } from '../components/Layout'
import { Empty, ErrorBox, fmtDateTime, Loading, Score, useFetch } from '../components/ui'

export const COMM_STATUS = {
  borrador: { label: 'Borrador', cls: 'b-warn' },
  aprobado: { label: 'Aprobado', cls: 'b-cyan' },
  enviado: { label: 'Enviado', cls: 'b-ok' },
}
export const CommBadge = ({ status }) => {
  const s = COMM_STATUS[status] || { label: status, cls: 'b-muted' }
  return <span className={`badge ${s.cls}`}>{s.label}</span>
}

export default function Communications() {
  usePageHeader('Comunicados', 'Newsletter (cuerpo del mail) + informe adjunto para cada alerta')
  const navigate = useNavigate()
  const { data, error, loading } = useFetch(() => api.get('/communications'), [], { interval: 60000 })
  const mail = useFetch(() => api.get('/communications/mail-status'), [])

  return (
    <div className="stack">
      {mail.data && !mail.data.configured && (
        <div className="alert-box info">
          El correo todavía no está configurado. Podés generar, editar y descargar comunicados; para enviar la prueba
          hay que completar los datos <span className="mono">SMTP_*</span> en el <span className="mono">.env</span> del servidor.
        </div>
      )}
      <div className="card" style={{ padding: '6px 22px' }}>
        <ErrorBox error={error} />
        {loading && !data ? <Loading /> : data?.length === 0 ? (
          <Empty icon="✉">
            Todavía no hay comunicados.<br />Abrí una alerta y usá <b>“Generar comunicado”</b> para crear el borrador del newsletter y del informe.
          </Empty>
        ) : data && (
          <div className="table-wrap">
            <table className="tbl">
              <thead><tr><th>Comunicado</th><th>Score</th><th>Alerta</th><th>Título</th><th>Estado</th><th>Envíos</th><th>Actualizado</th></tr></thead>
              <tbody>{data.map((c) => (
                <tr key={c.code} className="click" onClick={() => navigate(`/comunicados/${c.code}`)}>
                  <td className="code">{c.code}</td>
                  <td><Score value={c.score} /></td>
                  <td><div className="code" style={{ color: 'var(--text)' }}>{c.alert_code}</div><div className="sub mono">{c.cve_id}</div></td>
                  <td style={{ maxWidth: 420 }}><div className="prod">{c.title}</div><div className="sub">{c.vendor} {c.product}</div></td>
                  <td><CommBadge status={c.status} /></td>
                  <td className="num">{c.sends || '—'}</td>
                  <td className="num">{fmtDateTime(c.updated_at)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
