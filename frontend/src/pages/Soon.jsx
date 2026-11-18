import { usePageHeader } from '../components/Layout'

const CONTENT = {
  comunicados: {
    title: 'Comunicados',
    sub: 'Alertas preventivas enviadas a clientes',
    phase: 'Fase 6',
    items: [
      'Borrador automático del flyer de alerta (formato Vectus) a partir de cada alerta aprobada.',
      'Informe de impacto en DOCX/PDF con la estructura de sus informes actuales.',
      'Edición y aprobación del analista antes del envío.',
      'Registro de destinatarios y fecha de envío (Fase 8).',
    ],
  },
  casos: {
    title: 'Casos de uso SOC',
    sub: 'Flujos y playbooks asociados a cada alerta',
    phase: 'Fase 7',
    items: [
      'Un caso de uso por alerta (CU-SOC-NNN) vinculado a su código SAT.',
      'Diagrama del flujo de detección, evaluación, validación y remediación.',
      'Playbook para el equipo de seguridad: detección, contención, indicadores de compromiso.',
      'Seguimiento de remediación por cliente y cierre con trazabilidad.',
    ],
  },
}

export default function Soon({ kind }) {
  const c = CONTENT[kind]
  usePageHeader(c.title, c.sub)
  return (
    <div className="card soon-card" style={{ maxWidth: 760 }}>
      <div className="card-title">En construcción · {c.phase}</div>
      <p style={{ marginBottom: 14 }}>Esta sección se completa en la {c.phase} del proyecto. Va a incluir:</p>
      <ul style={{ paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {c.items.map((i) => <li key={i} className="prose" style={{ fontSize: 13 }}>{i}</li>)}
      </ul>
    </div>
  )
}
