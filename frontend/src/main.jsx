import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth'
import Layout from './components/Layout'
import { Loading, ToastProvider } from './components/ui'
import AlertDetail from './pages/AlertDetail'
import Alerts from './pages/Alerts'
import Audit from './pages/Audit'
import Clients from './pages/Clients'
import CommunicationEditor from './pages/CommunicationEditor'
import Communications from './pages/Communications'
import Dashboard from './pages/Dashboard'
import Login from './pages/Login'
import Settings from './pages/Settings'
import UseCaseDetail from './pages/UseCaseDetail'
import UseCases from './pages/UseCases'
import Users from './pages/Users'
import Vendors from './pages/Vendors'
import './styles.css'

function RequireAuth({ children, admin = false }) {
  const { user, ready, isAdmin } = useAuth()
  if (!ready) return <div className="auth-wrap"><Loading /></div>
  if (!user) return <Navigate to="/login" replace />
  if (admin && !isAdmin) return <Navigate to="/" replace />
  return children
}


function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<Dashboard />} />
        <Route path="alertas" element={<Alerts />} />
        <Route path="alertas/:code" element={<AlertDetail />} />
        <Route path="comunicados" element={<Communications />} />
        <Route path="comunicados/:code" element={<CommunicationEditor />} />
        <Route path="casos-de-uso" element={<UseCases />} />
        <Route path="casos-de-uso/:code" element={<UseCaseDetail />} />
        <Route path="clientes" element={<Clients />} />
        <Route path="fabricantes" element={<Vendors />} />
        <Route path="usuarios" element={<RequireAuth admin><Users /></RequireAuth>} />
        <Route path="auditoria" element={<RequireAuth admin><Audit /></RequireAuth>} />
        <Route path="configuracion" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
