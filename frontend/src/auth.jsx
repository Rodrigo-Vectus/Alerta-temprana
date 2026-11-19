import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api, getToken, setToken } from './api'

const AuthCtx = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)

  const loadMe = useCallback(async () => {
    if (!getToken()) { setUser(null); setReady(true); return }
    try { setUser(await api.get('/auth/me')) } catch { setToken(null); setUser(null) }
    setReady(true)
  }, [])

  useEffect(() => { loadMe() }, [loadMe])

  useEffect(() => {
    const onUnauth = () => { setToken(null); setUser(null) }
    window.addEventListener('vsat:unauthorized', onUnauth)
    return () => {
      window.removeEventListener('vsat:unauthorized', onUnauth)
    }
  }, [])

  // Ingreso por código enviado por mail
  const requestCode = (email) => api.post('/auth/request-code', { email })
  const verifyCode = async (email, code) => {
    const r = await api.post('/auth/verify-code', { email, code })
    setToken(r.access_token)
    setUser(r.user)
    return r.user
  }

  const logout = () => { setToken(null); setUser(null) }

  const value = {
    user, ready, requestCode, verifyCode, logout, reload: loadMe,
    canWrite: user && ['admin', 'analista'].includes(user.role),
    isAdmin: user?.role === 'admin',
  }
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

export const useAuth = () => useContext(AuthCtx)
