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
    const onMustChange = () => setUser((u) => (u ? { ...u, must_change_password: true } : u))
    window.addEventListener('vsat:unauthorized', onUnauth)
    window.addEventListener('vsat:must-change', onMustChange)
    return () => {
      window.removeEventListener('vsat:unauthorized', onUnauth)
      window.removeEventListener('vsat:must-change', onMustChange)
    }
  }, [])

  const login = async (email, password) => {
    const r = await api.post('/auth/login', { email, password })
    setToken(r.access_token)
    setUser(r.user)
    return r.user
  }

  const logout = () => { setToken(null); setUser(null) }

  const value = {
    user, ready, login, logout, reload: loadMe,
    canWrite: user && ['admin', 'analista'].includes(user.role),
    isAdmin: user?.role === 'admin',
  }
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

export const useAuth = () => useContext(AuthCtx)
