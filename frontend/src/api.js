// Cliente HTTP de la consola. Agrega el token y normaliza errores.
const TOKEN_KEY = 'vsat-token'

export const storage = {
  get(k) { try { return localStorage.getItem(k) } catch { return null } },
  set(k, v) { try { localStorage.setItem(k, v) } catch { /* sin storage */ } },
  del(k) { try { localStorage.removeItem(k) } catch { /* sin storage */ } },
}

export const getToken = () => storage.get(TOKEN_KEY)
export const setToken = (t) => (t ? storage.set(TOKEN_KEY, t) : storage.del(TOKEN_KEY))

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status }
}

async function request(method, path, body, raw = false) {
  const headers = { Accept: 'application/json' }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  let res
  try {
    res = await fetch(`/api${path}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined })
  } catch {
    throw new ApiError(0, 'No hay conexión con el servidor')
  }

  if (res.status === 204) return null
  if (raw && res.ok) return res
  let data = null
  try { data = await res.json() } catch { /* sin cuerpo */ }

  if (!res.ok) {
    let msg = data?.detail
    if (Array.isArray(msg)) msg = msg.map((d) => d.msg).join(' · ')
    if (res.status === 429) msg = 'Demasiados intentos. Esperá un minuto y volvé a probar.'
    const err = new ApiError(res.status, msg || `Error ${res.status}`)
    if (res.status === 401 && path !== '/auth/login') window.dispatchEvent(new CustomEvent('vsat:unauthorized'))
    if (res.status === 403 && msg?.includes('cambiar la contraseña')) window.dispatchEvent(new CustomEvent('vsat:must-change'))
    throw err
  }
  return data
}

export const api = {
  get: (p) => request('GET', p),
  post: (p, b = {}) => request('POST', p, b),
  patch: (p, b = {}) => request('PATCH', p, b),
  del: (p) => request('DELETE', p),
  // Respuestas no JSON (HTML, archivos)
  text: async (p, method = 'GET', body) => (await request(method, p, body, true)).text(),
  blob: async (p) => {
    const res = await request('GET', p, undefined, true)
    const cd = res.headers.get('Content-Disposition') || ''
    const m = cd.match(/filename="([^"]+)"/)
    return { blob: await res.blob(), filename: m ? m[1] : 'archivo' }
  },
}

export async function download(path) {
  const { blob, filename } = await api.blob(path)
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 2000)
}
