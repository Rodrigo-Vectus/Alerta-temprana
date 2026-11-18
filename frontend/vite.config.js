import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Solo para desarrollo local: en producción nginx hace de proxy a /api
const api = process.env.API_URL || 'http://localhost'

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': api } },
  preview: { proxy: { '/api': api } },
})
