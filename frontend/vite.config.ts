import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// When running inside Docker, the backend is reachable as http://backend:8000
// When running locally (npm run dev on host), set VITE_API_BASE=http://localhost:8000
const target = process.env.VITE_API_BASE || 'http://backend:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api': {
        target,
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      }
    }
  }
})
