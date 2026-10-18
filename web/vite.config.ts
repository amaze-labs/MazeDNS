import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// During `npm run dev`, proxy API calls to the Go backend (:8080, or
// MAZEDNS_API_URL when it runs elsewhere).
const api = process.env.MAZEDNS_API_URL || 'http://127.0.0.1:8080'

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    proxy: {
      '/api': api,
      '/metrics': api,
      '/healthz': api,
    },
  },
})
