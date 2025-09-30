import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: true
  },
  preview: {
    port: process.env.PORT || 3000,
    host: true,
    allowedHosts: ['flamo.up.railway.app', 'exoper.com', '.railway.app']
  }
})
