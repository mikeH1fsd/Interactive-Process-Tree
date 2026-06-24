import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/elastic_api': {
        target: 'http://10.48.144.79:9200',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/elastic_api/, '')
      }
    }
  }
})
