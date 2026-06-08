/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import basicSsl from '@vitejs/plugin-basic-ssl'

// HTTPS na dev serveru (:5173) preko self-signed sertifikata koji generiše @vitejs/plugin-basic-ssl.
// Sva komunikacija browser ↔ frontend ↔ gateway ide preko HTTPS-a; browser će prvi put tražiti
// da se prihvati self-signed sertifikat (i za :5173 i za gateway :8080).
export default defineConfig({
  plugins: [react(), basicSsl()],
  server: {
    host: true,
    https: true,
    port: 5173,
  },
  test: {
    environment: 'jsdom',
    globals: true,
  },
})
