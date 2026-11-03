import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            // Guarantee that any upstream WWW-Authenticate: Basic challenge is stripped
            // so Chrome / Chromium browsers never trigger a native modal credentials dialog
            const authHeader = proxyRes.headers['www-authenticate'];
            if (authHeader && String(authHeader).toLowerCase().includes('basic')) {
              delete proxyRes.headers['www-authenticate'];
            }
          });
        }
      }
    }
  }
});
