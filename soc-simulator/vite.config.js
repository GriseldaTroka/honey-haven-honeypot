import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    open: '/soc',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        // Ensure backend Set-Cookie values are host-only for the dev server
        // so the browser will send session cookies back to the proxied origin.
        cookieDomainRewrite: '',
        // Increase proxy timeouts to 60s and expose proxy lifecycle logs for debugging
        timeout: 60000,
        proxyTimeout: 60000,
        configure(proxy, options) {
          proxy.on('proxyReq', (proxyReq, req, res, opt) => {
            try {
              console.log(`[vite-proxy] proxyReq ${req.method} ${req.url} -> ${opt && opt.target}`)
            } catch (e) {}
          })
          proxy.on('proxyRes', (proxyRes, req, res) => {
            try {
              console.log(`[vite-proxy] proxyRes ${req.method} ${req.url} <- ${proxyRes.statusCode}`)
            } catch (e) {}
          })
          proxy.on('error', (err, req, res) => {
            try {
              console.error(`[vite-proxy] proxyError ${req && req.method} ${req && req.url}`, err && err.message)
            } catch (e) {}
          })
        },
      },
      '/research': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        cookieDomainRewrite: '',
        timeout: 60000,
        proxyTimeout: 60000,
        configure(proxy, options) {
          proxy.on('proxyReq', (proxyReq, req, res, opt) => {
            try { console.log(`[vite-proxy] proxyReq ${req.method} ${req.url} -> ${opt && opt.target}`) } catch (e) {}
          })
          proxy.on('proxyRes', (proxyRes, req, res) => {
            try { console.log(`[vite-proxy] proxyRes ${req.method} ${req.url} <- ${proxyRes.statusCode}`) } catch (e) {}
          })
          proxy.on('error', (err, req, res) => {
            try { console.error(`[vite-proxy] proxyError ${req && req.method} ${req && req.url}`, err && err.message) } catch (e) {}
          })
        },
      },
      '/beacon': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        cookieDomainRewrite: '',
        timeout: 60000,
        proxyTimeout: 60000,
        configure(proxy, options) {
          proxy.on('proxyReq', (proxyReq, req, res, opt) => {
            try { console.log(`[vite-proxy] proxyReq ${req.method} ${req.url} -> ${opt && opt.target}`) } catch (e) {}
          })
          proxy.on('proxyRes', (proxyRes, req, res) => {
            try { console.log(`[vite-proxy] proxyRes ${req.method} ${req.url} <- ${proxyRes.statusCode}`) } catch (e) {}
          })
          proxy.on('error', (err, req, res) => {
            try { console.error(`[vite-proxy] proxyError ${req && req.method} ${req && req.url}`, err && err.message) } catch (e) {}
          })
        },
      },
    },
  },
})
