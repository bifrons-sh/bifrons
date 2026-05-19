import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

// Vite build config for the operator SPA.
//
// - `base: '/ui/'` matches the Go mount so hashed asset URLs resolve under
//   the embedded FileServer.
// - `outDir` points at the Go package's `dist/` so `//go:embed all:dist`
//   picks up the freshly-built bundle on the next `go build`.
// - `emptyOutDir: false` keeps the tracked `.gitkeep` stub in place so
//   the embed compiles on a fresh clone. The Makefile `ui` target prunes
//   stale outputs before invoking Vite, so hashes don't accumulate.
export default defineConfig({
  base: '/ui/',
  plugins: [react()],
  build: {
    outDir: resolve(__dirname, '../internal/api/ui/dist'),
    emptyOutDir: false,
    sourcemap: false,
    target: 'es2022',
    chunkSizeWarningLimit: 1024,
  },
  server: {
    port: 5173,
    // During `vite dev`, proxy API + OIDC calls to the local portal so
    // the SPA can exercise the real backend without CORS.
    proxy: {
      '/api': 'http://127.0.0.1:18080',
      '/oidc': 'http://127.0.0.1:18080',
    },
  },
});
