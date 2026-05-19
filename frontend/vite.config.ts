import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';
import fs from 'node:fs';

const apiOrigin = process.env.BNASMGR_API_ORIGIN || 'http://127.0.0.1:8080';
const tlsCert = process.env.BNASMGR_DEV_TLS_CERT;
const tlsKey = process.env.BNASMGR_DEV_TLS_KEY;

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    https: tlsCert && tlsKey ? {
      cert: fs.readFileSync(tlsCert),
      key: fs.readFileSync(tlsKey)
    } : undefined,
    proxy: {
      '/api': {
        target: apiOrigin,
        secure: false
      }
    }
  }
});
