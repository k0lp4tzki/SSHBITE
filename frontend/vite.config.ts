import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Builds into the Python package; the wheel ships these files (spec 3.1). No CDN, no inline scripts.
export default defineConfig({
  plugins: [svelte()],
  base: '/',
  build: {
    outDir: '../sshbite/web/static',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        assetFileNames: (info) =>
          /\.woff2?$/.test(info.names?.[0] ?? info.name ?? '') ? 'fonts/[name]-[hash][extname]' : 'assets/[name]-[hash][extname]',
      },
    },
  },
  server: { proxy: { '/api': 'http://127.0.0.1:8722' } },
});
