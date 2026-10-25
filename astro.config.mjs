// @ts-check
import { defineConfig } from 'astro/config';
import svelte from '@astrojs/svelte';
import tailwindcss from '@tailwindcss/vite';

// Static build served by Tauri from dist/. The whole UI is one client-only Svelte island.
export default defineConfig({
  integrations: [svelte()],
  output: 'static',
  build: { inlineStylesheets: 'never' },
  server: { port: 4321, host: '127.0.0.1' },
  vite: {
    plugins: [tailwindcss()],
    clearScreen: false,
    server: {
      strictPort: true,
      // Only src/ and public/ are frontend; the Rust target/ alone holds more files than the default inotify limit.
      watch: { ignored: ['**/target/**', '**/src-tauri/**', '**/crates/**', '**/fuzz/**', '**/e2e/**', '**/docker/**', '**/dist/**'] },
    },
    envPrefix: ['VITE_', 'TAURI_'],
  },
});
